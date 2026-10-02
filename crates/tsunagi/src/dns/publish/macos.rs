//! Telling the macOS resolver to send some questions here, through
//! `/etc/resolver`.
//!
//! macOS reads one file per domain out of `/etc/resolver`: a file named after
//! a domain, containing the `nameserver` and `port` to send that domain's
//! questions to, makes the system resolver a *scoped* resolver for exactly
//! that suffix and nothing else (see `resolver(5)`). That is the same contract
//! the systemd-resolved and NRPT publishers arrange on the other platforms:
//! route these suffixes to this server, and claim nothing else.
//!
//! # Why a port, and so no privileged socket
//!
//! A resolver file carries a `port`, so the server does not have to sit on 53
//! and the agent needs nothing like `CAP_NET_BIND_SERVICE`. It can serve on a
//! high port and still be reached for its suffixes.
//!
//! # Tagged, reversible, and never clobbering
//!
//! Every file this publisher writes begins with a marker line, so it only ever
//! replaces or removes files it wrote itself: a pre-existing `/etc/resolver`
//! entry a user set up by hand is left untouched. The files are removed when
//! the resolver is turned off and on shutdown; a crash leaves them behind, and
//! the next apply for the same domains overwrites them.
//!
//! # Privilege
//!
//! Writing under `/etc/resolver` needs root. A permission error is reported as
//! a refusal — the kind of failure a person has to act on — rather than a
//! transient one, so the agent does not retry it at the ordinary pace.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::BoxFuture;

use super::{DnsPublisher, PublishError, Published};

/// The directory macOS reads scoped resolvers from.
const RESOLVER_DIR: &str = "/etc/resolver";

/// The first line of every file this publisher writes, so it recognises its
/// own and never touches a file a user created.
const MARKER: &str = "# managed by tsunagi — do not edit";

/// Writes and removes `/etc/resolver` files for the overlay zones.
#[derive(Debug)]
pub struct ResolverDirPublisher {
    /// The resolver directory. A field rather than a constant so the tests can
    /// point it at a temporary directory and never touch the real one.
    dir: PathBuf,
    /// The domain files written by the last apply, so a later apply can remove
    /// the ones no longer wanted and `revert` can remove them all.
    written: Mutex<BTreeSet<String>>,
}

impl Default for ResolverDirPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolverDirPublisher {
    /// A publisher writing to the real `/etc/resolver`.
    pub fn new() -> Self {
        Self::in_dir(RESOLVER_DIR)
    }

    /// A publisher writing to a specific directory. For the tests.
    fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            written: Mutex::new(BTreeSet::new()),
        }
    }

    fn apply_inner(&self, published: &Published) -> Result<(), PublishError> {
        let desired = desired_files(published)?;

        // The directory may not exist yet; creating it needs root.
        std::fs::create_dir_all(&self.dir).map_err(|err| classify(&self.dir, err))?;

        // Remove the files from a previous apply that are no longer wanted.
        let previous = lock(&self.written).clone();
        for name in previous.difference(&keys(&desired)) {
            remove_if_ours(&self.dir.join(name));
        }

        for (name, body) in &desired {
            let path = self.dir.join(name);
            // Only ever overwrite a file that is already ours, or a name that
            // is free. A resolver a user set up by hand is left in place and
            // reported, never clobbered.
            if path.exists() && !is_ours(&path) {
                return Err(PublishError::Failed(format!(
                    "{} already exists and was not created by tsunagi; \
                     remove it or rename the network to publish its resolver",
                    path.display()
                )));
            }
            std::fs::write(&path, body).map_err(|err| classify(&path, err))?;
        }

        *lock(&self.written) = keys(&desired);
        Ok(())
    }

    fn revert_inner(&self) {
        let written = std::mem::take(&mut *lock(&self.written));
        for name in &written {
            remove_if_ours(&self.dir.join(name));
        }
    }
}

impl DnsPublisher for ResolverDirPublisher {
    fn name(&self) -> &str {
        "resolver-dir"
    }

    fn apply<'a>(&'a self, published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>> {
        // A handful of small file writes, short enough to run in place rather
        // than hop to the blocking pool.
        Box::pin(async move { self.apply_inner(published) })
    }

    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>> {
        Box::pin(async move {
            self.revert_inner();
            Ok(())
        })
    }
}

/// The resolver files a publication implies: a map of file name to contents.
fn desired_files(published: &Published) -> Result<Vec<(String, String)>, PublishError> {
    if published.servers.is_empty() {
        return Err(PublishError::Failed(
            "no server address to point the resolver at".to_string(),
        ));
    }
    let body = file_contents(published);
    let mut files = Vec::new();
    for domain in &published.domains {
        let name = resolver_file_name(domain)?;
        files.push((name, body.clone()));
    }
    Ok(files)
}

/// The contents of one resolver file: the marker, every server, one port.
fn file_contents(published: &Published) -> String {
    let mut out = String::from(MARKER);
    out.push('\n');
    for server in &published.servers {
        let ip = match server.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        };
        out.push_str("nameserver ");
        out.push_str(&ip);
        out.push('\n');
    }
    // One port for the file; every server listens on the same one. The `port`
    // directive is what lets the server stay off 53.
    if let Some(first) = published.servers.first() {
        out.push_str("port ");
        out.push_str(&first.port().to_string());
        out.push('\n');
    }
    out
}

/// The file name for a domain, rejecting anything that is not a plain label
/// path component: a resolver file name must never escape the directory.
fn resolver_file_name(domain: &str) -> Result<String, PublishError> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(std::path::MAIN_SEPARATOR)
        || trimmed == "."
        || trimmed == ".."
        || trimmed.starts_with('.')
    {
        return Err(PublishError::Failed(format!(
            "cannot make a resolver file name for the domain {domain:?}"
        )));
    }
    Ok(trimmed.to_string())
}

/// Whether a file is one this publisher wrote, by its marker first line.
fn is_ours(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => text.lines().next() == Some(MARKER),
        Err(_) => false,
    }
}

/// Removes a file, but only if it is one of ours. Best effort.
fn remove_if_ours(path: &Path) {
    if is_ours(path)
        && let Err(err) = std::fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(path = %path.display(), %err, "cannot remove the resolver file");
    }
}

/// The set of file names in a desired-files list.
fn keys(files: &[(String, String)]) -> BTreeSet<String> {
    files.iter().map(|(name, _)| name.clone()).collect()
}

/// Turns a filesystem error into the right kind of publish error: a permission
/// problem is a refusal a person must act on, anything else is a plain failure.
fn classify(path: &Path, err: std::io::Error) -> PublishError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        PublishError::Refused(format!(
            "writing {} needs root; start the agent with `sudo` or as a root LaunchDaemon",
            path.display()
        ))
    } else {
        PublishError::Failed(format!("cannot write {}: {err}", path.display()))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::SocketAddr;

    use super::*;

    fn published(domains: &[&str]) -> Published {
        Published {
            interface: "utun5".into(),
            servers: vec![
                "10.13.37.1:5353".parse::<SocketAddr>().unwrap(),
                "[fd00::1]:5353".parse::<SocketAddr>().unwrap(),
            ],
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn a_file_lists_every_server_and_one_port_under_the_marker() {
        let body = file_contents(&published(&["mynet."]));
        let mut lines = body.lines();
        assert_eq!(lines.next(), Some(MARKER));
        assert_eq!(lines.next(), Some("nameserver 10.13.37.1"));
        assert_eq!(lines.next(), Some("nameserver fd00::1"));
        assert_eq!(lines.next(), Some("port 5353"));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn a_domain_becomes_a_plain_file_name_without_its_trailing_dot() {
        assert_eq!(resolver_file_name("mynet.").unwrap(), "mynet");
        assert_eq!(resolver_file_name("my.net").unwrap(), "my.net");
    }

    #[test]
    fn a_domain_that_would_escape_the_directory_is_refused() {
        assert!(resolver_file_name("../etc/passwd").is_err());
        assert!(resolver_file_name("a/b").is_err());
        assert!(resolver_file_name("").is_err());
        assert!(resolver_file_name(".").is_err());
        assert!(resolver_file_name(".hidden").is_err());
    }

    #[tokio::test]
    async fn apply_writes_a_file_per_domain_and_revert_removes_them() {
        let dir = tempfile::tempdir().unwrap();
        let publisher = ResolverDirPublisher::in_dir(dir.path());

        publisher
            .apply(&published(&["mynet.", "other."]))
            .await
            .unwrap();
        assert!(dir.path().join("mynet").is_file());
        assert!(dir.path().join("other").is_file());

        publisher.revert().await.unwrap();
        assert!(!dir.path().join("mynet").exists());
        assert!(!dir.path().join("other").exists());
    }

    #[tokio::test]
    async fn re_applying_removes_a_domain_that_is_no_longer_wanted() {
        let dir = tempfile::tempdir().unwrap();
        let publisher = ResolverDirPublisher::in_dir(dir.path());

        publisher.apply(&published(&["a.", "b."])).await.unwrap();
        publisher.apply(&published(&["a."])).await.unwrap();

        assert!(dir.path().join("a").is_file());
        assert!(
            !dir.path().join("b").exists(),
            "the dropped domain's file is removed"
        );
    }

    #[tokio::test]
    async fn a_file_a_user_created_is_never_clobbered_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = dir.path().join("mynet");
        std::fs::write(&foreign, "nameserver 9.9.9.9\n").unwrap();

        let publisher = ResolverDirPublisher::in_dir(dir.path());
        let err = publisher.apply(&published(&["mynet."])).await.unwrap_err();
        assert!(matches!(err, PublishError::Failed(_)), "{err:?}");
        // Untouched.
        assert_eq!(
            std::fs::read_to_string(&foreign).unwrap(),
            "nameserver 9.9.9.9\n"
        );

        // And revert leaves a foreign file alone even if it is in our set.
        publisher.revert().await.unwrap();
        assert!(foreign.is_file());
    }
}
