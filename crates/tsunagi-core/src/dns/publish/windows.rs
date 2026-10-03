//! Telling the Windows DNS client to send some questions here, through the
//! Name Resolution Policy Table.
//!
//! The NRPT is how Windows does split DNS: a rule says "names under this
//! suffix are resolved by these servers", and names outside every rule are
//! resolved the ordinary way. That is exactly the contract of [`Published`] —
//! route these suffixes here and claim nothing else — so one NRPT rule per
//! suffix is the whole of it. The rules are keyed by namespace, not by
//! interface, so the interface name in [`Published`] is not needed here.
//!
//! # Why PowerShell
//!
//! The NRPT lives in the registry, but a rule only takes effect once the DNS
//! client is told to reload its policy, and that notification is an RPC with
//! no safe wrapper this crate may call — it forbids `unsafe`. The
//! `DnsClient` PowerShell module does the write *and* the reload, so it is
//! used by absolute path from `%SystemRoot%`. Every value passed to it is one
//! this agent produced: the suffixes are validated zone names (letters,
//! digits, `-`, `_`, `.` only) and the servers are addresses it is listening
//! on. They are still single-quoted and escaped when built into the script,
//! so nothing could be read as PowerShell rather than as data.
//!
//! # The port
//!
//! The Windows DNS client always asks on port 53; it cannot be told another.
//! So a server on a different port cannot be reached this way, and rather than
//! configure a rule that points at nothing, this says so — the same honest
//! failure the systemd-resolved path gives for an old resolver with no port.
//!
//! # Privilege
//!
//! Writing an NRPT rule needs an elevated process. An ordinary user is
//! refused, which is reported as its own kind of error because the answer to
//! it — run elevated, or as a service — differs from "this is not Windows".

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::BoxFuture;

use super::{DnsPublisher, PublishError, Published};

/// The port the Windows DNS client is fixed to.
const DNS_PORT: u16 = 53;

/// Configures the Name Resolution Policy Table through PowerShell.
#[derive(Debug, Default)]
pub struct NrptPublisher {
    /// The namespaces last configured, so shutdown knows what to undo.
    applied: Mutex<Vec<String>>,
}

impl NrptPublisher {
    /// Creates the publisher. Nothing is contacted until [`Self::apply`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// A suffix as the NRPT wants it: a leading dot means "this and everything
/// under it".
fn namespace(domain: &str) -> String {
    let trimmed = domain.trim_matches('.');
    format!(".{trimmed}")
}

/// A PowerShell single-quoted literal, with any embedded quote doubled.
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// A PowerShell array literal, `@('a','b')`, or `@()` when empty.
fn ps_array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| ps_literal(value)).collect();
    format!("@({})", items.join(","))
}

/// The script that clears our rules for these namespaces and then adds them.
fn apply_script(namespaces: &[String], servers: &[String]) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $ns = {ns}\n\
         $srv = {srv}\n\
         foreach ($n in $ns) {{ Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq $n }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }} }}\n\
         foreach ($n in $ns) {{ Add-DnsClientNrptRule -Namespace $n -NameServers $srv }}\n",
        ns = ps_array(namespaces),
        srv = ps_array(servers),
    )
}

/// The script that clears our rules for these namespaces.
fn revert_script(namespaces: &[String]) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         $ns = {ns}\n\
         foreach ($n in $ns) {{ Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq $n }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }} }}\n",
        ns = ps_array(namespaces),
    )
}

/// Turns what PowerShell said on failure into the kind of failure it is.
fn classify(text: &str) -> PublishError {
    let lower = text.to_ascii_lowercase();
    if lower.contains("access is denied")
        || lower.contains("requires elevation")
        || lower.contains("run as administrator")
        || lower.contains("administrator privilege")
        || lower.contains("permissiondenied")
    {
        PublishError::Refused(format!("the Windows DNS client refused the change: {text}"))
    } else if lower.contains("is not recognized")
        || lower.contains("commandnotfoundexception")
        || lower.contains("not recognized as the name of a cmdlet")
    {
        PublishError::Unavailable(format!(
            "the DnsClient PowerShell module is not available: {text}"
        ))
    } else {
        PublishError::Failed(format!("the Windows DNS client failed the change: {text}"))
    }
}

/// Runs a PowerShell script from `%SystemRoot%` and maps a failure to a
/// [`PublishError`].
async fn powershell(script: String) -> Result<(), PublishError> {
    let program = powershell_path();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(program)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
    })
    .await
    .map_err(|err| PublishError::Failed(format!("could not run PowerShell: {err}")))?
    .map_err(|err| PublishError::Unavailable(format!("could not run PowerShell: {err}")))?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = if stderr.trim().is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr.trim().to_string()
    };
    Err(classify(if text.is_empty() { "no output" } else { &text }))
}

/// The absolute path to Windows PowerShell, so nothing on `PATH` can stand in
/// for it.
fn powershell_path() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::Path::new(&root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

impl DnsPublisher for NrptPublisher {
    fn name(&self) -> &str {
        "windows-nrpt"
    }

    fn apply<'a>(&'a self, published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>> {
        Box::pin(async move {
            if published.domains.is_empty() {
                return Err(PublishError::Unavailable(
                    "there are no suffixes to route, so there is no rule to write".to_string(),
                ));
            }

            // Windows can only ask on port 53, so a server anywhere else is
            // unreachable this way. Keep the ones it can use.
            let servers: BTreeSet<IpAddr> = published
                .servers
                .iter()
                .filter(|server| server.port() == DNS_PORT)
                .map(|server| server.ip())
                .collect();
            if servers.is_empty() {
                let elsewhere = published
                    .servers
                    .iter()
                    .map(|server| server.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(PublishError::Unavailable(format!(
                    "the Windows DNS client only asks on port {DNS_PORT}, and the server is on \
                     {elsewhere}. Run the server on port {DNS_PORT}, or point your resolver at it \
                     yourself."
                )));
            }

            let namespaces: Vec<String> = published.domains.iter().map(|d| namespace(d)).collect();
            let servers: Vec<String> = servers.iter().map(|ip| ip.to_string()).collect();

            powershell(apply_script(&namespaces, &servers)).await?;

            match self.applied.lock() {
                Ok(mut guard) => *guard = namespaces,
                Err(poisoned) => *poisoned.into_inner() = namespaces,
            }
            Ok(())
        })
    }

    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>> {
        Box::pin(async move {
            let namespaces = match self.applied.lock() {
                Ok(mut guard) => std::mem::take(&mut *guard),
                Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
            };
            if namespaces.is_empty() {
                return Ok(());
            }
            powershell(revert_script(&namespaces)).await
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn a_suffix_gets_a_leading_dot() {
        assert_eq!(namespace("lab"), ".lab");
        assert_eq!(namespace(".lab"), ".lab");
        assert_eq!(namespace("a.b"), ".a.b");
    }

    #[test]
    fn a_quote_in_a_value_cannot_escape_the_literal() {
        // Zone names never contain a quote, but the escaping is what makes
        // that a guarantee rather than a hope.
        assert_eq!(ps_literal("a'b"), "'a''b'");
        assert_eq!(ps_array(&["x".into(), "y".into()]), "@('x','y')");
        assert_eq!(ps_array(&[]), "@()");
    }

    #[test]
    fn the_apply_script_removes_before_it_adds() {
        let script = apply_script(&[".lab".into()], &["10.13.37.69".into()]);
        let remove = script.find("Remove-DnsClientNrptRule").unwrap();
        let add = script.find("Add-DnsClientNrptRule").unwrap();
        assert!(
            remove < add,
            "a stale rule must go before the new one:\n{script}"
        );
        assert!(script.contains("@('.lab')"));
        assert!(script.contains("@('10.13.37.69')"));
    }

    #[test]
    fn an_access_denied_is_a_refusal_a_missing_cmdlet_is_unavailable() {
        assert!(matches!(
            classify("Access is denied"),
            PublishError::Refused(_)
        ));
        assert!(matches!(
            classify("The term 'Add-DnsClientNrptRule' is not recognized"),
            PublishError::Unavailable(_)
        ));
        assert!(matches!(
            classify("something else"),
            PublishError::Failed(_)
        ));
    }

    #[tokio::test]
    async fn a_server_only_on_a_nonstandard_port_is_unavailable_not_a_failure() {
        // Nothing is run: Windows cannot ask there, and saying so is the
        // honest answer without touching the DNS client.
        let publisher = NrptPublisher::new();
        let published = Published {
            interface: "tsun0".into(),
            servers: vec![SocketAddr::from(([10, 13, 37, 69], 5354))],
            domains: vec!["lab".into()],
        };
        let err = publisher.apply(&published).await.unwrap_err();
        assert!(matches!(err, PublishError::Unavailable(_)), "{err}");
    }

    #[tokio::test]
    async fn reverting_without_having_applied_does_nothing_and_succeeds() {
        NrptPublisher::new().revert().await.unwrap();
    }
}
