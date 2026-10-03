//! Telling systemd-resolved to send some questions here.
//!
//! Three calls on `org.freedesktop.resolve1.Manager`, all scoped to the
//! overlay interface:
//!
//! * `SetLinkDNSEx` — where to send them. The `Ex` form carries a **port**,
//!   which is why this server does not have to sit on 53 and the agent needs
//!   no `CAP_NET_BIND_SERVICE`. Systems before systemd 247 have only
//!   `SetLinkDNS`, which has no port; there the fallback only works if the
//!   server did get port 53, and it says so rather than appearing to work.
//! * `SetLinkDomains` with `routing_only` set — a *routing* suffix, the
//!   `~domain` form. It says which questions come here and claims nothing
//!   else.
//! * `SetLinkDefaultRoute(false)` — so this never becomes the resolver for
//!   anything outside those suffixes. Without it resolved may fall back to
//!   this link for ordinary names, and this server refuses those.
//!
//! # It cleans up by itself
//!
//! resolved keys all of this to the interface, and drops it when the
//! interface goes. The overlay interface belongs to a file descriptor the
//! agent holds, so it goes when the agent does — however the agent goes. The
//! explicit `RevertLink` on shutdown only makes that immediate.
//!
//! # Privilege
//!
//! resolved asks polkit, and polkit decides by user id, not by capability.
//! So `CAP_NET_ADMIN` does not help here: an ordinary user is prompted or
//! refused, while a system service running as root is not. That refusal is
//! reported as its own kind of error, because the answer to it is different
//! from the answer to "resolved is not installed".

use std::net::IpAddr;

use crate::BoxFuture;

use super::{DnsPublisher, PublishError, Published, interface_index};

/// `AF_INET`, as resolved wants it.
const AF_INET: i32 = 2;
/// `AF_INET6`.
const AF_INET6: i32 = 10;

#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Resolved {
    /// Servers for a link, with a port and a name. systemd 247 and later.
    #[zbus(name = "SetLinkDNSEx")]
    fn set_link_dns_ex(
        &self,
        ifindex: i32,
        addresses: &[(i32, Vec<u8>, u16, String)],
    ) -> zbus::Result<()>;

    /// Servers for a link, without a port. Always port 53.
    #[zbus(name = "SetLinkDNS")]
    fn set_link_dns(&self, ifindex: i32, addresses: &[(i32, Vec<u8>)]) -> zbus::Result<()>;

    /// Suffixes for a link. The flag makes one routing-only.
    #[zbus(name = "SetLinkDomains")]
    fn set_link_domains(&self, ifindex: i32, domains: &[(String, bool)]) -> zbus::Result<()>;

    /// Whether this link may answer for names outside its suffixes.
    #[zbus(name = "SetLinkDefaultRoute")]
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;

    /// Forgets everything set for a link.
    #[zbus(name = "RevertLink")]
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

/// Configures systemd-resolved over D-Bus.
#[derive(Debug, Default)]
pub struct ResolvedPublisher {
    /// The link last configured, so shutdown knows what to undo.
    applied: std::sync::Mutex<Option<u32>>,
}

impl ResolvedPublisher {
    /// Creates the publisher. Nothing is contacted until [`Self::apply`].
    pub fn new() -> Self {
        Self::default()
    }

    async fn proxy() -> Result<ResolvedProxy<'static>, PublishError> {
        let connection = zbus::Connection::system().await.map_err(|err| {
            PublishError::Unavailable(format!("no system D-Bus to talk to resolved on: {err}"))
        })?;
        ResolvedProxy::new(&connection).await.map_err(|err| {
            PublishError::Unavailable(format!("systemd-resolved is not answering: {err}"))
        })
    }
}

/// Turns a D-Bus failure into the kind of failure it actually is.
fn classify(err: zbus::Error, what: &str) -> PublishError {
    let name = match &err {
        zbus::Error::MethodError(name, _, _) => name.as_str().to_string(),
        _ => String::new(),
    };
    match name.as_str() {
        "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
        | "org.freedesktop.DBus.Error.AccessDenied" => {
            PublishError::Refused(format!("systemd-resolved refused {what}: {err}"))
        }
        "org.freedesktop.DBus.Error.UnknownMethod"
        | "org.freedesktop.DBus.Error.ServiceUnknown" => {
            PublishError::Unavailable(format!("systemd-resolved cannot do {what}: {err}"))
        }
        _ => PublishError::Failed(format!("systemd-resolved failed {what}: {err}")),
    }
}

/// The address in the shape resolved wants: a family and raw octets.
fn wire_address(address: IpAddr) -> (i32, Vec<u8>) {
    match address {
        IpAddr::V4(address) => (AF_INET, address.octets().to_vec()),
        IpAddr::V6(address) => (AF_INET6, address.octets().to_vec()),
    }
}

impl DnsPublisher for ResolvedPublisher {
    fn name(&self) -> &str {
        "systemd-resolved"
    }

    fn apply<'a>(&'a self, published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>> {
        Box::pin(async move {
            let ifindex = interface_index(&published.interface).ok_or_else(|| {
                PublishError::Unavailable(format!(
                    "interface `{}` is not on this host, so there is no link to configure",
                    published.interface
                ))
            })?;
            if published.servers.is_empty() {
                return Err(PublishError::Unavailable(
                    "there is no listening address to send questions to".to_string(),
                ));
            }
            let proxy = Self::proxy().await?;
            let index = ifindex as i32;
            // Every family in one call, because this replaces the link's
            // whole list: sending them one at a time would leave only the
            // last. A resolver then picks whichever it can reach.
            let servers: Vec<(i32, Vec<u8>, u16, String)> = published
                .servers
                .iter()
                .map(|server| {
                    let (family, octets) = wire_address(server.ip());
                    (family, octets, server.port(), String::new())
                })
                .collect();

            match proxy.set_link_dns_ex(index, &servers).await {
                Ok(()) => {}
                Err(err) => {
                    let classified = classify(err, "setting the link's DNS servers");
                    // Older systemd has no `Ex` form, and the plain one is
                    // always port 53. Falling back to it when the server is
                    // somewhere else would point resolved at nothing.
                    if !matches!(classified, PublishError::Unavailable(_)) {
                        return Err(classified);
                    }
                    if let Some(elsewhere) =
                        published.servers.iter().find(|server| server.port() != 53)
                    {
                        return Err(PublishError::Unavailable(format!(
                            "this systemd-resolved cannot be given a port, and the server is on \
                             {}. Run the server on port 53, or point your resolver at \
                             {elsewhere} yourself.",
                            elsewhere.port()
                        )));
                    }
                    let plain: Vec<(i32, Vec<u8>)> = servers
                        .into_iter()
                        .map(|(family, octets, _, _)| (family, octets))
                        .collect();
                    proxy
                        .set_link_dns(index, &plain)
                        .await
                        .map_err(|err| classify(err, "setting the link's DNS servers"))?;
                }
            }

            let domains: Vec<(String, bool)> = published
                .domains
                .iter()
                .map(|domain| (domain.clone(), true))
                .collect();
            proxy
                .set_link_domains(index, &domains)
                .await
                .map_err(|err| classify(err, "setting the link's search domains"))?;

            // Last, and deliberately: until this is off, resolved may send
            // ordinary names here, and this server refuses them.
            proxy
                .set_link_default_route(index, false)
                .await
                .map_err(|err| classify(err, "clearing the link's default route"))?;

            match self.applied.lock() {
                Ok(mut guard) => *guard = Some(ifindex),
                Err(poisoned) => *poisoned.into_inner() = Some(ifindex),
            }
            Ok(())
        })
    }

    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>> {
        Box::pin(async move {
            let applied = match self.applied.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            let Some(ifindex) = applied else {
                return Ok(());
            };
            let proxy = Self::proxy().await?;
            match proxy.revert_link(ifindex as i32).await {
                Ok(()) => Ok(()),
                // The link going away takes the setting with it, so this is
                // the outcome asked for rather than a failure.
                Err(zbus::Error::MethodError(name, _, _))
                    if name.as_str().contains("NoSuchLink") =>
                {
                    Ok(())
                }
                Err(err) => Err(classify(err, "reverting the link")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn an_address_is_encoded_the_way_resolved_expects() {
        assert_eq!(
            wire_address(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 69))),
            (AF_INET, vec![10, 13, 37, 69])
        );
        let (family, octets) = wire_address("fd55::1".parse().unwrap());
        assert_eq!(family, AF_INET6);
        assert_eq!(octets.len(), 16);
    }

    #[tokio::test]
    async fn an_interface_that_is_not_here_is_unavailable_not_a_failure() {
        // Nothing is contacted: there is no link to configure, and saying so
        // is the honest answer without bothering the bus.
        let publisher = ResolvedPublisher::new();
        let published = Published {
            interface: "tsunagi-no-such-interface".into(),
            servers: vec![SocketAddr::from(([10, 13, 37, 69], 5354))],
            domains: vec!["lab".into()],
        };
        let err = publisher.apply(&published).await.unwrap_err();
        assert!(matches!(err, PublishError::Unavailable(_)), "{err}");
    }

    #[tokio::test]
    async fn reverting_without_having_applied_does_nothing_and_succeeds() {
        // The shutdown path must not fail because there was nothing to undo.
        ResolvedPublisher::new().revert().await.unwrap();
    }
}
