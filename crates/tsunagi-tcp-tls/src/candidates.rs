//! Bounded address selection shared by native TCP carriers.
use iroh::EndpointId;
use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Duration};
use tokio::{
    net::TcpStream,
    task::JoinSet,
    time::{sleep, timeout},
};
use tsunagi::{
    NetworkId,
    dataplane::transport::{PacketTransport, SharedLink, TransportError},
};

/// TCP service registered on its own port, using authenticated, per-network announcements.
pub trait TcpEndpoint: PacketTransport {
    /// Independent version of the data carrier.
    fn wire_version(&self) -> u16;
    /// Actual bound TCP port.
    fn bound_port(&self) -> u16;
    /// Replace reachability for one membership; an empty list still permits reverse dialing.
    fn set_pair_addresses(
        &self,
        network: NetworkId,
        peer: EndpointId,
        addresses: Option<Vec<SocketAddr>>,
    );
    /// Retire candidates and negotiations belonging to this network.
    fn clear_network(&self, network: NetworkId);
}

#[derive(Debug, Default)]
pub(crate) struct Candidates {
    pub(crate) pairs: Mutex<HashMap<(NetworkId, EndpointId), Vec<SocketAddr>>>,
    pub(crate) manual: Mutex<HashMap<EndpointId, Vec<SocketAddr>>>,
}

/// Stagger TCP connects so a stale LAN address cannot hide a reachable candidate.
/// Only one connected socket at a time negotiates a link with the remote peer.
pub async fn dial_candidates<F, Fut>(
    addresses: Vec<SocketAddr>,
    mut authenticate: F,
) -> Result<SharedLink, TransportError>
where
    F: FnMut(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = Result<SharedLink, TransportError>>,
{
    timeout(Duration::from_secs(8), async {
        let mut connects = JoinSet::new();
        for (i, addr) in addresses.into_iter().take(32).enumerate() {
            connects.spawn(async move {
                sleep(Duration::from_millis(60 * i as u64)).await;
                let socket = timeout(Duration::from_secs(3), TcpStream::connect(addr))
                    .await
                    .ok()?
                    .ok()?;
                Some((socket, addr))
            });
        }
        let mut error = TransportError::Unreachable("no reachable TCP listener for peer".into());
        while let Some(result) = connects.join_next().await {
            if let Ok(Some((socket, addr))) = result {
                let _ = socket.set_nodelay(true);
                match timeout(Duration::from_secs(4), authenticate(socket, addr)).await {
                    Ok(Ok(link)) => return Ok(link),
                    Ok(Err(err)) => error = err,
                    Err(_) => error = TransportError::Unreachable("TCP handshake timed out".into()),
                }
            }
        }
        Err(error)
    })
    .await
    .map_err(|_| TransportError::Unreachable("TCP dial timed out".into()))?
}

/// Bind one port for both address families where the host supports dual-stack TCP.
pub fn listen(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let ipv6 = || -> std::io::Result<std::net::TcpListener> {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        socket.listen(128)?;
        Ok(socket.into())
    };
    let socket =
        ipv6().or_else(|_| std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)))?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket)
}
