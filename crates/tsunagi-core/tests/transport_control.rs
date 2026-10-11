//! Opaque transport negotiation stays inside authenticated network sessions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use tsunagi::dataplane::transport::{ControlSender, PacketTransport, SharedLink, TransportError};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::proto::message::{ControlMessage, TransportPayload};
use tsunagi::testing::{TestAgent, network, wait_for_peers, wait_until};
use tsunagi::{BoxFuture, NetworkId};

#[derive(Debug, Default)]
struct Negotiator {
    control: Mutex<Option<Arc<dyn ControlSender>>>,
    received: Mutex<Vec<(NetworkId, iroh::EndpointId, Vec<u8>)>>,
}
impl PacketTransport for Negotiator {
    fn name(&self) -> &str {
        "negotiator"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn attach_control(&self, control: Arc<dyn ControlSender>) {
        *self.control.lock().unwrap() = Some(control);
    }
    fn on_control(
        &self,
        network: NetworkId,
        peer: iroh::EndpointId,
        _: &str,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.received
            .lock()
            .unwrap()
            .push((network, peer, payload.to_vec()));
        Ok(())
    }
    fn open<'a>(
        &'a self,
        _: NetworkId,
        _: iroh::EndpointId,
        _: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async { Err(TransportError::Closed) })
    }
}

#[tokio::test]
async fn negotiated_secrets_are_redacted_scoped_and_delivered_over_real_control() {
    let discovery = SharedMemoryDiscovery::new();
    let a_transport = Arc::new(Negotiator::default());
    let b_transport = Arc::new(Negotiator::default());
    let a = TestAgent::spawn_with(
        |c| c.with_custom_transport("negotiator", a_transport.clone()),
        &discovery,
    )
    .await
    .unwrap();
    let b = TestAgent::spawn_with(
        |c| c.with_custom_transport("negotiator", b_transport.clone()),
        &discovery,
    )
    .await
    .unwrap();
    let (name, secret) = network("private-negotiation");
    let id = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, id, 1).await;
    let message = ControlMessage::Transport {
        protocol: "negotiator".into(),
        payload: TransportPayload::new(b"never-export-this-secret".to_vec()),
    };
    assert!(!format!("{message:?}").contains("never-export"));
    let sender = a_transport.control.lock().unwrap().clone().unwrap();
    sender
        .send(
            id,
            b.agent.endpoint_id(),
            "negotiator",
            TransportPayload::new(b"never-export-this-secret".to_vec()),
        )
        .await
        .unwrap();
    wait_until("private transport message", || async {
        (!b_transport.received.lock().unwrap().is_empty()).then_some(())
    })
    .await;
    assert_eq!(
        b_transport.received.lock().unwrap()[0],
        (
            id,
            a.agent.endpoint_id(),
            b"never-export-this-secret".to_vec()
        )
    );
    let unknown = NetworkId::from_bytes([0xa5; 32]);
    assert!(
        sender
            .send(
                unknown,
                b.agent.endpoint_id(),
                "negotiator",
                TransportPayload::new(vec![1])
            )
            .await
            .is_err()
    );
    a.agent.shutdown().await;
    b.agent.shutdown().await;
}

#[test]
fn private_bytes_are_bounded_on_decode_and_by_local_policy() {
    let limits = tsunagi::Limits {
        max_transport_payload_len: 4,
        ..Default::default()
    };
    let message = |len| ControlMessage::Transport {
        protocol: "awg".into(),
        payload: TransportPayload::new(vec![42; len]),
    };
    assert!(tsunagi::proto::message::validate(&message(4), &limits).is_ok());
    assert!(tsunagi::proto::message::validate(&message(5), &limits).is_err());
    let bytes = postcard::to_stdvec(&TransportPayload::new(vec![1; 4097])).unwrap();
    assert!(postcard::from_bytes::<TransportPayload>(&bytes).is_err());
    let bytes = postcard::to_stdvec(&message(4)).unwrap();
    let decoded: ControlMessage = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, message(4));
}
