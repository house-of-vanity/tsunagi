#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{ServerName, UnixTime};
use tsunagi::identity::DeviceIdentity;
use tsunagi_tcp_tls::cert::{PinnedEndpointVerifier, generate_self_signed_cert};

#[test]
fn test_generate_and_pin_certificate() {
    let identity = DeviceIdentity::generate();
    let peer_id = identity.endpoint_id();

    let (cert, _key) = generate_self_signed_cert(&identity.secret_bytes())
        .expect("cert generation should succeed");

    let verifier = PinnedEndpointVerifier::new(peer_id);
    let server_name = ServerName::try_from("tsunagi.local").unwrap();

    let verified = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());

    assert!(
        verified.is_ok(),
        "certificate matching peer endpoint id must verify"
    );

    let other_identity = DeviceIdentity::generate();
    let wrong_verifier = PinnedEndpointVerifier::new(other_identity.endpoint_id());

    let wrong_verified =
        wrong_verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());

    assert!(
        wrong_verified.is_err(),
        "certificate with wrong endpoint id must fail verification"
    );
}

#[test]
fn test_make_client_and_server_config() {
    let identity = DeviceIdentity::generate();
    let peer_id = identity.endpoint_id();

    let (cert, key) = generate_self_signed_cert(&identity.secret_bytes())
        .expect("cert generation should succeed");

    let server_config = tsunagi_tcp_tls::cert::make_server_config(cert, key);
    assert!(server_config.is_ok());

    let client_config = tsunagi_tcp_tls::cert::make_client_config(peer_id);
    assert!(client_config.is_ok());
}
