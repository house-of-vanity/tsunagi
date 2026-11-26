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

    let (cert, _key) =
        generate_self_signed_cert(&identity.secret_bytes(), tsunagi_tcp_tls::cert::DEFAULT_SNI)
            .expect("cert generation should succeed");

    let verifier = PinnedEndpointVerifier::new(peer_id);
    let server_name = ServerName::try_from(tsunagi_tcp_tls::cert::DEFAULT_SNI).unwrap();

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

    let (cert, key) = generate_self_signed_cert(&identity.secret_bytes(), "custom.example.com")
        .expect("cert generation should succeed");

    let server_config = tsunagi_tcp_tls::cert::make_server_config(cert, key);
    assert!(server_config.is_ok());

    let client_config = tsunagi_tcp_tls::cert::make_client_config(peer_id);
    assert!(client_config.is_ok());
}

#[test]
fn unrelated_certificate_fields_cannot_satisfy_the_identity_pin() {
    let expected = DeviceIdentity::generate().endpoint_id();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["peer.invalid".into()]).unwrap();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            expected.as_bytes().to_vec(),
        ));
    let cert = params.self_signed(&key).unwrap();
    assert!(
        PinnedEndpointVerifier::new(expected)
            .verify_server_cert(
                cert.der(),
                &[],
                &ServerName::try_from("peer.invalid").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_err()
    );
}
