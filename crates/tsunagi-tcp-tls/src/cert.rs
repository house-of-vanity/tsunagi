//! TLS certificate generation and verification.
//!
//! Generates a self-signed TLS certificate derived from the device's persistent
//! identity, and verifies remote certificates against the expected peer's
//! [`iroh::EndpointId`].

use std::sync::Arc;

use iroh::EndpointId;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, Error as RustlsError, ServerConfig};

/// Verifies that the server certificate's public key matches the expected peer.
#[derive(Debug)]
pub struct PinnedEndpointVerifier {
    expected: EndpointId,
}

impl PinnedEndpointVerifier {
    /// Creates a verifier expecting `peer`.
    pub fn new(peer: EndpointId) -> Self {
        Self { expected: peer }
    }
}

impl ServerCertVerifier for PinnedEndpointVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Parse the certificate's SPKI / public key
        let cert_bytes = end_entity.as_ref();
        let expected_bytes = self.expected.as_bytes();

        // Check if the expected 32-byte Ed25519 public key is in the certificate
        if cert_bytes
            .windows(32)
            .any(|window| window == expected_bytes)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        // We require TLS 1.3
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Default SNI domain used to disguise TLS connections.
pub const DEFAULT_SNI: &str = "cloudflare.com";

/// Generates a self-signed certificate and private key for TLS 1.3 using
/// a given 32-byte Ed25519 secret key and specified SNI domain.
pub fn generate_self_signed_cert(
    secret_key_bytes: &[u8; 32],
    sni: &str,
) -> Result<
    (
        CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // PKCS#8 prefix for v1 Ed25519 private keys:
    // 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(secret_key_bytes);

    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8);
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)?;
    let mut params = rcgen::CertificateParams::new(vec![sni.to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, sni);

    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der);

    Ok((cert_der, priv_key))
}

/// Creates a `rustls::ServerConfig` for the node.
pub fn make_server_config(
    cert: CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Creates a `rustls::ClientConfig` expecting a specific peer's `EndpointId`.
pub fn make_client_config(expected_peer: EndpointId) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedEndpointVerifier::new(expected_peer));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
