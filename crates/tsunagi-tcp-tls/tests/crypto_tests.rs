#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tsunagi_tcp_tls::crypto::PeerCipher;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_peer_cipher_bidirectional_roundtrip() {
    let peer_a_id = iroh::SecretKey::generate().public();
    let peer_b_id = iroh::SecretKey::generate().public();

    let secret_a = StaticSecret::from([10u8; 32]);
    let public_a = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::from([20u8; 32]);
    let public_b = PublicKey::from(&secret_b);

    let cipher_a = PeerCipher::new(peer_a_id, peer_b_id, &secret_a, &public_b);
    let cipher_b = PeerCipher::new(peer_b_id, peer_a_id, &secret_b, &public_a);

    // A -> B
    let msg_from_a = b"hello from node A to node B over Noise E2EE";
    let encrypted_by_a = cipher_a
        .encrypt(msg_from_a)
        .expect("encryption should succeed");
    let decrypted_by_b = cipher_b
        .decrypt(&encrypted_by_a)
        .expect("decryption should succeed");
    assert_eq!(&decrypted_by_b[..], msg_from_a);

    // B -> A
    let msg_from_b = b"hello back from node B to node A";
    let encrypted_by_b = cipher_b
        .encrypt(msg_from_b)
        .expect("encryption should succeed");
    let decrypted_by_a = cipher_a
        .decrypt(&encrypted_by_b)
        .expect("decryption should succeed");
    assert_eq!(&decrypted_by_a[..], msg_from_b);

    // Sequence nonces increment
    let msg2 = b"packet 2";
    let enc2 = cipher_a.encrypt(msg2).expect("encryption should succeed");
    assert_ne!(encrypted_by_a[..8], enc2[..8], "nonces should differ");
    let dec2 = cipher_b.decrypt(&enc2).expect("decryption should succeed");
    assert_eq!(&dec2[..], msg2);
}

#[test]
fn test_tampered_payload_rejected() {
    let peer_a_id = iroh::SecretKey::generate().public();
    let peer_b_id = iroh::SecretKey::generate().public();

    let secret_a = StaticSecret::from([10u8; 32]);
    let public_a = PublicKey::from(&secret_a);

    let secret_b = StaticSecret::from([20u8; 32]);
    let public_b = PublicKey::from(&secret_b);

    let cipher_a = PeerCipher::new(peer_a_id, peer_b_id, &secret_a, &public_b);
    let cipher_b = PeerCipher::new(peer_b_id, peer_a_id, &secret_b, &public_a);

    let encrypted = cipher_a.encrypt(b"secret payload").expect("encrypt");
    // Corrupt one byte of ciphertext
    let len = encrypted.len();
    let mut modified = encrypted.to_vec();
    modified[len - 1] ^= 0xff;

    assert!(
        cipher_b.decrypt(&modified).is_err(),
        "corrupted ciphertext must fail AEAD verification"
    );
}
