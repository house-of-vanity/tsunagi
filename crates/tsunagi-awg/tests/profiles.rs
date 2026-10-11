//! Fresh and bounded masking profiles, and rejection of foreign/truncated wire packets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use tsunagi_awg::profile::PairProfile;

#[test]
fn profiles_are_fresh_bounded_and_redacted() {
    let profiles: Vec<_> = (0..128).map(|_| PairProfile::generate()).collect();
    for (i, profile) in profiles.iter().enumerate() {
        profile.validate().unwrap();
        assert!(!format!("{profile:?}").contains(&format!("{:?}", profile.header_key())));
        for other in &profiles[..i] {
            assert_ne!(profile.header_key(), other.header_key());
            assert_ne!(profile.id(), other.id());
        }
        for packet in profile.signature_packets() {
            assert!(packet.len() < 1200);
        }
    }
}

#[test]
fn masked_packets_round_trip_and_reject_other_profiles_and_truncation() {
    let profile = PairProfile::generate();
    let other = PairProfile::generate();
    for (kind, size) in [(1, 148), (2, 92), (3, 64), (4, 800)] {
        let mut message = vec![0x7b; size];
        message[..4].copy_from_slice(&(kind as u32).to_le_bytes());
        let wire = profile.encode(&message).unwrap();
        assert_ne!(&wire[..4], &message[..4]);
        assert_eq!(profile.decode(&wire).unwrap(), message);
        assert!(other.decode(&wire).is_none());
        for length in 0..44 {
            assert!(profile.decode(&wire[..length]).is_none());
        }
    }
}
