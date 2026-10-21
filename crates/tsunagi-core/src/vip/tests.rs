#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::NetworkId;

#[test]
fn concurrent_backend_edits_merge_and_deletion_cannot_resurrect() {
    let net = NetworkId::from_bytes([7; 32]);
    let a = iroh::SecretKey::generate();
    let b = iroh::SecretKey::generate();
    let limits = Limits::default();
    let mut state = VipSet::default();
    let id = hex::encode([9; 16]);
    let initial = VipConfig {
        id: id.clone(),
        name: "api".into(),
        listeners: vec![Listener::new(Protocol::Tcp, 443)],
    };
    let changes = state.edit(net, &a, 1, &initial, None, &limits).unwrap();
    state.merge(net, changes, &limits).unwrap();
    let revision = state.revision(&id);
    let mut first = initial.clone();
    first.listeners[0].backends.push(Backend {
        peer: a.public().to_string(),
        port: 6443,
    });
    let mut second = initial.clone();
    second.listeners[0].backends.push(Backend {
        peer: b.public().to_string(),
        port: 7443,
    });
    let x = state
        .edit(net, &a, 2, &first, Some(&revision), &limits)
        .unwrap();
    let y = state
        .edit(net, &b, 1, &second, Some(&revision), &limits)
        .unwrap();
    let mut reverse = state.clone();
    state.merge(net, x.clone(), &limits).unwrap();
    state.merge(net, y.clone(), &limits).unwrap();
    reverse.merge(net, y, &limits).unwrap();
    reverse.merge(net, x, &limits).unwrap();
    assert_eq!(state.configs(), reverse.configs());
    assert_eq!(state.configs()[0].listeners[0].backends.len(), 2);
    assert!(
        state
            .edit(net, &a, 3, &initial, Some(&revision), &limits)
            .is_err()
    );
    let removed = state.delete(net, &a, 3, &id, &state.revision(&id)).unwrap();
    let old = state.entries(&id);
    state.merge(net, removed, &limits).unwrap();
    state.merge(net, old, &limits).unwrap();
    assert!(state.configs().is_empty());
}

#[test]
fn signed_fields_reject_tampering_wrong_network_and_limits() {
    let net = NetworkId::from_bytes([2; 32]);
    let key = iroh::SecretKey::generate();
    let limits = Limits::default();
    let state = VipSet::default();
    let cfg = VipConfig {
        id: hex::encode([3; 16]),
        name: "dns".into(),
        ..Default::default()
    };
    let entries = state.edit(net, &key, 1, &cfg, None, &limits).unwrap();
    let mut bad = entries.clone();
    bad[0].clock += 1;
    assert!(VipSet::default().merge(net, bad, &limits).is_err());
    assert!(
        VipSet::default()
            .merge(NetworkId::from_bytes([4; 32]), entries.clone(), &limits)
            .is_err()
    );
    let mut small = limits.clone();
    small.max_vips = 0;
    assert!(VipSet::default().merge(net, entries, &small).is_err());
}

#[test]
fn deletion_history_does_not_exhaust_active_capacity_or_accept_stale_fields() {
    let network = NetworkId::from_bytes([9; 32]);
    let key = iroh::SecretKey::generate();
    let limits = Limits {
        max_vips: 1,
        max_vip_tombstones: 4,
        ..Default::default()
    };
    let mut state = VipSet::default();
    for index in 0..4 {
        let config = VipConfig::new("reused-name");
        let fields = state
            .edit(network, &key, index * 2 + 1, &config, None, &limits)
            .unwrap();
        state.merge(network, fields.clone(), &limits).unwrap();
        let deletion = state
            .delete(
                network,
                &key,
                index * 2 + 2,
                &config.id,
                &state.revision(&config.id),
            )
            .unwrap();
        state.merge(network, deletion, &limits).unwrap();
        assert_eq!(state.entries(&config.id).len(), 1);
        assert!(!state.merge(network, fields, &limits).unwrap());
    }
    let next = VipConfig::new("next");
    let fields = state.edit(network, &key, 9, &next, None, &limits).unwrap();
    state.merge(network, fields, &limits).unwrap();
    assert_eq!(state.configs().len(), 1);
}

#[test]
fn reservations_avoid_nodes_and_name_conflicts_have_a_deterministic_holder() {
    let network = NetworkId::from_bytes([4; 32]);
    let key = iroh::SecretKey::generate();
    let limits = Limits::default();
    let mut state = VipSet::default();
    for version in 1..=2 {
        let config = VipConfig::new("shared-name");
        let fields = state
            .edit(network, &key, version, &config, None, &limits)
            .unwrap();
        state.merge(network, fields, &limits).unwrap();
    }
    let range = "10.0.0.0/29".parse().unwrap();
    let taken = ["10.0.0.1".parse().unwrap()].into_iter().collect();
    let views = state.views(Some(range), taken, &Default::default(), &limits);
    assert!(views[0].error.is_none());
    assert!(
        views[1]
            .error
            .as_deref()
            .unwrap()
            .contains("name conflicts")
    );
    assert_ne!(views[0].address, views[1].address);
    for v in views {
        assert_ne!(v.address, Some("10.0.0.1".parse().unwrap()));
    }
}
