//! Shared services use real membership, signed state and mandatory SQLite.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::testing::{TestAgent, config_with, network, wait_for_peers, wait_until};
use tsunagi::vip::{Backend, Listener, Protocol, VipConfig, VipStatus};
use tsunagi::{Agent, NetworkId};
async fn view(agent: &Agent, network: NetworkId, id: &str) -> VipStatus {
    wait_until("VIP configuration reaches the replica", || async {
        agent
            .network_status(network)
            .await
            .ok()?
            .vips
            .into_iter()
            .find(|v| v.config.id == id)
    })
    .await
}
#[tokio::test]
async fn any_member_can_edit_services_and_an_offline_creator_is_not_required() {
    let discovery = SharedMemoryDiscovery::new();
    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let (name, secret) = network("shared-vips");
    let net = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, net, 1).await;
    let cfg = VipConfig::new("api");
    a.agent
        .save_vip(net, cfg.clone(), None, false)
        .await
        .unwrap();
    let before = view(&b.agent, net, &cfg.id).await;
    let mut edited = before.config.clone();
    let mut listener = Listener::new(Protocol::Tcp, 443);
    listener.backends.push(Backend {
        peer: b.agent.endpoint_id().to_string(),
        port: 6443,
    });
    edited.listeners.push(listener);
    b.agent
        .save_vip(net, edited.clone(), Some(before.revision.clone()), false)
        .await
        .unwrap();
    assert!(
        b.agent
            .save_vip(net, cfg.clone(), Some(before.revision), false)
            .await
            .is_err()
    );
    wait_until("creator observes another member's edit", || async {
        (view(&a.agent, net, &cfg.id).await.config == edited).then_some(())
    })
    .await;
    let a_dir = a.stop().await;
    let c = TestAgent::spawn(&discovery).await.unwrap();
    c.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(view(&c.agent, net, &cfg.id).await.config, edited);
    let a = Agent::spawn(config_with(a_dir.path(), &discovery))
        .await
        .unwrap();
    assert_eq!(view(&a, net, &cfg.id).await.config, edited);
    let current = view(&c.agent, net, &cfg.id).await;
    c.agent
        .save_vip(net, current.config, Some(current.revision), true)
        .await
        .unwrap();
    wait_until("deletion reaches the original creator", || async {
        a.network_status(net)
            .await
            .ok()?
            .vips
            .is_empty()
            .then_some(())
    })
    .await;
    a.shutdown().await;
    b.stop().await;
    c.stop().await;
}
#[tokio::test]
async fn invalid_drafts_are_atomic_and_services_do_not_cross_networks() {
    let discovery = SharedMemoryDiscovery::new();
    let a = TestAgent::spawn(&discovery).await.unwrap();
    let (name, secret) = network("vip-one");
    let net = a.agent.join_network(&name, &secret).await.unwrap();
    let (other, secret) = network("vip-two");
    let second = a.agent.join_network(&other, &secret).await.unwrap();
    let mut cfg = VipConfig::new("api");
    cfg.listeners.push(Listener::new(Protocol::Udp, 53));
    a.agent
        .save_vip(net, cfg.clone(), None, false)
        .await
        .unwrap();
    let before = view(&a.agent, net, &cfg.id).await;
    let mut invalid = before.config.clone();
    invalid.name = "renamed".into();
    invalid.listeners.push(invalid.listeners[0].clone());
    assert!(
        a.agent
            .save_vip(net, invalid, Some(before.revision.clone()), false)
            .await
            .is_err()
    );
    let after = view(&a.agent, net, &cfg.id).await;
    assert_eq!(after.config, before.config);
    assert_eq!(after.revision, before.revision);
    assert!(
        a.agent
            .network_status(second)
            .await
            .unwrap()
            .vips
            .is_empty()
    );
    a.stop().await;
}

#[tokio::test]
async fn a_restored_author_advances_its_counter_past_its_own_updates_held_by_a_replica() {
    use tsunagi::config::StoragePaths;
    use tsunagi::storage::StateStore;
    use tsunagi::vip::VipSet;
    let discovery = SharedMemoryDiscovery::new();
    let a = TestAgent::spawn(&discovery).await.unwrap();
    let b = TestAgent::spawn(&discovery).await.unwrap();
    let (name, secret) = network("vip-author-recovery");
    let net = a.agent.join_network(&name, &secret).await.unwrap();
    b.agent.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&a.agent, net, 1).await;
    let config = VipConfig::new("api");
    a.agent
        .save_vip(net, config.clone(), None, false)
        .await
        .unwrap();
    view(&b.agent, net, &config.id).await;
    let author = a.agent.endpoint_id();
    let adir = a.stop().await;
    let bdir = b.stop().await;
    let apath = StoragePaths::under(adir.path()).state_db();
    let bpath = StoragePaths::under(bdir.path()).state_db();
    // Model an old author backup with a newer, genuinely signed update retained
    // by another offline replica. Connections and recovery below remain real.
    tokio::task::spawn_blocking(move || {
        let a = StateStore::open(apath).unwrap();
        let b = StateStore::open(bpath).unwrap();
        let mut set = VipSet::default();
        set.merge(
            net,
            a.vip_fields(net, 192).unwrap(),
            &tsunagi::Limits::default(),
        )
        .unwrap();
        let mut cfg = set.configs().remove(0);
        cfg.name = "newer".into();
        let key =
            iroh::SecretKey::from_bytes(&a.device_identity().unwrap().unwrap().secret_bytes());
        let fields = set
            .edit(
                net,
                &key,
                100,
                &cfg,
                Some(&set.revision(&cfg.id)),
                &tsunagi::Limits::default(),
            )
            .unwrap();
        set.merge(net, fields, &tsunagi::Limits::default()).unwrap();
        b.put_vip_fields(net, &set.entries(&cfg.id), None).unwrap();
    })
    .await
    .unwrap();
    let b = Agent::spawn(config_with(bdir.path(), &discovery))
        .await
        .unwrap();
    let a = Agent::spawn(config_with(adir.path(), &discovery))
        .await
        .unwrap();
    let learned = wait_until(
        "the restored author learns its newer signed service",
        || async {
            let v = view(&a, net, &config.id).await;
            (v.config.name == "newer").then_some(v)
        },
    )
    .await;
    let mut next = learned.config;
    next.name = "latest".into();
    a.save_vip(net, next, Some(learned.revision), false)
        .await
        .unwrap();
    a.shutdown().await;
    let path = StoragePaths::under(adir.path()).state_db();
    let version = tokio::task::spawn_blocking(move || {
        StateStore::open(path)
            .unwrap()
            .own_record_version(net, author)
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        version > 100,
        "the observed author counter must not be reused"
    );
    b.shutdown().await;
}
