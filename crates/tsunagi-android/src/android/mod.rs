//! Android process entry points. JNI owns references here, never in the core.
#![allow(unsafe_code)]
mod display;
mod dns;
use crate::{
    plan::VpnPlan,
    service::{Reply, Request, Response, ServiceSignals, State},
    tun::AndroidTun,
};
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JObject, JString, JValue},
    sys::jlong,
};
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::{mpsc, oneshot, watch};
use tsunagi::{Agent, AgentConfig, StoragePaths, TransportPolicy, discovery::MainlineDiscovery};
use tsunagi_wg_quic::{DEFAULT_MTU, WireguardConfig, WireguardPlugin};

struct Session {
    id: i64,
    last_refresh: Option<std::time::Instant>,
    commands: mpsc::Sender<(Request, Reply)>,
    state: watch::Receiver<State>,
    underlay: watch::Sender<Vec<std::net::IpAddr>>,
    signals: watch::Sender<ServiceSignals>,
}
static SESSION: Mutex<Option<Session>> = Mutex::new(None);
// Stop/start can cross on the Android main thread. The previous agent closes
// its fd, endpoint and directory lock before its successor opens that identity.
static LIFETIME: Mutex<()> = Mutex::new(());

fn current() -> std::sync::MutexGuard<'static, Option<Session>> {
    SESSION.lock().unwrap_or_else(|e| e.into_inner())
}
fn status() -> State {
    let mut current = current();
    let Some(session) = current.as_mut() else {
        return State::Off;
    };
    let state = session.state.borrow().clone();
    let report = match &state {
        State::Ready(report, _) => Some(report.as_ref()),
        _ => None,
    };
    if session
        .last_refresh
        .is_none_or(|last| last.elapsed() >= tsunagi_ui::client::status_poll_interval(report))
        && session
            .commands
            .try_send((Request::Refresh, oneshot::channel().0))
            .is_ok()
    {
        session.last_refresh = Some(std::time::Instant::now());
    }
    state
}
fn send(cmd: tsunagi_ui::client::Command) -> Result<Response, String> {
    let (reply, result) = oneshot::channel();
    current()
        .as_ref()
        .ok_or("Tsunagi Agent stopped")?
        .commands
        .try_send((Request::Action(cmd), reply))
        .map_err(|_| "Tsunagi Agent is busy or stopped".to_owned())?;
    Ok(result)
}

#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_trust(
    mut env: jni_verifier::EnvUnowned,
    _: jni_verifier::objects::JObject,
    app: jni_verifier::objects::JObject,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, app))
        .resolve::<jni_verifier::errors::ThrowRuntimeExAndDefault>();
}

fn establish(vm: &JavaVM, service: &GlobalRef, plan: &VpnPlan) -> io::Result<File> {
    let mut env = vm.attach_current_thread().map_err(io::Error::other)?;
    let addresses = plan
        .addresses_in_order()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let routes = plan.routes().join(",");
    let result = env.with_local_frame(6, |env| -> jni::errors::Result<i32> {
        let addresses = env.new_string(addresses)?;
        let routes = env.new_string(routes)?;
        let dns = env.new_string(
            plan.dns_address()
                .map(|a| a.to_string())
                .unwrap_or_default(),
        )?;
        env.call_method(
            service,
            "establishTun",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IZ)I",
            &[
                JValue::Object(&addresses),
                JValue::Object(&routes),
                JValue::Object(&dns),
                JValue::Int(plan.mtu as i32),
                JValue::Bool(plan.full_tunnel.into()),
            ],
        )?
        .i()
    });
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return Err(io::Error::other(
            "Android could not establish the VPN. Check the VPN permission.",
        ));
    }
    let fd = result.map_err(io::Error::other)?;
    if fd < 0 {
        return Err(io::Error::other("Android revoked the VPN permission"));
    }
    // SAFETY: establishTun transferred exclusive ownership with detachFd().
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_start(
    mut env: JNIEnv,
    _: JObject,
    service: JObject,
    app: JObject,
    state_dir: JString,
    cache_dir: JString,
    addresses: JString,
    metered: jni::sys::jboolean,
) -> jlong {
    let result = (|| -> Result<i64, Box<dyn std::error::Error>> {
        // Keep the application (never an activity) alive for DNS throughout the process.
        static APPLICATION: OnceLock<GlobalRef> = OnceLock::new();
        let vm = Arc::new(env.get_java_vm()?);
        let application = env.new_global_ref(app)?;
        if APPLICATION.set(application.clone()).is_ok() {
            // SAFETY: the VM and this stored global reference live until process exit.
            unsafe {
                iroh::dns::install_android_jni_context(
                    vm.get_java_vm_pointer().cast(),
                    application.as_obj().as_raw().cast(),
                );
            }
        }
        let service = env.new_global_ref(service)?;
        let state_dir: String = env.get_string(&state_dir)?.into();
        let cache_dir: String = env.get_string(&cache_dir)?.into();
        let paths = StoragePaths::new(PathBuf::from(state_dir), PathBuf::from(cache_dir));
        let tun_vm = vm.clone();
        let tun_service = service.clone();
        let notice_vm = vm.clone();
        let notice_service = service.clone();
        let sdk = env
            .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")?
            .i()?;
        let dns = dns::resolver(vm.clone(), service.clone(), sdk);
        let factory = AndroidTun::new(
            dns.clone(),
            move |plan| establish(&tun_vm, &tun_service, plan),
            move |socket, source| {
                let mut env = vm.attach_current_thread().map_err(io::Error::other)?;
                let result = env.with_local_frame(3, |env| -> jni::errors::Result<bool> {
                    let source = env.new_string(source.to_string())?;
                    env.call_method(
                        &service,
                        "bindOverlaySocket",
                        "(ILjava/lang/String;)Z",
                        &[JValue::Int(socket.as_raw_fd()), JValue::Object(&source)],
                    )?
                    .z()
                });
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                    return Err(io::Error::other("VPN socket binding failed"));
                }
                if result.map_err(io::Error::other)? {
                    Ok(())
                } else {
                    Err(io::Error::other("VPN network is unavailable"))
                }
            },
        );
        let addresses: String = env.get_string(&addresses)?.into();
        let (underlay, physical) = watch::channel(underlay_ips(&addresses));
        let (commands, rx) = mpsc::channel(16);
        let (state, state_rx) = watch::channel(State::Starting);
        let (signals, updates) = watch::channel(ServiceSignals {
            stopped: false,
            metered: metered != 0,
        });
        static NEXT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut slot = current();
        if let Some(old) = slot.as_ref() {
            old.signals.send_modify(|s| s.stopped = true);
        }
        std::thread::Builder::new()
            .name("tsunagi-agent".into())
            .spawn(move || {
                let _lifetime = LIFETIME.lock().unwrap_or_else(|e| e.into_inner());
                if updates.borrow().stopped {
                    return;
                }
                let run = || -> Result<(), Box<dyn std::error::Error>> {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        let wg = WireguardPlugin::open(WireguardConfig::new(
                            paths.state_dir.join("wg-quic"),
                        ))
                        .await?;
                        let config = AgentConfig::new(paths)
                            .with_transport(TransportPolicy::N0Defaults)
                            .with_dht(MainlineDiscovery::default())
                            .with_interface(Arc::new(factory), "tsunagi-vpn", DEFAULT_MTU)
                            .with_tunnel(wg.clone());
                        let (config, carriers) = tsunagi_runtime::Carriers::configure(
                            config,
                            &[],
                            Some(physical),
                            |_| Vec::new(),
                        )
                        .await?;
                        let agent = Agent::spawn(config).await?;
                        let _listeners = carriers.listen(&agent);
                        crate::service::serve(agent, wg, dns, rx, &state, updates, |notice| {
                            update_exit_notification(&notice_vm, &notice_service, id, notice);
                        })
                        .await;
                        Ok(())
                    })
                };
                if let Err(e) = run() {
                    state.send_replace(State::Error(e.to_string()));
                }
            })?;
        *slot = Some(Session {
            id,
            last_refresh: None,
            commands,
            state: state_rx,
            underlay,
            signals,
        });
        Ok(id)
    })();
    match result {
        Ok(id) => id,
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalStateException", e.to_string());
            0
        }
    }
}

fn update_exit_notification(
    vm: &JavaVM,
    service: &GlobalRef,
    id: i64,
    notice: Option<&crate::service::ExitNotice>,
) {
    let Ok(mut env) = vm.attach_current_thread() else {
        return;
    };
    let _ = env.with_local_frame(8, |env| -> jni::errors::Result<()> {
        let network = env.new_string(notice.map_or("", |n| &n.network))?;
        let peer = env.new_string(notice.map_or("", |n| &n.peer))?;
        let name = env.new_string(notice.map_or("", |n| &n.name))?;
        let title = env.new_string(
            notice
                .map(|n| format!("Exit node · {}", n.name))
                .unwrap_or_default(),
        )?;
        let text = env.new_string(
            notice
                .map(|n| {
                    if n.online {
                        format!("IPv4 internet via {}", n.network_name)
                    } else {
                        format!(
                            "{} · Exit offline. IPv4 internet is blocked.",
                            n.network_name
                        )
                    }
                })
                .unwrap_or_default(),
        )?;
        env.call_method(
            service,
            "updateExitNotification",
            "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V",
            &[
                JValue::Long(id),
                JValue::Object(&network),
                JValue::Object(&peer),
                JValue::Object(&title),
                JValue::Object(&text),
                JValue::Object(&name),
                JValue::Bool(notice.is_some_and(|n| n.online).into()),
            ],
        )?;
        Ok(())
    });
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_disconnectExit(
    mut env: JNIEnv,
    _: JObject,
    id: jlong,
    network: JString,
    peer: JString,
) -> jni::sys::jboolean {
    let (Ok(network), Ok(peer)) = (env.get_string(&network), env.get_string(&peer)) else {
        return false.into();
    };
    current()
        .as_ref()
        .filter(|s| s.id == id)
        .is_some_and(|s| {
            s.commands
                .try_send((
                    Request::DisconnectExit {
                        network: network.into(),
                        peer: peer.into(),
                    },
                    oneshot::channel().0,
                ))
                .is_ok()
        })
        .into()
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_tileExit(
    mut env: JNIEnv,
    _: JObject,
    id: jlong,
    network: JString,
    peer: JString,
    connect: jni::sys::jboolean,
    wait_for_discovery: jni::sys::jboolean,
) -> jni::sys::jstring {
    // Called on the tile's background worker. Never hold the session lock while awaiting the agent.
    let mut run = || -> Result<(), String> {
        let network: String = env.get_string(&network).map_err(|e| e.to_string())?.into();
        let peer: String = env.get_string(&peer).map_err(|e| e.to_string())?.into();
        let (commands, mut state) = current()
            .as_ref()
            .filter(|s| s.id == id)
            .map(|s| (s.commands.clone(), s.state.clone()))
            .ok_or("Tsunagi Agent stopped")?;
        if connect != 0 && wait_for_discovery != 0 {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|e| e.to_string())?
                .block_on(crate::service::wait_for_exit_offer(
                    &mut state, &network, &peer,
                ))?;
        }
        let request = if connect != 0 {
            Request::RestoreExit { network, peer }
        } else {
            Request::DisconnectExit { network, peer }
        };
        let (reply, result) = oneshot::channel();
        commands
            .try_send((request, reply))
            .map_err(|_| "Tsunagi Agent is busy or stopped")?;
        result
            .blocking_recv()
            .map_err(|_| "Tsunagi Agent stopped")??;
        Ok(())
    };
    run()
        .err()
        .and_then(|e| env.new_string(e).ok())
        .map_or(std::ptr::null_mut(), JString::into_raw)
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_failed(
    _: JNIEnv,
    _: JObject,
    id: jlong,
) -> jni::sys::jboolean {
    current()
        .as_ref()
        .is_some_and(|s| s.id == id && matches!(*s.state.borrow(), State::Error(_)))
        .into()
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_stop(_: JNIEnv, _: JObject, id: jlong) {
    let mut slot = current();
    if slot.as_ref().is_some_and(|s| s.id == id)
        && let Some(session) = slot.take()
    {
        session.signals.send_modify(|s| s.stopped = true);
    }
}
fn underlay_ips(addresses: &str) -> Vec<std::net::IpAddr> {
    addresses
        .split(',')
        .take(32)
        .filter_map(|s| s.parse().ok())
        .collect()
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_setMetered(
    _: JNIEnv,
    _: JObject,
    id: jlong,
    metered: jni::sys::jboolean,
) {
    if let Some(s) = current().as_ref().filter(|s| s.id == id) {
        s.signals.send_if_modified(|signals| {
            let changed = signals.metered != (metered != 0);
            signals.metered = metered != 0;
            changed
        });
    }
}
#[unsafe(no_mangle)]
extern "system" fn Java_cy_hexor_tsunagi_Native_networkChanged(
    mut env: JNIEnv,
    _: JObject,
    id: jlong,
    addresses: JString,
) {
    let Ok(raw) = env.get_string(&addresses) else {
        return;
    };
    if let Some(s) = current().as_ref().filter(|s| s.id == id) {
        s.underlay.send_replace(underlay_ips(&String::from(raw)));
        let _ = s
            .commands
            .try_send((Request::NetworkChanged, oneshot::channel().0));
    }
}
