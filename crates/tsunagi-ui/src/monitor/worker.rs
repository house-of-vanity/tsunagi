use super::{
    Names,
    history::{Filter, History, Page},
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tsunagi::traffic::TrafficSnapshot;

struct Work {
    samples: VecDeque<(u64, TrafficSnapshot)>,
    filter: Filter,
    names: Arc<Names>,
    keep: bool,
    dirty: bool,
    closed: bool,
    omitted: u64,
    protocols: std::collections::BTreeSet<u8>,
    interrupt: Option<rusqlite::InterruptHandle>,
    page: Arc<Page>,
    error: Option<String>,
}

struct Shared {
    start: Instant,
    state: Mutex<Work>,
    wake: Condvar,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, Work> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A bounded input for the window. Returns false when capture has closed or failed.
#[derive(Clone)]
pub struct Feed(Arc<Shared>);
impl Feed {
    /// Queue an interval without blocking packet forwarding or the render thread.
    pub fn sample(&self, s: TrafficSnapshot) -> bool {
        let mut w = self.0.lock();
        if w.closed {
            return false;
        }
        for row in &s.flows {
            if let tsunagi::traffic::Flow::Ip { protocol, .. } = row.key.flow {
                w.protocols.insert(protocol);
            }
        }
        w.omitted = w.omitted.saturating_add(s.omitted);
        if w.samples.len() >= 2 {
            w.omitted = w.omitted.saturating_add(
                s.flows
                    .iter()
                    .map(|r| r.rx_packets.saturating_add(r.tx_packets))
                    .fold(0u64, u64::saturating_add),
            );
        } else {
            w.samples.push_back((self.elapsed(), s));
        }
        self.0.wake.notify_one();
        true
    }
    /// Display a capture failure while keeping the rows already collected available.
    pub fn error(&self, reason: String) {
        self.0.lock().error = Some(reason);
    }
    pub(super) fn elapsed(&self) -> u64 {
        self.0.start.elapsed().as_millis() as u64
    }
}

pub(super) struct Worker {
    pub feed: Feed,
}
impl Worker {
    pub fn new(directory: Option<PathBuf>) -> Self {
        let shared = Arc::new(Shared {
            start: Instant::now(),
            state: Mutex::new(Work {
                samples: VecDeque::new(),
                filter: Filter::default(),
                names: Arc::default(),
                keep: false,
                dirty: true,
                closed: false,
                omitted: 0,
                protocols: [1, 6, 17].into_iter().collect(),
                interrupt: None,
                page: Arc::default(),
                error: None,
            }),
            wake: Condvar::new(),
        });
        let thread = shared.clone();
        let spawn = std::thread::Builder::new()
            .name("tsng-traffic-window".into())
            .spawn(move || {
                if let Err(e) = run(&thread, directory) {
                    let mut w = thread.lock();
                    w.error = Some(format!("Traffic history: {e}"));
                    w.closed = true;
                }
            });
        if let Err(e) = spawn {
            let mut w = shared.lock();
            w.error = Some(e.to_string());
            w.closed = true;
        }
        Self { feed: Feed(shared) }
    }
    pub fn protocols(&self) -> Vec<u8> {
        self.feed.0.lock().protocols.iter().copied().collect()
    }
    pub fn names(&self, names: Arc<Names>) {
        let mut w = self.feed.0.lock();
        w.names = names;
        w.dirty = true;
        self.feed.0.wake.notify_one();
    }
    pub fn options(&self, filter: Filter, keep: bool) {
        let mut w = self.feed.0.lock();
        if w.filter != filter {
            w.page = Arc::default();
        }
        w.filter = filter;
        w.keep = keep;
        w.dirty = true;
        self.feed.0.wake.notify_one();
    }
    pub fn view(&self) -> (Arc<Page>, u64, Option<String>) {
        let w = self.feed.0.lock();
        (w.page.clone(), w.omitted, w.error.clone())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let mut w = self.feed.0.lock();
        w.closed = true;
        w.samples.clear();
        w.page = Arc::default();
        if let Some(db) = &w.interrupt {
            db.interrupt();
        }
        self.feed.0.wake.notify_one();
    }
}

fn run(shared: &Shared, directory: Option<PathBuf>) -> Result<(), String> {
    let mut db = History::open(directory.as_deref())?;
    shared.lock().interrupt = Some(db.interrupt());
    loop {
        let (mut samples, filter, keep, names) = {
            let w = shared.lock();
            let (mut w, _) = shared
                .wake
                .wait_timeout_while(w, Duration::from_secs(1), |w| {
                    !w.closed && !w.dirty && w.samples.is_empty()
                })
                .unwrap_or_else(|e| e.into_inner());
            if w.closed {
                return Ok(());
            }
            w.dirty = false;
            (
                std::mem::take(&mut w.samples),
                w.filter.clone(),
                w.keep,
                w.names.clone(),
            )
        };
        db.use_names(names.clone());
        if samples.is_empty() {
            db.apply(&[], shared.start.elapsed().as_millis() as u64, 0, keep)?;
        }
        for (now, s) in samples.drain(..) {
            db.apply(&s.flows, now, s.interval_ms, keep)?;
        }
        let page = Arc::new(db.page(&filter)?);
        let mut w = shared.lock();
        if !w.closed && filter == w.filter && Arc::ptr_eq(&names, &w.names) {
            w.page = page;
        }
    }
}
