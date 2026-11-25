//! Route ownership survives the process that installed the scoped physical
//! routes. A pre-existing compatible route may be used, never adopted.
use super::*;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct ScopedHalf {
    half: u8,
    egress: DefaultRoute,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Journal {
    marker: u32,
    routes: Vec<ScopedHalf>,
    ipv6: bool,
}

#[derive(Debug)]
pub(super) struct ScopedRoutes {
    journal: Option<PathBuf>,
    loaded: bool,
    owned: Journal,
    pub(super) active: Option<DefaultRoute>,
    checked: Option<Instant>,
}

impl Default for ScopedRoutes {
    fn default() -> Self {
        Self {
            journal: None,
            loaded: false,
            owned: Journal {
                marker: rand::random_range(1..i32::MAX as u32),
                routes: Vec::new(),
                ipv6: false,
            },
            active: None,
            checked: None,
        }
    }
}

pub(super) fn marked_args(
    action: &str,
    prefix: &str,
    egress: &DefaultRoute,
    marker: u32,
) -> Vec<String> {
    let mut args = scoped_args(action, prefix, egress);
    // Darwin exposes this otherwise unused route metric through RTM_GET.
    // The nonce separates routes made by independent agents on the same uplink.
    args.extend(["-hopcount".into(), marker.to_string()]);
    args
}

pub(super) fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find_map(|(k, v)| (k == key).then(|| v.trim()))
}

pub(super) fn flag(text: &str, name: &str) -> bool {
    field(text, "flags").is_some_and(|v| v.trim_matches(['<', '>']).split(',').any(|f| f == name))
}

pub(super) fn marker(text: &str) -> Option<u32> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some(i) = line.split_whitespace().position(|v| v == "hopcount") {
            return lines.next()?.split_whitespace().nth(i)?.parse().ok();
        }
    }
    None
}

/// A scoped lookup can return an unscoped LAN route or a default. Only an
/// exact scoped /1 on the requested interface can be ours.
fn inspect(
    run: Run<'_>,
    route: &ScopedHalf,
) -> Result<Option<(DefaultRoute, Option<u32>)>, String> {
    let args = owned(&[
        "-n",
        "get",
        "-ifscope",
        &route.egress.interface,
        "-net",
        HALVES[route.half as usize],
    ]);
    let text = match run_ok(run, Tool::Route, &args, None) {
        Ok(text) => text,
        Err(err)
            if err.contains("not in table")
                || err.contains("No such process")
                || err.contains("bad interface name") =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    };
    let destination = field(&text, "destination");
    let correct_half = match route.half {
        0 => matches!(destination, Some("default" | "0.0.0.0")),
        _ => destination == Some("128.0.0.0"),
    };
    if !correct_half || field(&text, "mask") != Some("128.0.0.0") || !flag(&text, "IFSCOPE") {
        return Ok(None);
    }
    let actual = parse_default_route(&text).ok_or("could not read scoped route interface")?;
    if actual.interface != route.egress.interface {
        return Ok(None);
    }
    let mark = flag(&text, "PROTO2").then(|| marker(&text)).flatten();
    Ok(Some((actual, mark)))
}

impl ScopedRoutes {
    pub(super) fn with_journal(path: PathBuf) -> Self {
        Self {
            journal: Some(path),
            ..Self::default()
        }
    }

    pub(super) fn load(&mut self) -> Result<(), String> {
        if self.loaded {
            return Ok(());
        }
        if let Some(path) = &self.journal {
            match fs::File::open(path) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(4097)
                        .read_to_end(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    if bytes.len() > 4096 {
                        return Err("oversized macOS exit route journal".into());
                    }
                    let data: Journal = postcard::from_bytes(&bytes)
                        .map_err(|e| format!("invalid macOS exit route journal: {e}"))?;
                    if data.marker == 0
                        || data.routes.len() > 8
                        || data
                            .routes
                            .iter()
                            .any(|r| r.half > 1 || !safe_name(&r.egress.interface))
                    {
                        return Err("invalid macOS exit route ownership".into());
                    }
                    self.owned = data;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.to_string()),
            }
        }
        self.loaded = true;
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let Some(path) = &self.journal else {
            return Ok(());
        };
        if self.owned.routes.is_empty() && !self.owned.ipv6 {
            return match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            };
        }
        let tmp = path.with_extension(format!("{}.tmp", rand::random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let bytes = postcard::to_allocvec(&self.owned).map_err(|err| err.to_string())?;
        let mut file = options.open(&tmp).map_err(|err| err.to_string())?;
        let result = file.write_all(&bytes).and_then(|()| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result.map_err(|e| e.to_string())
    }

    pub(super) fn previous(&self) -> Vec<ScopedHalf> {
        self.owned.routes.clone()
    }

    pub(super) fn ipv6_marker(&self) -> Option<u32> {
        self.owned.ipv6.then_some(self.owned.marker)
    }

    pub(super) fn record_ipv6(&mut self, active: bool) -> Result<u32, String> {
        if self.owned.ipv6 != active {
            self.owned.ipv6 = active;
            if let Err(why) = self.save() {
                self.owned.ipv6 = !active;
                return Err(why);
            }
        }
        Ok(self.owned.marker)
    }

    pub(super) fn desired(egress: &DefaultRoute) -> Vec<ScopedHalf> {
        [0, 1]
            .map(|half| ScopedHalf {
                half,
                egress: egress.clone(),
            })
            .into()
    }

    pub(super) fn check_due(&mut self, now: Instant) -> bool {
        if self
            .checked
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(15))
        {
            return false;
        }
        self.checked = Some(now);
        true
    }

    pub(super) fn ensure(&mut self, run: Run<'_>, wanted: &[ScopedHalf]) -> Result<(), String> {
        for route in wanted {
            let current = inspect(run, route)?;
            let action = match current {
                Some((actual, tag))
                    if actual == route.egress
                        && (tag.is_none()
                            || tag == Some(self.owned.marker)
                                && self.owned.routes.contains(route)) =>
                {
                    continue;
                }
                Some((actual, Some(tag)))
                    if tag == self.owned.marker
                        && self.owned.routes.contains(&ScopedHalf {
                            half: route.half,
                            egress: actual.clone(),
                        }) =>
                {
                    "change"
                }
                Some(_) => {
                    return Err(format!(
                        "scoped route {} on {} already belongs to another route owner",
                        HALVES[route.half as usize], route.egress.interface
                    ));
                }
                None => "add",
            };
            if !self.owned.routes.contains(route) {
                if self.owned.routes.len() >= 8 {
                    return Err("too many unreconciled scoped exit routes".into());
                }
                self.owned.routes.push(route.clone());
                if let Err(reason) = self.save() {
                    self.owned.routes.pop();
                    return Err(reason);
                }
            }
            run_ok(
                run,
                Tool::Route,
                &marked_args(
                    action,
                    HALVES[route.half as usize],
                    &route.egress,
                    self.owned.marker,
                ),
                None,
            )?;
            if inspect(run, route)? != Some((route.egress.clone(), Some(self.owned.marker))) {
                return Err(format!(
                    "the scoped route for {} on {} failed ownership verification",
                    HALVES[route.half as usize], route.egress.interface
                ));
            }
        }
        Ok(())
    }

    pub(super) fn retain(&mut self, run: Run<'_>, keep: &[ScopedHalf]) -> Result<(), String> {
        for route in self.previous() {
            if keep.contains(&route) {
                continue;
            }
            if inspect(run, &route)? == Some((route.egress.clone(), Some(self.owned.marker))) {
                run_ok(
                    run,
                    Tool::Route,
                    &scoped_args("delete", HALVES[route.half as usize], &route.egress),
                    None,
                )?;
            }
            self.owned.routes.retain(|r| r != &route);
            if let Err(reason) = self.save() {
                self.owned.routes.push(route);
                return Err(reason);
            }
        }
        Ok(())
    }
}
