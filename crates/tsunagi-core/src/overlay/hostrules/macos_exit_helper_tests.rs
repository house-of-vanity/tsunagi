//! Exercise the installed sharing helper against a throwaway host and PF.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const HELPER: &str = include_str!("macos/exit-offer.sh");
const INSTALL: &str = include_str!("macos/authorize-exit.sh");

struct Host(tempfile::TempDir);

impl Host {
    fn new() -> Self {
        let host = Self(tempfile::tempdir().unwrap());
        let dir = host.0.path();
        let mut helper = HELPER.to_string();
        for (program, body) in [
            (
                "/bin/ps",
                r#"test -f "$HOST/process_$2" && cat "$HOST/process_$2""#,
            ),
            (
                "/sbin/route",
                "printf 'gateway: 192.0.2.1\\ninterface: en7\\n'",
            ),
            (
                "/sbin/ifconfig",
                "echo 'inet 10.13.37.4 --> 10.13.37.4 netmask 0xffffff00'",
            ),
            ("/usr/bin/shlock", "exit 0"),
            (
                "/usr/sbin/sysctl",
                r#"
case "$1" in -n) cat "$HOST/forwarding";; -w) echo 1 > "$HOST/forwarding";; esac"#,
            ),
            (
                "/sbin/pfctl",
                r#"
echo "$*" >> "$HOST/pf.log"
case "$1" in
    -E) echo 'Token : 77' >&2;;
    -q) if [ "$5" = - ]; then cat > "$HOST/rules"; fi;;
esac"#,
            ),
        ] {
            let path = dir.join(Path::new(program).file_name().unwrap());
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            helper = helper.replace(program, path.to_str().unwrap());
        }
        let relocated = |text: &str| {
            text.replace(
                "/private/etc/tsunagi-exit",
                dir.join("grants").to_str().unwrap(),
            )
            .replace(
                "/private/var/run/tsunagi-exit",
                dir.join("state").to_str().unwrap(),
            )
            .replace(
                "/private/etc/sudoers.d",
                dir.join("policy").to_str().unwrap(),
            )
        };
        fs::write(dir.join("helper.sh"), relocated(&helper)).unwrap();
        fs::write(dir.join("forwarding"), "0\n").unwrap();
        fs::write(dir.join("process_321"), "501  Tue Nov 24 16:42:52 2026\n").unwrap();
        fs::write(
            dir.join("installer.sh"),
            relocated(INSTALL).replace("/usr/sbin/visudo", "/usr/bin/true"),
        )
        .unwrap();
        host
    }

    fn run(&self, script: &str, args: &[&str]) -> Output {
        self.run_as("321", script, args)
    }

    fn run_as(&self, pid: &str, script: &str, args: &[&str]) -> Output {
        let mut command = Command::new("/bin/sh");
        command.arg(self.0.path().join(script));
        if script == "helper.sh" {
            command.arg(pid);
        }
        command
            .args(args)
            .env_clear()
            .env("HOST", self.0.path())
            .env("SUDO_UID", "501")
            .output()
            .unwrap()
    }

    fn grant(&self, uid: &str, key: &str) {
        let result = self.run("installer.sh", &[uid, key, HELPER]);
        assert!(result.status.success(), "{:?}", result.stderr);
    }
}

#[test]
fn restarting_with_a_new_utun_releases_a_dead_agents_rules_and_preserves_other_agents() {
    let host = Host::new();
    host.grant("501", "10.13.37.0_24");
    let dir = host.0.path();
    for (pid, iface) in [("321", "utun4"), ("322", "utun5")] {
        fs::write(
            dir.join(format!("process_{pid}")),
            format!("501  born {pid}"),
        )
        .unwrap();
        assert!(
            host.run_as(pid, "helper.sh", &["apply", iface, "10.13.37.0/24"])
                .status
                .success()
        );
    }
    // PID 321 has been reused since that holder's abrupt termination.
    fs::write(dir.join("process_321"), "501  later").unwrap();
    assert!(host.run("helper.sh", &["clear", "utun9"]).status.success());
    assert!(!dir.join("state/tsng_501_4_10.13.37.0_24.token").exists());
    assert!(dir.join("state/tsng_501_5_10.13.37.0_24.token").exists());
}

#[test]
fn privileged_helper_accepts_only_a_granted_subnet_configured_on_the_utun() {
    let host = Host::new();
    host.grant("502", "10.13.37.0_24");
    host.grant("501", "10.13.37.0_16");
    for args in [
        ["apply", "utun4", "10.13.37.0/24"],
        ["apply", "utun4", "10.13.37.0/16"],
        ["apply", "utun4", "10.13.37.0/24;whoami"],
        ["apply", "en0", "10.13.37.0/24"],
        ["apply", "utun4/../", "10.13.37.0/24"],
        ["shell", "utun4", "10.13.37.0/24"],
    ] {
        assert!(!host.run("helper.sh", &args).status.success(), "{args:?}");
    }
    assert!(!host.0.path().join("pf.log").exists());
    assert_eq!(
        fs::read_to_string(host.0.path().join("forwarding")).unwrap(),
        "0\n"
    );
}

#[test]
fn authorized_exit_owns_one_pf_reference_and_clears_only_its_anchor() {
    let host = Host::new();
    host.grant("501", "10.13.37.0_24");
    let dir = host.0.path();
    let rule = fs::read_to_string(dir.join("policy/tsunagi-exit-501")).unwrap();
    assert_eq!(
        rule,
        format!(
            "#501 ALL = (root) NOPASSWD: NOSETENV: {}/grants/offer-v1\n",
            dir.display()
        )
    );
    for _ in 0..2 {
        let result = host.run("helper.sh", &["apply", "utun4", "10.13.37.0/24"]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(fs::read_to_string(dir.join("forwarding")).unwrap(), "1\n");
    let rules = fs::read_to_string(dir.join("rules")).unwrap();
    let uplink = super::DefaultRoute {
        interface: "en7".into(),
        gateway: Some("192.0.2.1".parse().unwrap()),
    };
    assert_eq!(
        rules,
        super::pf_rules("utun4", &uplink, &["10.13.37.0/24".parse().unwrap()], None)
    );
    assert!(host.run("helper.sh", &["clear", "utun4"]).status.success());
    assert!(host.run("helper.sh", &["clear", "utun4"]).status.success());
    let calls = fs::read_to_string(dir.join("pf.log")).unwrap();
    assert_eq!(calls.lines().filter(|line| *line == "-E").count(), 1);
    assert_eq!(calls.lines().filter(|line| *line == "-X 77").count(), 1);
    assert!(calls.contains("-q -a com.apple/tsng_501_4_10.13.37.0_24 -f /dev/null"));
    assert_eq!(fs::read_to_string(dir.join("forwarding")).unwrap(), "1\n");
}
