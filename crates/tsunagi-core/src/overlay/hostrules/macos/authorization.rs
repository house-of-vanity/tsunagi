//! System authorization for a single local user and IPv4 subnet.

pub(super) const NEEDS_AUTHORIZATION: &str = "Tsunagi exit sharing needs administrator approval";

/// Whether the local user's explicit enable action can be retried after authorization.
pub fn macos_exit_needs_authorization(detail: &str) -> bool {
    macos_exit_authorization_uid(detail).is_some()
}

/// The UID of the local agent that needs the grant, from a native authorization result.
pub fn macos_exit_authorization_uid(detail: &str) -> Option<u32> {
    let suffix = detail
        .strip_prefix(NEEDS_AUTHORIZATION)?
        .strip_prefix(" for UID ")?;
    if !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok().filter(|id| *id != 0)
}

/// Ask the system to authorize exit sharing for this local user and subnet.
/// Only a foreground client calls this, after the daemon tried its available rights.
#[cfg(target_os = "macos")]
pub fn authorize_macos_exit(range: crate::state::Ipv4Range, agent_uid: u32) -> Result<(), String> {
    use std::process::Command;
    const INSTALL: &str = include_str!("authorize-exit.sh");
    const HELPER: &str = include_str!("exit-offer.sh");
    const DIALOG: &str = r#"on run argv
set installCommand to "/bin/sh -c " & quoted form of (item 1 of argv) & " tsunagi " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " " & quoted form of (item 4 of argv)
do shell script installCommand with prompt ("Allow Tsunagi to share this Mac’s internet connection for " & (item 5 of argv) & " as local user " & (item 2 of argv) & "?") with administrator privileges
end run"#;
    if agent_uid == 0 {
        return Err("The system agent already runs as administrator.".into());
    }
    crate::state::Ipv4Range::new(range.base, range.prefix_len).map_err(|e| e.to_string())?;
    let output = Command::new("/usr/bin/osascript")
        .args([
            "-e",
            DIALOG,
            "--",
            INSTALL,
            &agent_uid.to_string(),
            &format!("{}_{}", range.base, range.prefix_len),
            HELPER,
            &range.to_string(),
        ])
        .output()
        .map_err(|e| format!("could not open macOS authorization: {e}"))?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        return Err(if reason.contains("(-128)") {
            "Exit sharing was not authorized.".to_string()
        } else {
            format!("Could not authorize exit sharing: {}", reason.trim())
        });
    }
    Ok(())
}
