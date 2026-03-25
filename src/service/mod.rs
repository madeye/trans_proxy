//! System service installation and removal.
//!
//! Platform-specific implementations:
//! - **macOS**: LaunchDaemon plist management via launchctl
//! - **Linux**: systemd unit file management via systemctl

use anyhow::{bail, Context, Result};
use std::process::Command;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{install, start, stop, uninstall};

#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{install, start, stop, uninstall};

/// Bail if not running as root (euid != 0).
pub(crate) fn check_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("This command must be run as root (use sudo)");
    }
    Ok(())
}

/// Set the file at `path` to mode 755.
pub(crate) fn set_executable(path: &str) -> Result<()> {
    run_cmd("chmod", &["755", path])
}

/// Run a shell command and bail on non-zero exit.
pub(crate) fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {cmd}"))?;
    if !status.success() {
        bail!("{cmd} failed (exit code: {:?})", status.code());
    }
    Ok(())
}

/// Filter out service/daemon-related arguments that shouldn't appear in the service config.
pub(crate) fn filter_service_args(args: &[String]) -> Vec<String> {
    let skip_flags = [
        "--install",
        "--uninstall",
        "--start",
        "--stop",
        "--daemon",
        "-d",
    ];
    let skip_with_value = ["--pid-file", "--log-file"];

    let mut result = Vec::new();
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if skip_flags.contains(&arg.as_str()) {
            continue;
        }

        // Handle --flag=value and --flag value forms
        let mut matched = false;
        for prefix in &skip_with_value {
            if arg == *prefix {
                skip_next = true;
                matched = true;
                break;
            }
            if arg.starts_with(&format!("{prefix}=")) {
                matched = true;
                break;
            }
        }

        if !matched {
            result.push(arg.clone());
        }
    }

    result
}

/// Extract a flag's value from args (supports `--flag value` and `--flag=value` forms).
pub(crate) fn extract_arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().map(|s| s.as_str());
        }
        if let Some(val) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(val);
        }
    }
    None
}

/// Check whether a boolean flag is present in the argument list.
pub(crate) fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_service_args_removes_flags() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--install".into(),
            "--dns".into(),
        ];
        let filtered = filter_service_args(&args);
        assert_eq!(
            filtered,
            vec!["--upstream-proxy", "127.0.0.1:1082", "--dns"]
        );
    }

    #[test]
    fn test_filter_service_args_removes_daemon_and_short_flag() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "-d".into(),
            "--uninstall".into(),
        ];
        let filtered = filter_service_args(&args);
        assert_eq!(filtered, vec!["--upstream-proxy", "127.0.0.1:1082"]);
    }

    #[test]
    fn test_filter_service_args_removes_value_flags_space_form() {
        let args: Vec<String> = vec![
            "--pid-file".into(),
            "/var/run/test.pid".into(),
            "--log-file".into(),
            "/var/log/test.log".into(),
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
        ];
        let filtered = filter_service_args(&args);
        assert_eq!(filtered, vec!["--upstream-proxy", "127.0.0.1:1082"]);
    }

    #[test]
    fn test_filter_service_args_removes_value_flags_equals_form() {
        let args: Vec<String> = vec![
            "--pid-file=/var/run/test.pid".into(),
            "--log-file=/var/log/test.log".into(),
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
        ];
        let filtered = filter_service_args(&args);
        assert_eq!(filtered, vec!["--upstream-proxy", "127.0.0.1:1082"]);
    }

    #[test]
    fn test_filter_service_args_empty() {
        let args: Vec<String> = vec![];
        let filtered = filter_service_args(&args);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_service_args_all_filtered() {
        let args: Vec<String> = vec![
            "--install".into(),
            "--daemon".into(),
            "--pid-file".into(),
            "/tmp/p".into(),
        ];
        let filtered = filter_service_args(&args);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_extract_arg() {
        let args: Vec<String> = vec![
            "--interface".into(),
            "wlan0".into(),
            "--listen-addr".into(),
            "0.0.0.0:9999".into(),
        ];
        assert_eq!(extract_arg(&args, "--interface"), Some("wlan0"));
        assert_eq!(extract_arg(&args, "--listen-addr"), Some("0.0.0.0:9999"));
        assert_eq!(extract_arg(&args, "--dns"), None);

        let args_eq: Vec<String> = vec!["--interface=br0".into()];
        assert_eq!(extract_arg(&args_eq, "--interface"), Some("br0"));
    }

    #[test]
    fn test_has_flag() {
        let args: Vec<String> = vec![
            "--local-traffic".into(),
            "--dns".into(),
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
        ];
        assert!(has_flag(&args, "--local-traffic"));
        assert!(has_flag(&args, "--dns"));
        assert!(!has_flag(&args, "--daemon"));
    }
}
