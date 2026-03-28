//! macOS launchd service installation and removal.
//!
//! Installs trans_proxy as a system-wide LaunchDaemon so it starts
//! automatically on boot. Requires root privileges.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

use super::{check_root, extract_arg, filter_service_args, has_flag, run_cmd, set_executable};

const PLIST_LABEL: &str = "com.github.madeye.trans_proxy";
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.github.madeye.trans_proxy.plist";
const INSTALL_BIN: &str = "/usr/local/bin/trans_proxy";
const LOG_PATH: &str = "/var/log/trans_proxy.log";
const SCRIPTS_DIR: &str = "/usr/local/lib/trans_proxy";
const PF_SETUP_SCRIPT: &str = "/usr/local/lib/trans_proxy/pf_setup.sh";
const PF_TEARDOWN_SCRIPT: &str = "/usr/local/lib/trans_proxy/pf_teardown.sh";
const WRAPPER_SCRIPT: &str = "/usr/local/lib/trans_proxy/run.sh";

const PF_SETUP_SCRIPT_CONTENT: &str = include_str!("../../scripts/pf_setup.sh");
const PF_TEARDOWN_SCRIPT_CONTENT: &str = include_str!("../../scripts/pf_teardown.sh");

/// Install trans_proxy as a launchd LaunchDaemon.
///
/// 1. Copies the running binary to `/usr/local/bin/trans_proxy`
/// 2. Generates a launchd plist from the provided proxy arguments
/// 3. Writes the plist to `/Library/LaunchDaemons/`
/// 4. Loads the service with `launchctl`
pub fn install(args: &[String]) -> Result<()> {
    check_root()?;

    // Get the path to the currently running binary
    let current_exe =
        std::env::current_exe().context("Failed to determine current executable path")?;

    // Copy binary to /usr/local/bin
    println!("Installing binary to {INSTALL_BIN}...");
    std::fs::copy(&current_exe, INSTALL_BIN)
        .with_context(|| format!("Failed to copy {} to {INSTALL_BIN}", current_exe.display()))?;

    // Make sure it's executable
    set_executable(INSTALL_BIN)?;

    // Install pf scripts
    println!("Installing pf scripts to {SCRIPTS_DIR}/...");
    std::fs::create_dir_all(SCRIPTS_DIR)
        .with_context(|| format!("Failed to create {SCRIPTS_DIR}"))?;
    std::fs::write(PF_SETUP_SCRIPT, PF_SETUP_SCRIPT_CONTENT)
        .with_context(|| format!("Failed to write {PF_SETUP_SCRIPT}"))?;
    std::fs::write(PF_TEARDOWN_SCRIPT, PF_TEARDOWN_SCRIPT_CONTENT)
        .with_context(|| format!("Failed to write {PF_TEARDOWN_SCRIPT}"))?;
    set_executable(PF_SETUP_SCRIPT)?;
    set_executable(PF_TEARDOWN_SCRIPT)?;

    // Generate and install the wrapper script (runs pf setup/teardown around trans_proxy)
    let wrapper = generate_wrapper(args);
    println!("Installing wrapper script to {WRAPPER_SCRIPT}...");
    std::fs::write(WRAPPER_SCRIPT, &wrapper)
        .with_context(|| format!("Failed to write {WRAPPER_SCRIPT}"))?;
    set_executable(WRAPPER_SCRIPT)?;

    // Generate and write the plist
    let plist = generate_plist(args);
    println!("Writing launchd plist to {PLIST_PATH}...");
    std::fs::write(PLIST_PATH, &plist)
        .with_context(|| format!("Failed to write plist to {PLIST_PATH}"))?;

    // Set proper ownership and permissions
    run_cmd("chmod", &["644", PLIST_PATH])?;
    run_cmd("chown", &["root:wheel", PLIST_PATH])?;

    // Load the service
    println!("Loading service...");
    // Use launchctl bootstrap for modern macOS (10.10+)
    let status = Command::new("launchctl")
        .args(["load", "-w", PLIST_PATH])
        .status()
        .context("Failed to run launchctl")?;

    if !status.success() {
        bail!("launchctl load failed (exit code: {:?})", status.code());
    }

    println!("Service installed and started successfully.");
    println!("  Label:   {PLIST_LABEL}");
    println!("  Binary:  {INSTALL_BIN}");
    println!("  Scripts: {SCRIPTS_DIR}/");
    println!("  Plist:   {PLIST_PATH}");
    println!("  Log:     {LOG_PATH}");
    println!();
    println!("Manage with:");
    println!("  sudo launchctl stop  {PLIST_LABEL}");
    println!("  sudo launchctl start {PLIST_LABEL}");
    println!("  sudo trans_proxy --uninstall");

    Ok(())
}

/// Start the installed trans_proxy LaunchDaemon.
pub fn start() -> Result<()> {
    check_root()?;

    if !Path::new(PLIST_PATH).exists() {
        bail!("Service is not installed (no plist at {PLIST_PATH}). Run with --install first.");
    }

    println!("Starting service...");
    run_cmd("launchctl", &["load", "-w", PLIST_PATH])?;
    println!("Service started.");
    Ok(())
}

/// Stop the installed trans_proxy LaunchDaemon.
pub fn stop() -> Result<()> {
    check_root()?;

    if !Path::new(PLIST_PATH).exists() {
        bail!("Service is not installed (no plist at {PLIST_PATH}). Run with --install first.");
    }

    println!("Stopping service...");
    run_cmd("launchctl", &["unload", PLIST_PATH])?;
    println!("Service stopped.");
    Ok(())
}

/// Uninstall the trans_proxy LaunchDaemon.
///
/// 1. Unloads the service with `launchctl`
/// 2. Removes the plist file
/// 3. Removes the installed binary
pub fn uninstall() -> Result<()> {
    check_root()?;

    let plist_path = Path::new(PLIST_PATH);
    let bin_path = Path::new(INSTALL_BIN);

    if plist_path.exists() {
        println!("Unloading service...");
        // Ignore errors — service may already be unloaded
        let _ = Command::new("launchctl")
            .args(["unload", "-w", PLIST_PATH])
            .status();

        println!("Removing {PLIST_PATH}...");
        std::fs::remove_file(plist_path)
            .with_context(|| format!("Failed to remove {PLIST_PATH}"))?;
    } else {
        println!("No plist found at {PLIST_PATH}, skipping.");
    }

    if bin_path.exists() {
        println!("Removing {INSTALL_BIN}...");
        std::fs::remove_file(bin_path)
            .with_context(|| format!("Failed to remove {INSTALL_BIN}"))?;
    } else {
        println!("No binary found at {INSTALL_BIN}, skipping.");
    }

    let scripts_dir = Path::new(SCRIPTS_DIR);
    if scripts_dir.exists() {
        println!("Removing {SCRIPTS_DIR}/...");
        std::fs::remove_dir_all(scripts_dir)
            .with_context(|| format!("Failed to remove {SCRIPTS_DIR}"))?;
    }

    println!("Service uninstalled.");
    Ok(())
}

/// Build the launchd plist XML from the proxy arguments.
///
/// The generated plist runs trans_proxy in foreground mode (no `--daemon`)
/// since launchd manages the process lifecycle. Arguments like `--install`,
/// `--uninstall`, `--daemon`, `--pid-file`, and `--log-file` are filtered out.
///
/// No `UserName` is set — loop prevention uses `IP_BOUND_IF` (binding outbound
/// sockets to lo0) and destination-based pf exclusion instead of UID filtering.
fn generate_plist(_args: &[String]) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{WRAPPER_SCRIPT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_PATH}</string>
    <key>WorkingDirectory</key>
    <string>/</string>
</dict>
</plist>
"#
    )
}

/// Build a wrapper shell script that runs pf setup before trans_proxy
/// and tears down pf rules on exit.
fn generate_wrapper(args: &[String]) -> String {
    let filtered_args = filter_service_args(args);

    let exec_args = if filtered_args.is_empty() {
        INSTALL_BIN.to_string()
    } else {
        format!("{} {}", INSTALL_BIN, filtered_args.join(" "))
    };

    // Extract interface and port for pf setup
    let interface = extract_arg(&filtered_args, "--interface").unwrap_or("en0");
    let port = extract_arg(&filtered_args, "--listen-addr")
        .and_then(|addr| addr.rsplit(':').next())
        .unwrap_or("8443");

    let local_traffic = has_flag(&filtered_args, "--local-traffic");
    let upstream = extract_arg(&filtered_args, "--upstream-proxy")
        .map(|s| {
            s.strip_prefix("http://")
                .or(s.strip_prefix("socks5://"))
                .unwrap_or(s)
        })
        // Strip socks5 userinfo (user:pass@host:port -> host:port)
        .map(|s| s.rsplit('@').next().unwrap_or(s));
    let ports = extract_arg(&filtered_args, "--ports");

    let setup_cmd = match (local_traffic, ports) {
        (true, Some(p)) => {
            let upstream_arg = upstream.unwrap_or("\"\"");
            format!("{PF_SETUP_SCRIPT} {interface} {port} {upstream_arg} {p}")
        }
        (true, None) => {
            let upstream_arg = upstream.unwrap_or("\"\"");
            format!("{PF_SETUP_SCRIPT} {interface} {port} {upstream_arg}")
        }
        (false, Some(p)) => format!("{PF_SETUP_SCRIPT} {interface} {port} \"\" {p}"),
        (false, None) => format!("{PF_SETUP_SCRIPT} {interface} {port}"),
    };

    format!(
        r#"#!/bin/bash
# Auto-generated wrapper script for trans_proxy LaunchDaemon.
# Sets up pf rules before starting, tears down on exit.
set -euo pipefail

cleanup() {{
    {PF_TEARDOWN_SCRIPT}
}}
trap cleanup EXIT

{setup_cmd}

exec {exec_args}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_plist_basic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--dns".into(),
        ];
        let plist = generate_plist(&args);

        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains(PLIST_LABEL));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains(&format!("<string>{WRAPPER_SCRIPT}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        // Should NOT have UserName when local-traffic is not set
        assert!(!plist.contains("<key>UserName</key>"));
    }

    #[test]
    fn test_generate_plist_local_traffic_no_username() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--local-traffic".into(),
        ];
        let plist = generate_plist(&args);

        // No UserName — loop prevention uses IP_BOUND_IF + destination exclusion
        assert!(!plist.contains("<key>UserName</key>"));
        // Plist uses wrapper script, not individual args
        assert!(plist.contains(&format!("<string>{WRAPPER_SCRIPT}</string>")));
    }

    #[test]
    fn test_generate_plist_filters_service_flags() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--install".into(),
            "--daemon".into(),
        ];
        let plist = generate_plist(&args);

        assert!(!plist.contains("--install"));
        assert!(!plist.contains("--daemon"));
    }

    #[test]
    fn test_generate_wrapper_basic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--dns".into(),
            "--interface".into(),
            "en0".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains("#!/bin/bash"));
        assert!(wrapper.contains("trap cleanup EXIT"));
        assert!(wrapper.contains(&format!(
            "exec {INSTALL_BIN} --upstream-proxy 127.0.0.1:1082 --dns --interface en0"
        )));
        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en0 8443")));
        assert!(wrapper.contains(PF_TEARDOWN_SCRIPT));
    }

    #[test]
    fn test_generate_wrapper_custom_interface_and_port() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--interface".into(),
            "en1".into(),
            "--listen-addr".into(),
            "0.0.0.0:9999".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en1 9999")));
    }

    #[test]
    fn test_generate_wrapper_local_traffic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--local-traffic".into(),
            "--interface".into(),
            "en0".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en0 8443 127.0.0.1:1082")));
    }

    #[test]
    fn test_generate_wrapper_with_ports() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--ports".into(),
            "80,443".into(),
            "--interface".into(),
            "en0".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en0 8443 \"\" 80,443")));
    }

    #[test]
    fn test_generate_wrapper_with_ports_and_local_traffic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--ports".into(),
            "80,443".into(),
            "--local-traffic".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en0 8443 127.0.0.1:1082 80,443")));
    }

    #[test]
    fn test_generate_wrapper_no_args() {
        let args: Vec<String> = vec![];
        let wrapper = generate_wrapper(&args);

        assert!(wrapper.contains(&format!("exec {INSTALL_BIN}\n")));
        assert!(wrapper.contains(&format!("{PF_SETUP_SCRIPT} en0 8443\n")));
    }

    #[test]
    fn test_generate_wrapper_filters_service_flags() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--install".into(),
            "--daemon".into(),
            "--pid-file".into(),
            "/tmp/test.pid".into(),
        ];
        let wrapper = generate_wrapper(&args);

        assert!(!wrapper.contains("--install"));
        assert!(!wrapper.contains("--daemon"));
        assert!(!wrapper.contains("--pid-file"));
        assert!(wrapper.contains("--upstream-proxy"));
    }
}
