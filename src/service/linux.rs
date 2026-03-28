//! Linux systemd service installation and removal.
//!
//! Installs trans_proxy as a systemd service so it starts automatically
//! on boot. Requires root privileges.

use anyhow::{Context, Result};
use std::path::Path;

use super::{check_root, extract_arg, filter_service_args, has_flag, run_cmd, set_executable};

const UNIT_PATH: &str = "/etc/systemd/system/trans_proxy.service";
const INSTALL_BIN: &str = "/usr/local/bin/trans_proxy";
const SCRIPTS_DIR: &str = "/usr/local/lib/trans_proxy";
const SETUP_SCRIPT: &str = "/usr/local/lib/trans_proxy/nftables_setup.sh";
const TEARDOWN_SCRIPT: &str = "/usr/local/lib/trans_proxy/nftables_teardown.sh";

const SETUP_SCRIPT_CONTENT: &str = include_str!("../../scripts/nftables_setup.sh");
const TEARDOWN_SCRIPT_CONTENT: &str = include_str!("../../scripts/nftables_teardown.sh");

/// Install trans_proxy as a systemd service.
///
/// 1. Copies the running binary to `/usr/local/bin/trans_proxy`
/// 2. Generates a systemd unit file from the provided proxy arguments
/// 3. Writes the unit to `/etc/systemd/system/`
/// 4. Reloads systemd and enables/starts the service
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

    // Install nftables scripts
    println!("Installing nftables scripts to {SCRIPTS_DIR}/...");
    std::fs::create_dir_all(SCRIPTS_DIR)
        .with_context(|| format!("Failed to create {SCRIPTS_DIR}"))?;
    std::fs::write(SETUP_SCRIPT, SETUP_SCRIPT_CONTENT)
        .with_context(|| format!("Failed to write {SETUP_SCRIPT}"))?;
    std::fs::write(TEARDOWN_SCRIPT, TEARDOWN_SCRIPT_CONTENT)
        .with_context(|| format!("Failed to write {TEARDOWN_SCRIPT}"))?;
    set_executable(SETUP_SCRIPT)?;
    set_executable(TEARDOWN_SCRIPT)?;

    // Generate and write the unit file
    let unit = generate_unit(args);
    println!("Writing systemd unit to {UNIT_PATH}...");
    std::fs::write(UNIT_PATH, &unit)
        .with_context(|| format!("Failed to write unit file to {UNIT_PATH}"))?;

    // Reload systemd and enable/start the service
    println!("Enabling and starting service...");
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", "--now", "trans_proxy"])?;

    println!("Service installed and started successfully.");
    println!("  Binary:  {INSTALL_BIN}");
    println!("  Scripts: {SCRIPTS_DIR}/");
    println!("  Unit:    {UNIT_PATH}");
    println!();
    println!("Manage with:");
    println!("  sudo systemctl stop    trans_proxy");
    println!("  sudo systemctl start   trans_proxy");
    println!("  sudo systemctl status  trans_proxy");
    println!("  journalctl -u trans_proxy -f");
    println!("  sudo trans_proxy --uninstall");

    Ok(())
}

/// Start the installed trans_proxy systemd service.
pub fn start() -> Result<()> {
    check_root()?;

    if !Path::new(UNIT_PATH).exists() {
        anyhow::bail!(
            "Service is not installed (no unit at {UNIT_PATH}). Run with --install first."
        );
    }

    println!("Starting service...");
    run_cmd("systemctl", &["start", "trans_proxy"])?;
    println!("Service started.");
    Ok(())
}

/// Stop the installed trans_proxy systemd service.
pub fn stop() -> Result<()> {
    check_root()?;

    if !Path::new(UNIT_PATH).exists() {
        anyhow::bail!(
            "Service is not installed (no unit at {UNIT_PATH}). Run with --install first."
        );
    }

    println!("Stopping service...");
    run_cmd("systemctl", &["stop", "trans_proxy"])?;
    println!("Service stopped.");
    Ok(())
}

/// Uninstall the trans_proxy systemd service.
///
/// 1. Stops and disables the service
/// 2. Removes the unit file and binary
/// 3. Reloads systemd
pub fn uninstall() -> Result<()> {
    check_root()?;

    let unit_path = Path::new(UNIT_PATH);
    let bin_path = Path::new(INSTALL_BIN);

    if unit_path.exists() {
        println!("Stopping and disabling service...");
        // Ignore errors — service may already be stopped/disabled
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "--now", "trans_proxy"])
            .status();

        println!("Removing {UNIT_PATH}...");
        std::fs::remove_file(unit_path).with_context(|| format!("Failed to remove {UNIT_PATH}"))?;
    } else {
        println!("No unit file found at {UNIT_PATH}, skipping.");
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

    // Reload systemd
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    println!("Service uninstalled.");
    Ok(())
}

/// Build the systemd unit file from the proxy arguments.
///
/// The generated unit runs trans_proxy in foreground mode (no `--daemon`)
/// since systemd manages the process lifecycle. Arguments like `--install`,
/// `--uninstall`, `--daemon`, `--pid-file`, and `--log-file` are filtered out.
///
/// Includes `ExecStartPre` and `ExecStopPost` to set up and tear down
/// nftables NAT redirect rules automatically.
fn generate_unit(args: &[String]) -> String {
    let filtered_args = filter_service_args(args);

    let exec_start = if filtered_args.is_empty() {
        INSTALL_BIN.to_string()
    } else {
        format!("{} {}", INSTALL_BIN, filtered_args.join(" "))
    };

    // Extract interface and port for nftables setup
    let interface = extract_arg(&filtered_args, "--interface").unwrap_or("eth0");
    let port = extract_arg(&filtered_args, "--listen-addr")
        .and_then(|addr| addr.rsplit(':').next())
        .unwrap_or("8443");

    let local_traffic = has_flag(&filtered_args, "--local-traffic");
    let fwmark = extract_arg(&filtered_args, "--fwmark").unwrap_or("1");
    let upstream = extract_arg(&filtered_args, "--upstream-proxy")
        .map(|s| s.strip_prefix("http://").or(s.strip_prefix("socks5://")).unwrap_or(s))
        // Strip socks5 userinfo (user:pass@host:port -> host:port)
        .map(|s| s.rsplit('@').next().unwrap_or(s));
    let ports = extract_arg(&filtered_args, "--ports");

    let fwmark_arg = if local_traffic { fwmark } else { "\"\"" };
    let upstream_arg = if local_traffic {
        upstream.unwrap_or("\"\"")
    } else {
        "\"\""
    };
    let setup_cmd = match ports {
        Some(p) => format!("{SETUP_SCRIPT} {interface} {port} {fwmark_arg} {upstream_arg} {p}"),
        None => format!("{SETUP_SCRIPT} {interface} {port} {fwmark_arg} {upstream_arg}"),
    };

    format!(
        r#"[Unit]
Description=Transparent proxy with upstream HTTP CONNECT and SOCKS5 support
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre={setup_cmd}
ExecStart={exec_start}
ExecStopPost={TEARDOWN_SCRIPT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_unit_basic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--dns".into(),
            "--interface".into(),
            "eth0".into(),
        ];
        let unit = generate_unit(&args);

        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("Type=simple"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("StandardOutput=journal"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("CAP_NET_ADMIN"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/trans_proxy --upstream-proxy 127.0.0.1:1082 --dns --interface eth0"
        ));
        assert!(
            unit.contains("ExecStartPre=/usr/local/lib/trans_proxy/nftables_setup.sh eth0 8443")
        );
        assert!(unit.contains("ExecStopPost=/usr/local/lib/trans_proxy/nftables_teardown.sh"));
        // No User= line when local-traffic is not set
        assert!(!unit.contains("User="));
    }

    #[test]
    fn test_generate_unit_no_args() {
        let args: Vec<String> = vec![];
        let unit = generate_unit(&args);

        assert!(unit.contains("ExecStart=/usr/local/bin/trans_proxy\n"));
        // Should not have trailing space
        assert!(!unit.contains("ExecStart=/usr/local/bin/trans_proxy "));
        // Defaults: eth0 interface, 8443 port
        assert!(
            unit.contains("ExecStartPre=/usr/local/lib/trans_proxy/nftables_setup.sh eth0 8443")
        );
    }

    #[test]
    fn test_generate_unit_custom_interface_and_port() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--interface".into(),
            "wlan0".into(),
            "--listen-addr".into(),
            "0.0.0.0:9999".into(),
        ];
        let unit = generate_unit(&args);

        assert!(
            unit.contains("ExecStartPre=/usr/local/lib/trans_proxy/nftables_setup.sh wlan0 9999")
        );
        assert!(unit.contains("ExecStopPost=/usr/local/lib/trans_proxy/nftables_teardown.sh"));
    }

    #[test]
    fn test_generate_unit_filters_service_flags() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--install".into(),
            "--daemon".into(),
            "--pid-file".into(),
            "/tmp/test.pid".into(),
            "--log-file".into(),
            "/tmp/test.log".into(),
            "--dns".into(),
        ];
        let unit = generate_unit(&args);

        // Filtered flags should not appear
        assert!(!unit.contains("--install"));
        assert!(!unit.contains("--daemon"));
        assert!(!unit.contains("--pid-file"));
        assert!(!unit.contains("--log-file"));
        assert!(!unit.contains("/tmp/test.pid"));
        assert!(!unit.contains("/tmp/test.log"));

        // Proxy args should remain
        assert!(unit.contains("--upstream-proxy"));
        assert!(unit.contains("127.0.0.1:1082"));
        assert!(unit.contains("--dns"));
    }

    #[test]
    fn test_generate_unit_network_ordering() {
        let unit = generate_unit(&[]);

        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
    }

    #[test]
    fn test_generate_unit_local_traffic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--local-traffic".into(),
            "--fwmark".into(),
            "42".into(),
            "--interface".into(),
            "eth0".into(),
        ];
        let unit = generate_unit(&args);

        // No User= directive — fwmark-based filtering, no dedicated user needed
        assert!(!unit.contains("User="));
        // Setup script should have fwmark and upstream proxy address
        assert!(unit.contains(
            "ExecStartPre=/usr/local/lib/trans_proxy/nftables_setup.sh eth0 8443 42 127.0.0.1:1082"
        ));
    }

    #[test]
    fn test_generate_unit_local_traffic_default_fwmark() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--local-traffic".into(),
        ];
        let unit = generate_unit(&args);

        // No User= directive
        assert!(!unit.contains("User="));
        // Default fwmark=1, upstream proxy extracted
        assert!(unit.contains("nftables_setup.sh eth0 8443 1 127.0.0.1:1082"));
    }

    #[test]
    fn test_generate_unit_without_local_traffic() {
        let args: Vec<String> = vec!["--upstream-proxy".into(), "127.0.0.1:1082".into()];
        let unit = generate_unit(&args);

        assert!(!unit.contains("User="));
        // No fwmark or upstream args when local-traffic is not set
        assert!(unit.contains("nftables_setup.sh eth0 8443 \"\" \"\"\n"));
    }

    #[test]
    fn test_generate_unit_with_ports() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--ports".into(),
            "22,80,443".into(),
            "--interface".into(),
            "eth0".into(),
        ];
        let unit = generate_unit(&args);

        assert!(unit.contains("nftables_setup.sh eth0 8443 \"\" \"\" 22,80,443"));
    }

    #[test]
    fn test_generate_unit_with_ports_and_local_traffic() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--ports".into(),
            "22,80,443".into(),
            "--local-traffic".into(),
            "--fwmark".into(),
            "5".into(),
        ];
        let unit = generate_unit(&args);

        assert!(unit.contains("nftables_setup.sh eth0 8443 5 127.0.0.1:1082 22,80,443"));
    }

    #[test]
    fn test_generate_unit_without_ports_all_tcp() {
        let args: Vec<String> = vec!["--upstream-proxy".into(), "127.0.0.1:1082".into()];
        let unit = generate_unit(&args);

        // Without ports, no 5th argument — script defaults to all TCP
        assert!(unit.contains("nftables_setup.sh eth0 8443 \"\" \"\"\n"));
    }

    #[test]
    fn test_generate_unit_local_traffic_without_ports() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "127.0.0.1:1082".into(),
            "--local-traffic".into(),
        ];
        let unit = generate_unit(&args);

        // local-traffic + no ports: fwmark + upstream, no trailing port list
        assert!(unit.contains("nftables_setup.sh eth0 8443 1 127.0.0.1:1082\n"));
    }

    #[test]
    fn test_generate_unit_local_traffic_socks5_upstream() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "socks5://127.0.0.1:1080".into(),
            "--local-traffic".into(),
        ];
        let unit = generate_unit(&args);

        // socks5:// prefix should be stripped, leaving just the address
        assert!(unit.contains("nftables_setup.sh eth0 8443 1 127.0.0.1:1080\n"));
    }

    #[test]
    fn test_generate_unit_local_traffic_socks5_auth_upstream() {
        let args: Vec<String> = vec![
            "--upstream-proxy".into(),
            "socks5://user:pass@10.0.0.1:1080".into(),
            "--local-traffic".into(),
        ];
        let unit = generate_unit(&args);

        // socks5:// prefix and user:pass@ should be stripped
        assert!(unit.contains("nftables_setup.sh eth0 8443 1 10.0.0.1:1080\n"));
    }
}
