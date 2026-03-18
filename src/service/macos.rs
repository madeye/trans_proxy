//! macOS launchd service installation and removal.
//!
//! Installs trans_proxy as a system-wide LaunchDaemon so it starts
//! automatically on boot. Requires root privileges.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

use super::{check_root, filter_service_args, run_cmd, set_executable};

const PLIST_LABEL: &str = "com.github.madeye.trans_proxy";
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.github.madeye.trans_proxy.plist";
const INSTALL_BIN: &str = "/usr/local/bin/trans_proxy";
const LOG_PATH: &str = "/var/log/trans_proxy.log";

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
    println!("  Label:  {PLIST_LABEL}");
    println!("  Binary: {INSTALL_BIN}");
    println!("  Plist:  {PLIST_PATH}");
    println!("  Log:    {LOG_PATH}");
    println!();
    println!("Manage with:");
    println!("  sudo launchctl stop  {PLIST_LABEL}");
    println!("  sudo launchctl start {PLIST_LABEL}");
    println!("  sudo trans_proxy --uninstall");

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

    println!("Service uninstalled.");
    Ok(())
}

/// Build the launchd plist XML from the proxy arguments.
///
/// The generated plist runs trans_proxy in foreground mode (no `--daemon`)
/// since launchd manages the process lifecycle. Arguments like `--install`,
/// `--uninstall`, `--daemon`, `--pid-file`, and `--log-file` are filtered out.
fn generate_plist(args: &[String]) -> String {
    let filtered_args = filter_service_args(args);

    let mut program_args = String::new();
    program_args.push_str("        <string>");
    program_args.push_str(INSTALL_BIN);
    program_args.push_str("</string>\n");
    for arg in &filtered_args {
        program_args.push_str("        <string>");
        program_args.push_str(&xml_escape(arg));
        program_args.push_str("</string>\n");
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{program_args}    </array>
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

/// Escape special XML characters in a string for plist values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
