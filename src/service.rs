//! macOS launchd service installation and removal.
//!
//! Installs trans_proxy as a system-wide LaunchDaemon so it starts
//! automatically on boot. Requires root privileges.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

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
    let current_exe = std::env::current_exe()
        .context("Failed to determine current executable path")?;

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

/// Filter out service/daemon-related arguments that shouldn't appear in the plist.
/// Launchd manages the process lifecycle, so `--daemon`, `--pid-file`, `--log-file`,
/// `--install`, and `--uninstall` are not needed.
fn filter_service_args(args: &[String]) -> Vec<String> {
    let skip_flags = ["--install", "--uninstall", "--daemon", "-d"];
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

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn check_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("This command must be run as root (use sudo)");
    }
    Ok(())
}

fn set_executable(path: &str) -> Result<()> {
    run_cmd("chmod", &["755", path])
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {cmd}"))?;
    if !status.success() {
        bail!("{cmd} failed (exit code: {:?})", status.code());
    }
    Ok(())
}

