//! End-to-end test runner for trans_proxy.
//!
//! Must be run as root/sudo. Dispatches to platform-specific tests:
//! - **Linux**: nftables OUTPUT chain on loopback with fwmark
//! - **macOS**: pf rdr on lo0 with a loopback alias IP (10.200.200.1)

mod common;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use anyhow::{bail, Result};

use common::*;

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("E2E tests must be run as root/sudo");
    }

    let root = find_project_root();
    eprintln!("Project root: {}", root.display());
    eprintln!("Platform: {}", std::env::consts::OS);

    let trans_proxy_bin = root.join("target/release/trans_proxy");
    let test_servers_bin = root.join("target/release/test_servers");
    if !trans_proxy_bin.exists() || !test_servers_bin.exists() {
        bail!(
            "Binaries not found. Run `cargo build --release --workspace` first.\n  Expected:\n    {}\n    {}",
            trans_proxy_bin.display(),
            test_servers_bin.display()
        );
    }

    // Platform-specific env vars for test_servers
    #[cfg(target_os = "linux")]
    let envs: Vec<(&str, &str)> = vec![("FWMARK", "1")];
    #[cfg(target_os = "macos")]
    let envs: Vec<(&str, &str)> = vec![("BIND_ADDR", "10.200.200.1")];

    eprintln!("Starting test servers...");

    // On macOS, ensure the lo0 alias exists before starting test_servers
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let _ = Command::new("sudo")
            .args([
                "ifconfig",
                "lo0",
                "alias",
                "10.200.200.1",
                "netmask",
                "255.255.255.255",
            ])
            .output();
    }

    let (_servers_guard, ports) = start_test_servers(&root, &envs)?;

    // Wait for test servers to be ready
    wait_for_port(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        ports.socks5_port,
    )))
    .await?;
    wait_for_port(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        ports.http_connect_port,
    )))
    .await?;

    // http_dest may be on a different IP (10.200.200.1 on macOS)
    let dest_ip: std::net::Ipv4Addr = ports.http_dest_addr.parse()?;
    wait_for_port(std::net::SocketAddr::from((dest_ip, ports.http_dest_port))).await?;

    #[cfg(target_os = "linux")]
    linux::run(&root, &ports).await?;

    #[cfg(target_os = "macos")]
    macos::run(&root, &ports).await?;

    Ok(())
}
