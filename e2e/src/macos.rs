//! macOS e2e tests using pf (packet filter).
//!
//! Uses a loopback alias IP (10.200.200.1 on lo0) with source-based pf
//! filtering to avoid redirect loops on a single machine:
//!
//! - http_dest binds to 10.200.200.1 (the alias)
//! - pf `rdr` only matches traffic FROM 10.200.200.1, so the test SOCKS5
//!   server's outbound connections (from 127.0.0.1) bypass the rdr rule
//! - The e2e test binds its source to 10.200.200.1 before connecting
//!
//! This exercises the real DIOCNATLOOK code path on macOS.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::common::*;

/// The alias IP added to lo0 for testing.
const TEST_IP: [u8; 4] = [10, 200, 200, 1];
const TEST_IP_STR: &str = "10.200.200.1";
const PF_ANCHOR: &str = "trans_proxy_e2e";

/// Guard that tears down pf anchor and removes lo0 alias on drop.
struct PfGuard;

impl Drop for PfGuard {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["pfctl", "-a", PF_ANCHOR, "-F", "all"])
            .output();
        let _ = Command::new("sudo")
            .args(["ifconfig", "lo0", "-alias", TEST_IP_STR])
            .output();
        eprintln!("  Cleaned up pf anchor and lo0 alias");
    }
}

fn setup_lo0_alias() -> Result<()> {
    let output = Command::new("sudo")
        .args([
            "ifconfig",
            "lo0",
            "alias",
            TEST_IP_STR,
            "netmask",
            "255.255.255.255",
        ])
        .output()
        .context("failed to add lo0 alias")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Already exists is OK
        if !stderr.contains("File exists") {
            bail!("ifconfig lo0 alias failed: {stderr}");
        }
    }
    Ok(())
}

fn setup_pf(proxy_port: u16, dest_port: u16) -> Result<PfGuard> {
    setup_lo0_alias()?;

    // Build pf rules:
    // - Only redirect traffic FROM 10.200.200.1 to 10.200.200.1 (test traffic)
    // - Traffic from 127.0.0.1 (socks5 server outbound) is not matched
    let rules = format!(
        "rdr on lo0 proto tcp from {TEST_IP_STR} to {TEST_IP_STR} port {dest_port} -> 127.0.0.1 port {proxy_port}\n"
    );

    // Load anchor reference into pf if not present
    let check = Command::new("sudo")
        .args(["pfctl", "-s", "rules"])
        .output()?;
    let existing = String::from_utf8_lossy(&check.stdout);
    if !existing.contains(&format!("anchor \"{PF_ANCHOR}\"")) {
        // Load the main pf.conf first, then add our anchor
        let _ = Command::new("sudo")
            .args(["pfctl", "-f", "/etc/pf.conf"])
            .output();
    }

    // Load rules into the anchor
    let mut child = Command::new("sudo")
        .args(["pfctl", "-a", PF_ANCHOR, "-f", "/dev/stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start pfctl")?;

    use std::io::Write;
    child.stdin.take().unwrap().write_all(rules.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "pfctl anchor load failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Enable pf
    let _ = Command::new("sudo").args(["pfctl", "-e"]).output();

    // We also need the anchor to be referenced from the main ruleset.
    // Add rdr-anchor + anchor if not already present.
    let mut child = Command::new("sudo")
        .args(["pfctl", "-f", "/dev/stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start pfctl for anchor ref")?;

    // Read existing pf.conf and append our anchor references
    let pf_conf = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
    let mut full_conf = pf_conf.clone();
    if !full_conf.contains(&format!("rdr-anchor \"{PF_ANCHOR}\"")) {
        full_conf.push_str(&format!("\nrdr-anchor \"{PF_ANCHOR}\"\n"));
    }
    if !full_conf.contains(&format!("anchor \"{PF_ANCHOR}\"")) {
        full_conf.push_str(&format!("anchor \"{PF_ANCHOR}\"\n"));
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(full_conf.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        // Non-fatal: the anchor rules are loaded, just the reference may be missing
        eprintln!(
            "  Warning: pfctl main config reload: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    eprintln!(
        "  pf anchor '{PF_ANCHOR}' loaded: rdr {TEST_IP_STR}:{dest_port} -> 127.0.0.1:{proxy_port}"
    );
    Ok(PfGuard)
}

fn test_bind_addr() -> SocketAddr {
    SocketAddr::from((TEST_IP, 0))
}

fn dest_addr(port: u16) -> SocketAddr {
    SocketAddr::from((TEST_IP, port))
}

async fn test_socks5_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 1: SOCKS5 tunneling e2e (macOS/pf) ---");

    let proxy_port = 18443u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let _proxy = start_trans_proxy(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let _pf = setup_pf(proxy_port, ports.http_dest_port)?;
    sleep(Duration::from_millis(200)).await;

    let body = http_get(dest_addr(ports.http_dest_port), Some(test_bind_addr())).await?;
    assert_eq!(body, EXPECTED_BODY, "SOCKS5 e2e: unexpected response body");

    eprintln!("  PASS");
    Ok(())
}

async fn test_http_connect_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 2: HTTP CONNECT tunneling e2e (macOS/pf) ---");

    let proxy_port = 18444u16;
    let upstream = format!("127.0.0.1:{}", ports.http_connect_port);

    let _proxy = start_trans_proxy(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let _pf = setup_pf(proxy_port, ports.http_dest_port)?;
    sleep(Duration::from_millis(200)).await;

    let body = http_get(dest_addr(ports.http_dest_port), Some(test_bind_addr())).await?;
    assert_eq!(
        body, EXPECTED_BODY,
        "HTTP CONNECT e2e: unexpected response body"
    );

    eprintln!("  PASS");
    Ok(())
}

async fn test_dns_forwarding(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 3: DNS forwarding (macOS) ---");

    let fake_dns = UdpSocket::bind("127.0.0.1:0").await?;
    let fake_dns_addr = fake_dns.local_addr()?;
    eprintln!("  fake DNS upstream on {fake_dns_addr}");

    let proxy_port = 18445u16;
    let dns_listen_port = 15353u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let dns_listen = format!("127.0.0.1:{dns_listen_port}");
    let dns_upstream = fake_dns_addr.to_string();
    let _proxy = start_trans_proxy(
        root,
        proxy_port,
        &upstream,
        &[
            "--dns",
            "--dns-listen",
            &dns_listen,
            "--dns-upstream",
            &dns_upstream,
        ],
    )?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;
    sleep(Duration::from_millis(200)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let query = build_dns_query("testhost.example.com", 0xABCD);
    client
        .send_to(&query, format!("127.0.0.1:{dns_listen_port}"))
        .await?;

    let mut buf = vec![0u8; 1500];
    let (n, from_addr) = timeout(Duration::from_secs(2), fake_dns.recv_from(&mut buf))
        .await
        .context("timeout waiting for DNS query at fake upstream")?
        .context("recv_from failed")?;

    assert!(n >= 12, "DNS query too short");
    eprintln!("  fake DNS upstream received query ({n} bytes)");

    let forwarded_tx_id = u16::from_be_bytes([buf[0], buf[1]]);
    let response_ip = Ipv4Addr::new(127, 0, 0, 99);
    let response = build_dns_response("testhost.example.com", response_ip, forwarded_tx_id);
    fake_dns.send_to(&response, from_addr).await?;

    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .context("timeout waiting for DNS response")?
        .context("recv_from failed")?;

    assert!(n >= 12, "DNS response too short");
    assert_eq!(buf[0], 0xAB);
    assert_eq!(buf[1], 0xCD);
    eprintln!("  DNS response received with correct tx_id");

    eprintln!("  PASS");
    Ok(())
}

async fn test_port_selective_redirect(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 4: Port-selective redirect (macOS/pf) ---");

    let unproxied_listener = tokio::net::TcpListener::bind(format!("{TEST_IP_STR}:0")).await?;
    let unproxied_port = unproxied_listener.local_addr()?.port();

    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            if let Ok((mut stream, _)) = unproxied_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let mut filled = 0;
                    loop {
                        let n = stream.read(&mut buf[filled..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        filled += n;
                        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let body = "direct_connection\n";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    });

    let proxy_port = 18446u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let _proxy = start_trans_proxy(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    // Only redirect http_dest_port, not unproxied_port
    let _pf = setup_pf(proxy_port, ports.http_dest_port)?;
    sleep(Duration::from_millis(200)).await;

    // Proxied port
    let body1 = http_get(dest_addr(ports.http_dest_port), Some(test_bind_addr())).await?;
    assert_eq!(
        body1, EXPECTED_BODY,
        "port-selective: proxied port should return e2e body"
    );

    // Unproxied port — pf rule only matches http_dest_port, so this goes direct
    let body2 = http_get(dest_addr(unproxied_port), Some(test_bind_addr())).await?;
    assert_eq!(
        body2, "direct_connection\n",
        "port-selective: unproxied port should connect directly"
    );

    eprintln!("  PASS");
    Ok(())
}

pub async fn run(root: &Path, ports: &TestServerPorts) -> Result<()> {
    // Ensure lo0 alias is set up before any tests
    setup_lo0_alias()?;
    eprintln!("  lo0 alias {TEST_IP_STR} configured");

    report_results(vec![
        ("SOCKS5 tunneling", test_socks5_tunneling(root, ports).await),
        (
            "HTTP CONNECT tunneling",
            test_http_connect_tunneling(root, ports).await,
        ),
        ("DNS forwarding", test_dns_forwarding(root, ports).await),
        (
            "Port-selective redirect",
            test_port_selective_redirect(root, ports).await,
        ),
    ])
}
