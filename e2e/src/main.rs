//! End-to-end test runner for trans_proxy.
//!
//! Must be run as root on Linux. Orchestrates:
//! 1. Starting test_servers (SOCKS5, HTTP CONNECT, HTTP destination)
//! 2. Starting trans_proxy with appropriate flags
//! 3. Setting up nftables redirect rules
//! 4. Making TCP connections through the proxy chain
//! 5. Tearing everything down
//!
//! Uses the --local-traffic + --fwmark code path (OUTPUT chain on loopback).

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const EXPECTED_BODY: &str = "trans_proxy_e2e_ok\n";
const FWMARK: u32 = 1;

#[derive(Deserialize)]
struct TestServerPorts {
    socks5_port: u16,
    http_connect_port: u16,
    http_dest_port: u16,
}

/// Guard that cleans up nftables rules on drop.
struct NftablesGuard {
    script_dir: PathBuf,
}

impl Drop for NftablesGuard {
    fn drop(&mut self) {
        let script = self.script_dir.join("nftables_teardown.sh");
        let _ = Command::new("bash").arg(&script).output();
    }
}

/// Guard that kills a child process on drop.
struct ProcessGuard {
    child: Child,
    name: String,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("  Stopped {}", self.name);
    }
}

fn find_project_root() -> PathBuf {
    // Look for Cargo.toml starting from the e2e binary's location
    let exe = std::env::current_exe().unwrap();
    // target/release/e2e -> go up to project root
    let mut dir = exe.parent().unwrap().to_path_buf();
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("scripts").exists() {
            return dir;
        }
        if !dir.pop() {
            // Fallback: current directory
            return std::env::current_dir().unwrap();
        }
    }
}

fn start_test_servers(root: &Path) -> Result<(ProcessGuard, TestServerPorts)> {
    let bin = root.join("target/release/test_servers");
    let mut child = Command::new(&bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start test_servers at {}", bin.display()))?;

    let stdout = child.stdout.take().context("no stdout")?;
    let reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut reader = reader;
    reader.read_line(&mut line)?;

    let ports: TestServerPorts =
        serde_json::from_str(line.trim()).context("failed to parse test_servers port JSON")?;

    eprintln!(
        "  test_servers: socks5={}, http_connect={}, http_dest={}",
        ports.socks5_port, ports.http_connect_port, ports.http_dest_port
    );

    let guard = ProcessGuard {
        child,
        name: "test_servers".into(),
    };
    Ok((guard, ports))
}

fn start_trans_proxy(
    root: &Path,
    listen_port: u16,
    upstream: &str,
    extra_args: &[&str],
) -> Result<ProcessGuard> {
    let bin = root.join("target/release/trans_proxy");
    let mut cmd = Command::new(&bin);
    cmd.arg("--listen-addr")
        .arg(format!("127.0.0.1:{listen_port}"))
        .arg("--upstream-proxy")
        .arg(upstream)
        .arg("--local-traffic")
        .arg("--fwmark")
        .arg(FWMARK.to_string())
        .arg("--log-level")
        .arg("debug");

    for arg in extra_args {
        cmd.arg(arg);
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to start trans_proxy at {}", bin.display()))?;

    let guard = ProcessGuard {
        child,
        name: "trans_proxy".into(),
    };
    Ok(guard)
}

fn setup_nftables(
    root: &Path,
    proxy_port: u16,
    upstream: &str,
    ports: &str,
) -> Result<NftablesGuard> {
    let script = root.join("scripts/nftables_setup.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("lo")
        .arg(proxy_port.to_string())
        .arg(FWMARK.to_string())
        .arg(upstream)
        .arg(ports)
        .output()
        .context("failed to run nftables_setup.sh")?;

    if !output.status.success() {
        bail!(
            "nftables_setup.sh failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(NftablesGuard {
        script_dir: root.join("scripts"),
    })
}

async fn wait_for_port(port: u16) -> Result<()> {
    timeout(STARTUP_TIMEOUT, async {
        loop {
            if TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .is_ok()
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context(format!("timeout waiting for port {port}"))?;
    Ok(())
}

async fn http_get(addr: SocketAddr) -> Result<String> {
    let mut stream = timeout(REQUEST_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("timeout connecting")?
        .context("failed to connect")?;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .context("timeout reading response")?
        .context("failed to read")?;

    let text = String::from_utf8(response)?;
    // Extract body after \r\n\r\n
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

// ===== DNS helpers =====

const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;

fn build_dns_query(domain: &str, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pkt
}

fn build_dns_response(domain: &str, ip: Ipv4Addr, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: response, recursion desired + available
    pkt.extend_from_slice(&[0x81, 0x80]);
    // QDCOUNT=1, ANCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // Question section
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    // Answer: pointer to name at offset 12
    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    // TTL = 60
    pkt.extend_from_slice(&60u32.to_be_bytes());
    // RDLENGTH = 4
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&ip.octets());
    pkt
}

// ===== Test cases =====

async fn test_socks5_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 1: SOCKS5 tunneling e2e ---");

    let proxy_port = 18443u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let _proxy = start_trans_proxy(root, proxy_port, &upstream, &[])?;
    wait_for_port(proxy_port).await?;

    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.socks5_port),
        &ports.http_dest_port.to_string(),
    )?;

    // Small delay for nftables rules to take effect
    sleep(Duration::from_millis(100)).await;

    let body = http_get(SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port))).await?;
    assert_eq!(body, EXPECTED_BODY, "SOCKS5 e2e: unexpected response body");

    eprintln!("  PASS");
    Ok(())
}

async fn test_http_connect_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 2: HTTP CONNECT tunneling e2e ---");

    let proxy_port = 18444u16;
    let upstream = format!("127.0.0.1:{}", ports.http_connect_port);

    let _proxy = start_trans_proxy(root, proxy_port, &upstream, &[])?;
    wait_for_port(proxy_port).await?;

    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.http_connect_port),
        &ports.http_dest_port.to_string(),
    )?;

    sleep(Duration::from_millis(100)).await;

    let body = http_get(SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port))).await?;
    assert_eq!(
        body, EXPECTED_BODY,
        "HTTP CONNECT e2e: unexpected response body"
    );

    eprintln!("  PASS");
    Ok(())
}

async fn test_dns_forwarding(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 3: DNS forwarding + IP-to-domain mapping ---");

    // Start a fake UDP DNS upstream
    let fake_dns = UdpSocket::bind("127.0.0.1:0").await?;
    let fake_dns_addr = fake_dns.local_addr()?;
    eprintln!("  fake DNS upstream on {fake_dns_addr}");

    let proxy_port = 18445u16;
    let dns_listen_port = 15353u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let _proxy = start_trans_proxy(
        root,
        proxy_port,
        &upstream,
        &[
            "--dns",
            "--dns-listen",
            &format!("127.0.0.1:{dns_listen_port}"),
            "--dns-upstream",
            &fake_dns_addr.to_string(),
        ],
    )?;
    wait_for_port(proxy_port).await?;

    // Give DNS forwarder time to bind
    sleep(Duration::from_millis(200)).await;

    // Send a DNS query for testhost.example.com
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let query = build_dns_query("testhost.example.com", 0xABCD);
    client
        .send_to(&query, format!("127.0.0.1:{dns_listen_port}"))
        .await?;

    // Fake upstream receives the forwarded query
    let mut buf = vec![0u8; 1500];
    let (n, from_addr) = timeout(Duration::from_secs(2), fake_dns.recv_from(&mut buf))
        .await
        .context("timeout waiting for DNS query at fake upstream")?
        .context("recv_from failed")?;

    assert!(n >= 12, "DNS query too short");
    eprintln!("  fake DNS upstream received query ({n} bytes)");

    // Capture the transaction ID from the forwarded query
    let forwarded_tx_id = u16::from_be_bytes([buf[0], buf[1]]);

    // Send a response mapping testhost.example.com -> 127.0.0.99
    let response_ip = Ipv4Addr::new(127, 0, 0, 99);
    let response = build_dns_response("testhost.example.com", response_ip, forwarded_tx_id);
    fake_dns.send_to(&response, from_addr).await?;

    // Client should receive the DNS response
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .context("timeout waiting for DNS response")?
        .context("recv_from failed")?;

    assert!(n >= 12, "DNS response too short");
    // Verify the tx_id was rewritten back to our original
    assert_eq!(buf[0], 0xAB);
    assert_eq!(buf[1], 0xCD);
    eprintln!("  DNS response received with correct tx_id");

    eprintln!("  PASS");
    Ok(())
}

async fn test_port_selective_redirect(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 4: Port-selective redirect ---");

    // We need a second http_dest instance on a different port.
    // Start a simple TCP server inline for the "unproxied" port.
    let unproxied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let unproxied_port = unproxied_listener.local_addr()?.port();

    // Serve the same response on the unproxied port
    tokio::spawn(async move {
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
    wait_for_port(proxy_port).await?;

    // Only redirect http_dest_port, NOT unproxied_port
    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.socks5_port),
        &ports.http_dest_port.to_string(),
    )?;

    sleep(Duration::from_millis(100)).await;

    // Connection to http_dest_port should go through the proxy
    let body1 = http_get(SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port))).await?;
    assert_eq!(
        body1, EXPECTED_BODY,
        "port-selective: proxied port should return e2e body"
    );

    // Connection to unproxied_port should go directly (not through proxy)
    let body2 = http_get(SocketAddr::from(([127, 0, 0, 1], unproxied_port))).await?;
    assert_eq!(
        body2, "direct_connection\n",
        "port-selective: unproxied port should connect directly"
    );

    eprintln!("  PASS");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check root
    if unsafe { libc::geteuid() } != 0 {
        bail!("E2E tests must be run as root (need nftables + SO_MARK)");
    }

    let root = find_project_root();
    eprintln!("Project root: {}", root.display());

    // Verify binaries exist
    let trans_proxy_bin = root.join("target/release/trans_proxy");
    let test_servers_bin = root.join("target/release/test_servers");
    if !trans_proxy_bin.exists() || !test_servers_bin.exists() {
        bail!(
            "Binaries not found. Run `cargo build --release --workspace` first.\n  Expected:\n    {}\n    {}",
            trans_proxy_bin.display(),
            test_servers_bin.display()
        );
    }

    eprintln!("Starting test servers...");
    let (_servers_guard, ports) = start_test_servers(&root)?;

    // Wait for test servers to be ready
    wait_for_port(ports.socks5_port).await?;
    wait_for_port(ports.http_connect_port).await?;
    wait_for_port(ports.http_dest_port).await?;

    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, result) in [
        (
            "SOCKS5 tunneling",
            test_socks5_tunneling(&root, &ports).await,
        ),
        (
            "HTTP CONNECT tunneling",
            test_http_connect_tunneling(&root, &ports).await,
        ),
        ("DNS forwarding", test_dns_forwarding(&root, &ports).await),
        (
            "Port-selective redirect",
            test_port_selective_redirect(&root, &ports).await,
        ),
    ] {
        match result {
            Ok(()) => passed += 1,
            Err(e) => {
                eprintln!("  FAIL: {name}: {e:#}");
                failed += 1;
            }
        }
    }

    eprintln!("\n=== Results: {passed} passed, {failed} failed ===");
    if failed > 0 {
        bail!("{failed} test(s) failed");
    }
    Ok(())
}
