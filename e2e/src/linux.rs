//! Linux e2e tests using nftables OUTPUT chain on loopback.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::common::*;

const FWMARK: u32 = 1;

/// Guard that cleans up nftables rules on drop.
struct NftablesGuard {
    bin: PathBuf,
}

impl Drop for NftablesGuard {
    fn drop(&mut self) {
        let _ = Command::new(&self.bin)
            .args(["--teardown-firewall", "--upstream-proxy", "127.0.0.1:1"])
            .output();
    }
}

fn start_trans_proxy_linux(
    root: &Path,
    listen_port: u16,
    upstream: &str,
    extra_args: &[&str],
) -> Result<ProcessGuard> {
    let mut args: Vec<&str> = vec!["--fwmark", &"1"];
    args.extend_from_slice(extra_args);
    start_trans_proxy(root, listen_port, upstream, &args)
}

fn setup_nftables(
    root: &Path,
    proxy_port: u16,
    upstream: &str,
    ports: &str,
) -> Result<NftablesGuard> {
    let bin = root.join("target/release/trans_proxy");
    let output = Command::new(&bin)
        .args([
            "--setup-firewall",
            "--interface",
            "lo",
            "--listen-addr",
            &format!("127.0.0.1:{proxy_port}"),
            "--local-traffic",
            "--fwmark",
            &FWMARK.to_string(),
            "--upstream-proxy",
            upstream,
            "--ports",
            ports,
        ])
        .output()
        .context("failed to run trans_proxy --setup-firewall")?;

    if !output.status.success() {
        bail!(
            "trans_proxy --setup-firewall failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(NftablesGuard { bin })
}

async fn test_socks5_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 1: SOCKS5 tunneling e2e ---");

    let proxy_port = 18443u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let _proxy = start_trans_proxy_linux(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.socks5_port),
        &ports.http_dest_port.to_string(),
    )?;

    sleep(Duration::from_millis(100)).await;

    let body = http_get(
        SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port)),
        None,
    )
    .await?;
    assert_eq!(body, EXPECTED_BODY, "SOCKS5 e2e: unexpected response body");

    eprintln!("  PASS");
    Ok(())
}

async fn test_http_connect_tunneling(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 2: HTTP CONNECT tunneling e2e ---");

    let proxy_port = 18444u16;
    let upstream = format!("127.0.0.1:{}", ports.http_connect_port);

    let _proxy = start_trans_proxy_linux(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.http_connect_port),
        &ports.http_dest_port.to_string(),
    )?;

    sleep(Duration::from_millis(100)).await;

    let body = http_get(
        SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port)),
        None,
    )
    .await?;
    assert_eq!(
        body, EXPECTED_BODY,
        "HTTP CONNECT e2e: unexpected response body"
    );

    eprintln!("  PASS");
    Ok(())
}

async fn test_dns_forwarding(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 3: DNS forwarding + IP-to-domain mapping ---");

    let fake_dns = UdpSocket::bind("127.0.0.1:0").await?;
    let fake_dns_addr = fake_dns.local_addr()?;
    eprintln!("  fake DNS upstream on {fake_dns_addr}");

    let proxy_port = 18445u16;
    let dns_listen_port = 15353u16;
    let upstream = format!("socks5://127.0.0.1:{}", ports.socks5_port);

    let dns_listen = format!("127.0.0.1:{dns_listen_port}");
    let dns_upstream = fake_dns_addr.to_string();
    let _proxy = start_trans_proxy_linux(
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
    eprintln!("\n--- Test 4: Port-selective redirect ---");

    let unproxied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let unproxied_port = unproxied_listener.local_addr()?.port();

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

    let _proxy = start_trans_proxy_linux(root, proxy_port, &upstream, &[])?;
    wait_for_port(SocketAddr::from(([127, 0, 0, 1], proxy_port))).await?;

    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.socks5_port),
        &ports.http_dest_port.to_string(),
    )?;

    sleep(Duration::from_millis(100)).await;

    let body1 = http_get(
        SocketAddr::from(([127, 0, 0, 1], ports.http_dest_port)),
        None,
    )
    .await?;
    assert_eq!(
        body1, EXPECTED_BODY,
        "port-selective: proxied port should return e2e body"
    );

    let body2 = http_get(SocketAddr::from(([127, 0, 0, 1], unproxied_port)), None).await?;
    assert_eq!(
        body2, "direct_connection\n",
        "port-selective: unproxied port should connect directly"
    );

    eprintln!("  PASS");
    Ok(())
}

async fn test_quic_blocked(root: &Path, ports: &TestServerPorts) -> Result<()> {
    eprintln!("\n--- Test 5: QUIC / HTTP-3 (UDP) is dropped, not bypassed ---");

    // With an HTTP CONNECT upstream (which cannot carry UDP), QUIC on UDP 443
    // must be dropped to prevent it from bypassing the TCP-only proxy. e2e runs
    // as root, so 127.0.0.1:443 is bindable; a control server on an ephemeral
    // port proves the drop is targeted (only QUIC ports), not a blanket UDP
    // block. (The SOCKS5 upstream instead TPROXY-redirects UDP 443 — that path
    // needs a real forwarding/ingress setup and is covered separately.)
    let quic_server = UdpSocket::bind("127.0.0.1:443")
        .await
        .context("bind UDP 127.0.0.1:443 (e2e must run as root)")?;
    let control_server = UdpSocket::bind("127.0.0.1:0").await?;
    let control_port = control_server.local_addr()?.port();

    let proxy_port = 18447u16;

    // Proxy TCP 443 → quic_block_ports mirrors it, dropping UDP 443.
    let _nft = setup_nftables(
        root,
        proxy_port,
        &format!("127.0.0.1:{}", ports.http_connect_port),
        "443",
    )?;

    sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let mut buf = vec![0u8; 64];

    // Control: UDP to a non-QUIC port must still be delivered.
    client
        .send_to(b"ping", format!("127.0.0.1:{control_port}"))
        .await?;
    timeout(Duration::from_secs(1), control_server.recv_from(&mut buf))
        .await
        .context("control UDP packet should be delivered, but timed out")?
        .context("control recv_from failed")?;
    eprintln!("  control UDP delivered (drop is targeted, not blanket)");

    // QUIC: UDP to 443 must be dropped — it must never reach the server.
    client.send_to(b"quic", "127.0.0.1:443").await?;
    let leaked = timeout(Duration::from_millis(500), quic_server.recv_from(&mut buf)).await;
    if leaked.is_ok() {
        bail!("UDP 443 reached the server: QUIC/HTTP-3 bypassed the proxy");
    }
    eprintln!("  UDP 443 dropped");

    eprintln!("  PASS");
    Ok(())
}

pub async fn run(root: &Path, ports: &TestServerPorts) -> Result<()> {
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
        ("QUIC blocked", test_quic_blocked(root, ports).await),
    ])
}
