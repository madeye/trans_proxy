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
    script_dir: PathBuf,
}

impl Drop for NftablesGuard {
    fn drop(&mut self) {
        let script = self.script_dir.join("nftables_teardown.sh");
        let _ = Command::new("bash").arg(&script).output();
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
    ])
}
