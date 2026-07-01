//! LAN-client driver for the docker gateway e2e (see `docker/gateway-e2e.yml`).
//!
//! Runs inside the `client` container, whose traffic to the WAN server is
//! routed through a `gateway` container running trans_proxy. It drives real
//! forwarded traffic — the path the loopback e2e cannot reach — and asserts:
//!
//!   * TCP to the destination is transparently proxied (HTTP body matches).
//!   * UDP/QUIC to the destination is either relayed (SOCKS5 upstream, echo
//!     returns) or dropped (HTTP CONNECT upstream, no echo) per `EXPECT_UDP`.
//!
//! Configuration is via environment variables so the same binary serves both
//! scenarios:
//!   TCP_TARGET   ip:port of the WAN HTTP destination (through the gateway)
//!   UDP_TARGET   ip:port of the WAN UDP echo destination (through the gateway)
//!   EXPECT_UDP   "1" → require the echo (relayed); "0" → require no echo
//!   SCENARIO     free-text label for logs
//!
//! Exits non-zero on the first failed assertion.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

const EXPECTED_BODY: &str = "trans_proxy_e2e_ok\n";

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var {key}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let scenario = std::env::var("SCENARIO").unwrap_or_else(|_| "gateway".into());
    let tcp_target: SocketAddr = env("TCP_TARGET")?.parse().context("bad TCP_TARGET")?;
    let udp_target: SocketAddr = env("UDP_TARGET")?.parse().context("bad UDP_TARGET")?;
    let expect_udp = env("EXPECT_UDP")? == "1";

    eprintln!("=== Docker gateway e2e: {scenario} ===");
    eprintln!("  TCP target {tcp_target}, UDP target {udp_target}, expect_udp={expect_udp}");

    // The gateway sets up forwarding + firewall asynchronously; give the routed
    // TCP path time to come up before asserting.
    wait_for_tcp(tcp_target, Duration::from_secs(30))
        .await
        .context("gateway/destination never became reachable over TCP")?;

    test_tcp(tcp_target)
        .await
        .context("TCP proxy test failed")?;
    eprintln!("  [PASS] TCP transparently proxied through the gateway");

    test_udp(udp_target, expect_udp)
        .await
        .context("UDP relay test failed")?;
    if expect_udp {
        eprintln!("  [PASS] UDP/QUIC relayed through the gateway (echo returned)");
    } else {
        eprintln!("  [PASS] UDP/QUIC dropped by the gateway (no echo, as expected)");
    }

    eprintln!("=== {scenario}: ALL CHECKS PASSED ===");
    Ok(())
}

/// Retry a TCP connect until it succeeds or the deadline elapses.
async fn wait_for_tcp(addr: SocketAddr, within: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(()),
            _ if tokio::time::Instant::now() >= deadline => {
                bail!("timed out waiting for {addr}")
            }
            _ => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Issue an HTTP GET through the gateway and verify the known response body.
async fn test_tcp(addr: SocketAddr) -> Result<()> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .context("connect timeout")?
        .context("connect failed")?;

    let request = format!("GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .context("read timeout")?
        .context("read failed")?;

    let text = String::from_utf8_lossy(&response);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    if body != EXPECTED_BODY {
        bail!("unexpected HTTP body: {body:?} (full response: {text:?})");
    }
    Ok(())
}

/// Send a UDP probe through the gateway. When `expect_echo`, require the echo
/// back (proves the relay works); otherwise require silence (proves the drop).
async fn test_udp(addr: SocketAddr, expect_echo: bool) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let probe = b"trans_proxy_udp_probe";

    let mut buf = vec![0u8; 1500];
    // Retry a few times: QUIC-style traffic is lossy and the relay/session
    // setup may drop the very first datagram.
    let attempts = if expect_echo { 5 } else { 3 };
    for attempt in 1..=attempts {
        sock.send_to(probe, addr).await?;
        match timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if !expect_echo {
                    bail!("UDP echo returned but should have been dropped ({n} bytes)");
                }
                if &buf[..n] != probe {
                    bail!("UDP echo payload mismatch: {:?}", &buf[..n]);
                }
                return Ok(());
            }
            _ => {
                // No reply this round.
                if expect_echo {
                    eprintln!("  (udp attempt {attempt}/{attempts}: no echo yet, retrying)");
                    continue;
                }
                // Drop case: one silent round is enough proof per attempt; keep
                // probing to be sure nothing leaks late.
            }
        }
    }

    if expect_echo {
        bail!("no UDP echo after {attempts} attempts — relay did not work");
    }
    Ok(())
}
