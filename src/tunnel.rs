//! HTTP CONNECT tunnel establishment and relay.
//!
//! Opens a TCP connection to the upstream proxy, performs an HTTP CONNECT
//! handshake to the original destination, and returns the connected stream
//! for bidirectional relay.
//!
//! # Timeouts
//!
//! All phases of the CONNECT handshake (connect, send, receive) are subject
//! to a 10-second timeout to prevent hung connections.
//!
//! # Hostname Support
//!
//! When a hostname is available (from SNI or DNS lookup), the CONNECT request
//! uses `CONNECT hostname:port` instead of `CONNECT ip:port`, allowing the
//! upstream proxy to perform its own DNS resolution and apply domain-based
//! access policies.

use anyhow::{bail, Context, Result};
use std::net::SocketAddrV4;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 8192;

/// Establish a CONNECT tunnel through the upstream proxy to the given destination.
/// Returns the connected TcpStream (with the CONNECT handshake completed).
/// `hostname`: if Some, use it in the CONNECT request instead of the raw IP.
pub async fn connect_via_proxy(
    proxy_addr: std::net::SocketAddr,
    dest: SocketAddrV4,
    hostname: Option<&str>,
) -> Result<TcpStream> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy_addr))
        .await
        .context("Timeout connecting to upstream proxy")?
        .context("Failed to connect to upstream proxy")?;

    // Send CONNECT request — prefer hostname over raw IP when available
    let host = match hostname {
        Some(h) => h.to_string(),
        None => dest.ip().to_string(),
    };
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host,
        dest.port(),
        host,
        dest.port()
    );

    timeout(CONNECT_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .context("Timeout sending CONNECT request")?
        .context("Failed to send CONNECT request")?;

    // Read response, looking for \r\n\r\n
    let mut buf = vec![0u8; MAX_RESPONSE_SIZE];
    let mut filled = 0;

    let response = timeout(CONNECT_TIMEOUT, async {
        loop {
            if filled >= MAX_RESPONSE_SIZE {
                bail!("CONNECT response too large");
            }
            let n = stream
                .read(&mut buf[filled..])
                .await
                .context("Failed to read CONNECT response")?;
            if n == 0 {
                bail!("Connection closed during CONNECT handshake");
            }
            filled += n;

            // Check for end of headers
            if let Some(pos) = find_header_end(&buf[..filled]) {
                // Parse status line
                let header_str = std::str::from_utf8(&buf[..pos])
                    .context("Invalid UTF-8 in CONNECT response")?;
                parse_connect_response(header_str)?;
                return Ok(());
            }
        }
    })
    .await
    .context("Timeout waiting for CONNECT response")?;

    response?;
    Ok(stream)
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn parse_connect_response(header: &str) -> Result<()> {
    let status_line = header.lines().next().context("Empty CONNECT response")?;
    // Expect "HTTP/1.x 200 ..."
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        bail!("Malformed CONNECT response: {}", status_line);
    }
    let code: u16 = parts[1].parse().context("Invalid status code")?;
    if code != 200 {
        bail!("CONNECT failed with status {}: {}", code, status_line);
    }
    Ok(())
}
