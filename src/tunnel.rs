//! Upstream proxy tunnel establishment and relay.
//!
//! Opens a TCP connection to the upstream proxy and performs either an
//! HTTP CONNECT or SOCKS5 handshake to the original destination, returning
//! the connected stream for bidirectional relay.
//!
//! # Timeouts
//!
//! All phases of the handshake (connect, send, receive) are subject
//! to a 10-second timeout to prevent hung connections.
//!
//! # Hostname Support
//!
//! When a hostname is available (from SNI or DNS lookup), the request
//! uses the hostname instead of the raw IP, allowing the upstream proxy
//! to perform its own DNS resolution and apply domain-based access policies.

use anyhow::{bail, Context, Result};
use std::net::SocketAddrV4;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::config::{ProxyAuth, ProxyProtocol, UpstreamProxy};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 8192;

/// Establish a tunnel through the upstream proxy to the given destination.
///
/// Connects to `proxy.addr`, then performs either an HTTP CONNECT or SOCKS5
/// handshake depending on [`proxy.protocol`](crate::config::ProxyProtocol).
/// Returns the connected [`TcpStream`] with the handshake completed and
/// all protocol framing consumed — ready for bidirectional relay.
///
/// When `hostname` is `Some`, it is sent in the CONNECT/SOCKS5 request
/// (as a domain name) instead of the raw destination IP, allowing the
/// upstream proxy to perform its own DNS resolution.
///
/// When `local_traffic` is enabled, platform-specific socket options are set
/// to prevent the proxy's own traffic from being intercepted:
/// - **Linux**: Sets `SO_MARK` (`fwmark`) so nftables can skip marked packets.
/// - **macOS**: Sets `IP_BOUND_IF` to bind to `lo0` when the upstream proxy is
///   on localhost, so packets never hit the `pass out on <iface>` pf rule.
pub async fn connect_via_proxy(
    proxy: &UpstreamProxy,
    dest: SocketAddrV4,
    hostname: Option<&str>,
    #[cfg(target_os = "linux")] fwmark: Option<u32>,
    #[cfg(target_os = "macos")] local_traffic: bool,
) -> Result<TcpStream> {
    let mut stream = timeout(CONNECT_TIMEOUT, async {
        let socket = if proxy.addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

        #[cfg(target_os = "linux")]
        if let Some(mark) = fwmark {
            set_fwmark(&socket, mark)?;
        }

        #[cfg(target_os = "macos")]
        if local_traffic && proxy.addr.ip().is_loopback() {
            bind_to_loopback(&socket)?;
        }

        socket.connect(proxy.addr).await
    })
    .await
    .context("Timeout connecting to upstream proxy")?
    .context("Failed to connect to upstream proxy")?;

    match &proxy.protocol {
        ProxyProtocol::HttpConnect => {
            handshake_http_connect(&mut stream, dest, hostname).await?;
        }
        ProxyProtocol::Socks5(auth) => {
            handshake_socks5(&mut stream, dest, hostname, auth).await?;
        }
    }

    Ok(stream)
}

/// Perform an HTTP CONNECT handshake on an established TCP stream.
async fn handshake_http_connect(
    stream: &mut TcpStream,
    dest: SocketAddrV4,
    hostname: Option<&str>,
) -> Result<()> {
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

            if let Some(pos) = find_header_end(&buf[..filled]) {
                let header_str = std::str::from_utf8(&buf[..pos])
                    .context("Invalid UTF-8 in CONNECT response")?;
                parse_connect_response(header_str)?;
                return Ok(());
            }
        }
    })
    .await
    .context("Timeout waiting for CONNECT response")?;

    response
}

/// Perform a SOCKS5 handshake ([RFC 1928](https://tools.ietf.org/html/rfc1928) /
/// [RFC 1929](https://tools.ietf.org/html/rfc1929)) on an established TCP stream.
///
/// Steps:
/// 1. **Greeting** — advertise supported auth methods
/// 2. **Auth** — username/password sub-negotiation if the server selects method `0x02`
/// 3. **CONNECT** — request a tunnel to `dest` (using ATYP domain when `hostname` is available)
async fn handshake_socks5(
    stream: &mut TcpStream,
    dest: SocketAddrV4,
    hostname: Option<&str>,
    auth: &ProxyAuth,
) -> Result<()> {
    // Step 1: Greeting — advertise supported auth methods
    let greeting = match auth {
        ProxyAuth::None => vec![0x05, 0x01, 0x00], // 1 method: no auth
        ProxyAuth::UsernamePassword { .. } => vec![0x05, 0x02, 0x00, 0x02], // 2 methods: no auth + user/pass
    };

    timeout(CONNECT_TIMEOUT, stream.write_all(&greeting))
        .await
        .context("Timeout sending SOCKS5 greeting")?
        .context("Failed to send SOCKS5 greeting")?;

    // Read server's method selection (2 bytes: version, method)
    let mut method_resp = [0u8; 2];
    timeout(CONNECT_TIMEOUT, stream.read_exact(&mut method_resp))
        .await
        .context("Timeout reading SOCKS5 method selection")?
        .context("Failed to read SOCKS5 method selection")?;

    if method_resp[0] != 0x05 {
        bail!(
            "SOCKS5: unexpected version {} in method selection",
            method_resp[0]
        );
    }

    match method_resp[1] {
        0x00 => {} // No auth required — proceed
        0x02 => {
            // Username/password auth (RFC 1929)
            match auth {
                ProxyAuth::UsernamePassword { username, password } => {
                    socks5_username_auth(stream, username, password).await?;
                }
                ProxyAuth::None => {
                    bail!("SOCKS5: server requires username/password auth but none configured");
                }
            }
        }
        0xFF => bail!("SOCKS5: no acceptable authentication methods"),
        other => bail!("SOCKS5: unsupported auth method 0x{:02x}", other),
    }

    // Step 2: CONNECT request
    let mut req = vec![
        0x05, // version
        0x01, // CMD: CONNECT
        0x00, // reserved
    ];

    match hostname {
        Some(h) if h.len() <= 255 => {
            // ATYP 0x03: domain name
            req.push(0x03);
            req.push(h.len() as u8);
            req.extend_from_slice(h.as_bytes());
        }
        _ => {
            // ATYP 0x01: IPv4
            req.push(0x01);
            req.extend_from_slice(&dest.ip().octets());
        }
    }
    req.extend_from_slice(&dest.port().to_be_bytes());

    timeout(CONNECT_TIMEOUT, stream.write_all(&req))
        .await
        .context("Timeout sending SOCKS5 CONNECT request")?
        .context("Failed to send SOCKS5 CONNECT request")?;

    // Read response: at least 4 bytes header, then variable address
    let mut resp_header = [0u8; 4];
    timeout(CONNECT_TIMEOUT, stream.read_exact(&mut resp_header))
        .await
        .context("Timeout reading SOCKS5 CONNECT response")?
        .context("Failed to read SOCKS5 CONNECT response")?;

    if resp_header[0] != 0x05 {
        bail!(
            "SOCKS5: unexpected version {} in CONNECT response",
            resp_header[0]
        );
    }
    if resp_header[1] != 0x00 {
        bail!(
            "SOCKS5: CONNECT failed with status 0x{:02x} ({})",
            resp_header[1],
            socks5_error_message(resp_header[1])
        );
    }

    // Consume the bound address (ATYP + addr + port) so the stream is clean
    match resp_header[3] {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut buf = [0u8; 6];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
                .await
                .context("Timeout reading SOCKS5 bound address")?
                .context("Failed to read SOCKS5 bound address")?;
        }
        0x03 => {
            // Domain: 1 byte len + domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut len_buf))
                .await
                .context("Timeout reading SOCKS5 domain length")?
                .context("Failed to read SOCKS5 domain length")?;
            let mut buf = vec![0u8; len_buf[0] as usize + 2];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
                .await
                .context("Timeout reading SOCKS5 bound domain")?
                .context("Failed to read SOCKS5 bound domain")?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut buf = [0u8; 18];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
                .await
                .context("Timeout reading SOCKS5 bound IPv6 address")?
                .context("Failed to read SOCKS5 bound IPv6 address")?;
        }
        other => bail!("SOCKS5: unknown address type 0x{:02x} in response", other),
    }

    Ok(())
}

/// SOCKS5 username/password sub-negotiation (RFC 1929).
async fn socks5_username_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut auth_req = vec![0x01]; // sub-negotiation version
    auth_req.push(username.len() as u8);
    auth_req.extend_from_slice(username.as_bytes());
    auth_req.push(password.len() as u8);
    auth_req.extend_from_slice(password.as_bytes());

    timeout(CONNECT_TIMEOUT, stream.write_all(&auth_req))
        .await
        .context("Timeout sending SOCKS5 auth")?
        .context("Failed to send SOCKS5 auth")?;

    let mut auth_resp = [0u8; 2];
    timeout(CONNECT_TIMEOUT, stream.read_exact(&mut auth_resp))
        .await
        .context("Timeout reading SOCKS5 auth response")?
        .context("Failed to read SOCKS5 auth response")?;

    if auth_resp[1] != 0x00 {
        bail!(
            "SOCKS5: authentication failed (status 0x{:02x})",
            auth_resp[1]
        );
    }

    Ok(())
}

/// Map a SOCKS5 reply status byte to a human-readable error message.
fn socks5_error_message(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

/// Set `SO_MARK` on a TCP socket for nftables fwmark-based filtering (Linux only).
///
/// This must be called before `connect()` so the SYN packet carries the mark
/// and the OUTPUT chain can skip it.
#[cfg(target_os = "linux")]
fn set_fwmark(socket: &tokio::net::TcpSocket, mark: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Bind a TCP socket to the loopback interface (`lo0`) via `IP_BOUND_IF` (macOS only).
///
/// When the upstream proxy is on localhost, this ensures the proxy's outbound
/// connections stay on lo0 and never traverse the physical interface where pf's
/// `pass out on <iface> route-to` rule would intercept them.
///
/// pf only applies `rdr on lo0` to traffic *re-routed* by `route-to`, not to
/// natively-originated loopback traffic, so no redirect loop occurs.
#[cfg(target_os = "macos")]
fn bind_to_loopback(socket: &tokio::net::TcpSocket) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let lo0_index = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
    if lo0_index == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "lo0 interface not found",
        ));
    }
    // IP_BOUND_IF = 25 on macOS (from <netinet/in.h>)
    const IP_BOUND_IF: libc::c_int = 25;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &lo0_index as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Find the end of HTTP headers (`\r\n\r\n`) in `data`. Returns the byte offset just past the delimiter.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// Parse an HTTP CONNECT response status line. Returns `Ok(())` on `200`, errors otherwise.
fn parse_connect_response(header: &str) -> Result<()> {
    let status_line = header.lines().next().context("Empty CONNECT response")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(find_header_end(b""), None);
    }

    #[test]
    fn test_parse_connect_response_ok() {
        assert!(parse_connect_response("HTTP/1.1 200 Connection established\r\n").is_ok());
    }

    #[test]
    fn test_parse_connect_response_error() {
        assert!(parse_connect_response("HTTP/1.1 403 Forbidden\r\n").is_err());
    }

    #[test]
    fn test_socks5_error_messages() {
        assert_eq!(socks5_error_message(0x01), "general SOCKS server failure");
        assert_eq!(socks5_error_message(0x05), "connection refused");
        assert_eq!(socks5_error_message(0xFF), "unknown error");
    }
}
