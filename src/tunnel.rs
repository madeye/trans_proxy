//! Upstream proxy tunnel establishment and relay.
//!
//! Opens a TCP connection to the upstream proxy and performs either an
//! HTTP CONNECT or SOCKS5 handshake to the original destination, returning
//! the connected stream for bidirectional relay.
//!
//! The HTTP CONNECT response is read in chunks, so bytes the upstream sends
//! immediately after the header terminator (the start of the tunneled payload
//! for server-speaks-first protocols) may land in the local buffer. Those
//! leftover bytes are returned to the caller so none of the payload is lost;
//! the SOCKS5 handshake uses exact-size reads and never over-reads.
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
//!
//! # Loop Prevention
//!
//! When `--local-traffic` is enabled, the proxy's own outbound connections
//! must be excluded from NAT interception to avoid infinite loops:
//!
//! - **Linux**: Sets `SO_MARK` (fwmark) on the TCP socket before connect.
//!   The nftables OUTPUT chain has a `meta mark` rule that skips marked packets.
//! - **macOS**: Sets `IP_BOUND_IF` to bind the socket to `lo0` when the upstream
//!   proxy is on localhost, keeping traffic off the physical interface where pf's
//!   `route-to` rule would intercept it.

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::config::{ProxyAuth, ProxyProtocol, UpstreamProxy};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 8192;
const MAX_SOCKS5_FIELD_LEN: usize = 255;

/// Establish a tunnel through the upstream proxy to the given destination.
///
/// Connects to `proxy.addr`, then performs either an HTTP CONNECT or SOCKS5
/// handshake depending on [`proxy.protocol`](crate::config::ProxyProtocol).
/// Returns the connected [`TcpStream`] with the handshake completed and
/// all protocol framing consumed — ready for bidirectional relay — plus any
/// payload bytes read past the CONNECT response headers (usually empty; the
/// caller must deliver them to the client before relaying).
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
    dest: SocketAddr,
    hostname: Option<&str>,
    #[cfg(target_os = "linux")] fwmark: Option<u32>,
    #[cfg(target_os = "macos")] local_traffic: bool,
) -> Result<(TcpStream, Vec<u8>)> {
    let mut stream = connect_proxy_stream(
        proxy,
        #[cfg(target_os = "linux")]
        fwmark,
        #[cfg(target_os = "macos")]
        local_traffic,
    )
    .await?;

    let leftover = match &proxy.protocol {
        ProxyProtocol::HttpConnect => handshake_http_connect(&mut stream, dest, hostname).await?,
        ProxyProtocol::Socks5(auth) => {
            // SOCKS5 framing is consumed with exact-size reads — no leftover
            socks5_negotiate_auth(&mut stream, auth).await?;
            socks5_connect(&mut stream, dest, hostname).await?;
            Vec::new()
        }
    };

    Ok((stream, leftover))
}

/// Open a TCP connection to the upstream proxy with the platform-specific
/// loop-prevention socket options applied (see module docs).
async fn connect_proxy_stream(
    proxy: &UpstreamProxy,
    #[cfg(target_os = "linux")] fwmark: Option<u32>,
    #[cfg(target_os = "macos")] local_traffic: bool,
) -> Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, async {
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
    .context("Failed to connect to upstream proxy")
}

/// Establish a SOCKS5 UDP ASSOCIATE relay through the upstream proxy.
///
/// Returns the TCP control stream — which **must be kept alive** for the
/// lifetime of the association (closing it tells the proxy to tear down the
/// UDP relay, per [RFC 1928](https://tools.ietf.org/html/rfc1928)) — and the
/// relay endpoint to which encapsulated UDP datagrams are sent.
///
/// The ASSOCIATE request advertises the wildcard source `0.0.0.0:0`: we cannot
/// predict the address the proxy will observe our datagrams arriving from, so
/// the proxy must accept datagrams from any source. If the proxy replies with
/// an unspecified bind address, datagrams are sent to the proxy's own IP (the
/// usual "same host as the control connection" convention).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // consumer (udp.rs) is Linux-only
pub async fn udp_associate(
    proxy: &UpstreamProxy,
    #[cfg(target_os = "linux")] fwmark: Option<u32>,
    #[cfg(target_os = "macos")] local_traffic: bool,
) -> Result<(TcpStream, SocketAddr)> {
    let auth = match &proxy.protocol {
        ProxyProtocol::Socks5(auth) => auth,
        ProxyProtocol::HttpConnect => {
            bail!("UDP ASSOCIATE requires a SOCKS5 upstream proxy");
        }
    };

    let mut stream = connect_proxy_stream(
        proxy,
        #[cfg(target_os = "linux")]
        fwmark,
        #[cfg(target_os = "macos")]
        local_traffic,
    )
    .await?;

    socks5_negotiate_auth(&mut stream, auth).await?;

    // UDP ASSOCIATE request (CMD 0x03), wildcard IPv4 source 0.0.0.0:0.
    let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    timeout(CONNECT_TIMEOUT, stream.write_all(&req))
        .await
        .context("Timeout sending SOCKS5 UDP ASSOCIATE request")?
        .context("Failed to send SOCKS5 UDP ASSOCIATE request")?;

    let mut resp_header = [0u8; 4];
    timeout(CONNECT_TIMEOUT, stream.read_exact(&mut resp_header))
        .await
        .context("Timeout reading SOCKS5 ASSOCIATE response")?
        .context("Failed to read SOCKS5 ASSOCIATE response")?;

    if resp_header[0] != 0x05 {
        bail!(
            "SOCKS5: unexpected version {} in ASSOCIATE response",
            resp_header[0]
        );
    }
    if resp_header[1] != 0x00 {
        bail!(
            "SOCKS5: UDP ASSOCIATE failed with status 0x{:02x} ({})",
            resp_header[1],
            socks5_error_message(resp_header[1])
        );
    }

    let bnd = read_socks5_bound_addr(&mut stream, resp_header[3]).await?;
    let relay = if bnd.ip().is_unspecified() {
        SocketAddr::new(proxy.addr.ip(), bnd.port())
    } else {
        bnd
    };

    Ok((stream, relay))
}

/// Perform an HTTP CONNECT handshake on an established TCP stream.
///
/// Returns any bytes read past the `\r\n\r\n` header terminator (the start
/// of the tunneled payload for server-speaks-first protocols, or pipelined
/// data from the proxy); usually empty.
async fn handshake_http_connect(
    stream: &mut TcpStream,
    dest: SocketAddr,
    hostname: Option<&str>,
) -> Result<Vec<u8>> {
    let request = http_connect_request(dest, hostname);

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
                // Preserve any payload bytes read past the header terminator
                return Ok(buf[pos..filled].to_vec());
            }
        }
    })
    .await
    .context("Timeout waiting for CONNECT response")?;

    response
}

/// Perform the SOCKS5 greeting + authentication sub-negotiation
/// ([RFC 1928](https://tools.ietf.org/html/rfc1928) /
/// [RFC 1929](https://tools.ietf.org/html/rfc1929)) on an established stream,
/// leaving it ready for a CONNECT or UDP ASSOCIATE request.
async fn socks5_negotiate_auth(stream: &mut TcpStream, auth: &ProxyAuth) -> Result<()> {
    // Greeting — advertise supported auth methods
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

    Ok(())
}

/// Send a SOCKS5 CONNECT request for `dest` and consume the reply, leaving the
/// stream clean for relay. Assumes auth negotiation has already completed.
async fn socks5_connect(
    stream: &mut TcpStream,
    dest: SocketAddr,
    hostname: Option<&str>,
) -> Result<()> {
    let req = socks5_connect_request(dest, hostname);

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
    read_socks5_bound_addr(stream, resp_header[3]).await?;

    Ok(())
}

/// Read and return a SOCKS5 bound address (`ATYP` + address + port) following a
/// reply header. A domain `ATYP` is consumed but reported as an unspecified
/// address (the caller substitutes a known IP).
async fn read_socks5_bound_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    match atyp {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut buf = [0u8; 6];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
                .await
                .context("Timeout reading SOCKS5 bound address")?
                .context("Failed to read SOCKS5 bound address")?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(SocketAddr::from((ip, port)))
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
            let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
            Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut buf = [0u8; 18];
            timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
                .await
                .context("Timeout reading SOCKS5 bound IPv6 address")?
                .context("Failed to read SOCKS5 bound IPv6 address")?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        other => bail!("SOCKS5: unknown address type 0x{:02x} in response", other),
    }
}

fn http_connect_request(dest: SocketAddr, hostname: Option<&str>) -> String {
    let host = proxy_request_host(dest, hostname);
    format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host,
        dest.port(),
        host,
        dest.port()
    )
}

fn socks5_connect_request(dest: SocketAddr, hostname: Option<&str>) -> Vec<u8> {
    let mut req = vec![
        0x05, // version
        0x01, // CMD: CONNECT
        0x00, // reserved
    ];

    match usable_proxy_hostname(hostname) {
        Some(h) => {
            req.push(0x03);
            req.push(h.len() as u8);
            req.extend_from_slice(h.as_bytes());
        }
        None => match dest.ip() {
            IpAddr::V4(ip) => {
                req.push(0x01);
                req.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                req.push(0x04);
                req.extend_from_slice(&ip.octets());
            }
        },
    }
    req.extend_from_slice(&dest.port().to_be_bytes());
    req
}

/// Encapsulate a UDP payload in a SOCKS5 UDP request header
/// ([RFC 1928 §7](https://tools.ietf.org/html/rfc1928#section-7)):
/// `RSV(2) | FRAG(1)=0 | ATYP | DST.ADDR | DST.PORT | DATA`.
///
/// Uses the domain `ATYP` when a safe `hostname` is supplied (letting the proxy
/// resolve and apply domain policy), otherwise the raw destination IP.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // consumer (udp.rs) is Linux-only
pub fn encode_socks5_udp(dest: SocketAddr, hostname: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(payload.len() + 22);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(1)=0

    match usable_proxy_hostname(hostname) {
        Some(h) => {
            pkt.push(0x03);
            pkt.push(h.len() as u8);
            pkt.extend_from_slice(h.as_bytes());
        }
        None => match dest.ip() {
            IpAddr::V4(ip) => {
                pkt.push(0x01);
                pkt.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                pkt.push(0x04);
                pkt.extend_from_slice(&ip.octets());
            }
        },
    }
    pkt.extend_from_slice(&dest.port().to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse a SOCKS5 UDP reply header, returning the byte offset at which the
/// encapsulated payload begins.
///
/// Returns `None` if the datagram is too short, malformed, or fragmented
/// (`FRAG != 0` — reassembly is unsupported, as in most SOCKS5 implementations).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // consumer (udp.rs) is Linux-only
pub fn socks5_udp_payload_offset(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 || buf[2] != 0x00 {
        return None;
    }
    let off = match buf[3] {
        0x01 => 4 + 4 + 2,                           // IPv4
        0x04 => 4 + 16 + 2,                          // IPv6
        0x03 => 4 + 1 + (*buf.get(4)? as usize) + 2, // domain
        _ => return None,
    };
    if buf.len() < off {
        return None;
    }
    Some(off)
}

fn proxy_request_host(dest: SocketAddr, hostname: Option<&str>) -> String {
    match usable_proxy_hostname(hostname) {
        Some(h) => h.to_string(),
        None => match dest.ip() {
            IpAddr::V6(ip) => format!("[{}]", ip),
            ip => ip.to_string(),
        },
    }
}

fn usable_proxy_hostname(hostname: Option<&str>) -> Option<&str> {
    hostname.filter(|host| is_safe_proxy_hostname(host))
}

fn is_safe_proxy_hostname(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    !name.is_empty()
        && host.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_'))
        })
}

/// SOCKS5 username/password sub-negotiation (RFC 1929).
async fn socks5_username_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<()> {
    let auth_req = build_socks5_auth_request(username, password)?;

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

fn build_socks5_auth_request(username: &str, password: &str) -> Result<Vec<u8>> {
    validate_socks5_auth_field("username", username)?;
    validate_socks5_auth_field("password", password)?;

    let mut auth_req = vec![0x01]; // sub-negotiation version
    auth_req.push(username.len() as u8);
    auth_req.extend_from_slice(username.as_bytes());
    auth_req.push(password.len() as u8);
    auth_req.extend_from_slice(password.as_bytes());
    Ok(auth_req)
}

fn validate_socks5_auth_field(label: &str, value: &str) -> Result<()> {
    let len = value.len();
    if len == 0 {
        bail!("SOCKS5: {label} cannot be empty");
    }
    if len > MAX_SOCKS5_FIELD_LEN {
        bail!("SOCKS5: {label} is {len} bytes, exceeds {MAX_SOCKS5_FIELD_LEN}-byte limit");
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
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;
    let (level, optname) = if socket.local_addr().is_ok_and(|a| a.is_ipv6()) {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
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

    #[test]
    fn test_socks5_auth_request_encodes_field_lengths() {
        let req = build_socks5_auth_request("user", "pass").unwrap();

        assert_eq!(req, b"\x01\x04user\x04pass");
    }

    #[test]
    fn test_socks5_auth_request_rejects_invalid_field_lengths() {
        assert!(build_socks5_auth_request("", "pass").is_err());
        assert!(build_socks5_auth_request("user", "").is_err());
        assert!(build_socks5_auth_request(&"u".repeat(256), "pass").is_err());
        assert!(build_socks5_auth_request("user", &"p".repeat(256)).is_err());
    }

    #[test]
    fn test_http_connect_request_uses_valid_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = http_connect_request(dest, Some("example.com"));

        assert_eq!(
            request,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[test]
    fn test_http_connect_request_falls_back_for_injected_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = http_connect_request(dest, Some("good.com\r\nX-Bad: yes"));

        assert_eq!(
            request,
            "CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\n\r\n"
        );
        assert!(!request.contains("X-Bad"));
    }

    #[test]
    fn test_socks5_connect_request_uses_valid_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = socks5_connect_request(dest, Some("example.com"));

        assert_eq!(
            request,
            vec![
                0x05, 0x01, 0x00, // SOCKS5 CONNECT header
                0x03, 0x0b, // domain address type and length
                b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
                0xbb, // port 443
            ]
        );
    }

    #[test]
    fn test_socks5_connect_request_falls_back_for_invalid_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let request = socks5_connect_request(dest, Some("good.com\r\nbad"));

        assert_eq!(
            request,
            vec![
                0x05, 0x01, 0x00, // SOCKS5 CONNECT header
                0x01, // IPv4 address type
                93, 184, 216, 34, // destination IP
                0x01, 0xbb, // port 443
            ]
        );
        assert!(!request.windows(b"good.com".len()).any(|w| w == b"good.com"));
    }

    #[test]
    fn test_proxy_hostname_validation() {
        assert!(is_safe_proxy_hostname("example.com"));
        assert!(is_safe_proxy_hostname("service_name.example.com."));
        assert!(!is_safe_proxy_hostname(""));
        assert!(!is_safe_proxy_hostname(".example.com"));
        assert!(!is_safe_proxy_hostname("example..com"));
        assert!(!is_safe_proxy_hostname("example.com:443"));
        assert!(!is_safe_proxy_hostname("example.com/path"));
        assert!(!is_safe_proxy_hostname("example.com\r\nInjected: yes"));
        assert!(!is_safe_proxy_hostname("例子.example"));
    }

    /// Run handshake_http_connect against a fake proxy that replies with
    /// `response` in a single write, returning the leftover bytes.
    async fn run_connect_handshake(response: &'static [u8]) -> Result<Vec<u8>> {
        let (leftover, _) = run_connect_handshake_capture(response, Some("example.com")).await?;
        Ok(leftover)
    }

    /// Run handshake_http_connect and capture the CONNECT request sent to the
    /// fake proxy.
    async fn run_connect_handshake_capture(
        response: &'static [u8],
        hostname: Option<&str>,
    ) -> Result<(Vec<u8>, String)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Consume the CONNECT request headers
            let mut buf = vec![0u8; 1024];
            let mut filled = 0;
            loop {
                let n = stream.read(&mut buf[filled..]).await.unwrap();
                assert!(n > 0, "client closed before sending CONNECT");
                filled += n;
                if find_header_end(&buf[..filled]).is_some() {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf[..filled]).to_string();
            stream.write_all(response).await.unwrap();
            request
        });

        let mut stream = TcpStream::connect(addr).await?;
        let dest: SocketAddr = "93.184.216.34:443".parse()?;
        let leftover = handshake_http_connect(&mut stream, dest, hostname).await?;
        let request = server.await.unwrap();
        Ok((leftover, request))
    }

    #[tokio::test]
    async fn test_http_connect_no_leftover() {
        let leftover = run_connect_handshake(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn test_http_connect_preserves_leftover_payload() {
        // Upstream coalesces the first tunneled bytes (e.g. an SMTPS banner)
        // with its CONNECT response — they must be returned, not dropped.
        let leftover = run_connect_handshake(
            b"HTTP/1.1 200 Connection established\r\n\r\n220 mail.example.com ESMTP\r\n",
        )
        .await
        .unwrap();
        assert_eq!(leftover, b"220 mail.example.com ESMTP\r\n");
    }

    #[tokio::test]
    async fn test_http_connect_failure_status() {
        let result = run_connect_handshake(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_http_connect_invalid_hostname_falls_back_to_ip() {
        let (_, request) = run_connect_handshake_capture(
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            Some("bad\r\nInjected: yes"),
        )
        .await
        .unwrap();

        assert!(request.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"));
        assert!(!request.contains("Injected: yes"));
    }

    #[test]
    fn test_encode_socks5_udp_ipv4() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let pkt = encode_socks5_udp(dest, None, b"hi");
        assert_eq!(
            pkt,
            vec![
                0x00, 0x00, 0x00, // RSV + FRAG
                0x01, // ATYP IPv4
                93, 184, 216, 34, // addr
                0x01, 0xbb, // port 443
                b'h', b'i', // payload
            ]
        );
    }

    #[test]
    fn test_encode_socks5_udp_uses_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let pkt = encode_socks5_udp(dest, Some("example.com"), b"x");
        assert_eq!(
            pkt,
            vec![
                0x00, 0x00, 0x00, 0x03, 0x0b, // domain ATYP + len
                b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb, b'x',
            ]
        );
    }

    #[test]
    fn test_encode_socks5_udp_falls_back_for_invalid_hostname() {
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let pkt = encode_socks5_udp(dest, Some("bad\r\nhost"), b"x");
        // Injected hostname rejected → falls back to the IPv4 address type
        assert_eq!(pkt[3], 0x01);
        assert!(!pkt.windows(3).any(|w| w == b"bad"));
    }

    #[test]
    fn test_socks5_udp_payload_offset() {
        // IPv4 reply: 3 + 1 + 4 + 2 = 10
        let v4 = [0u8, 0, 0, 1, 1, 2, 3, 4, 0, 80, b'p'];
        assert_eq!(socks5_udp_payload_offset(&v4), Some(10));
        // IPv6 reply: 3 + 1 + 16 + 2 = 22
        let mut v6 = vec![0u8, 0, 0, 4];
        v6.extend_from_slice(&[0u8; 18]);
        v6.push(b'p');
        assert_eq!(socks5_udp_payload_offset(&v6), Some(22));
        // Domain reply: 3 + 1 + 1 + len + 2
        let dom = [0u8, 0, 0, 3, 3, b'a', b'b', b'c', 0, 80, b'p'];
        assert_eq!(socks5_udp_payload_offset(&dom), Some(10));
    }

    #[test]
    fn test_socks5_udp_payload_offset_rejects_malformed() {
        assert_eq!(socks5_udp_payload_offset(&[0, 0]), None); // too short
        assert_eq!(socks5_udp_payload_offset(&[0, 0, 0x01, 1]), None); // FRAG != 0
        assert_eq!(socks5_udp_payload_offset(&[0, 0, 0, 0x09]), None); // bad ATYP
        assert_eq!(socks5_udp_payload_offset(&[0, 0, 0, 0x01, 1, 2]), None); // truncated
    }

    #[test]
    fn test_socks5_udp_roundtrip() {
        // A datagram we encode should, when prefixed as a reply, decode back to
        // the same payload.
        let dest: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let pkt = encode_socks5_udp(dest, None, b"payload-bytes");
        let off = socks5_udp_payload_offset(&pkt).unwrap();
        assert_eq!(&pkt[off..], b"payload-bytes");
    }

    /// Stand up a fake SOCKS5 server that accepts a UDP ASSOCIATE and reports a
    /// relay endpoint, then verify `udp_associate` drives the handshake and
    /// returns that endpoint.
    #[tokio::test]
    async fn test_udp_associate_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Greeting
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            // ASSOCIATE request
            let mut req = [0u8; 10];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x03); // UDP ASSOCIATE
                                      // Reply with relay endpoint 127.0.0.1:9999
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x27, 0x0f])
                .await
                .unwrap();
            // Hold the control connection open
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        });

        let proxy = UpstreamProxy {
            protocol: ProxyProtocol::Socks5(ProxyAuth::None),
            addr: proxy_addr,
        };
        let (_control, relay) = udp_associate(
            &proxy,
            #[cfg(target_os = "linux")]
            None,
            #[cfg(target_os = "macos")]
            false,
        )
        .await
        .unwrap();

        assert_eq!(relay, "127.0.0.1:9999".parse().unwrap());
        drop(_control);
        let _ = server.await;
    }

    /// When the proxy replies with an unspecified bind address, datagrams must
    /// be sent to the proxy's own IP.
    #[tokio::test]
    async fn test_udp_associate_unspecified_bind_uses_proxy_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 10];
            stream.read_exact(&mut req).await.unwrap();
            // Reply BND.ADDR = 0.0.0.0:7000
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x1b, 0x58])
                .await
                .unwrap();
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        });

        let proxy = UpstreamProxy {
            protocol: ProxyProtocol::Socks5(ProxyAuth::None),
            addr: proxy_addr,
        };
        let (_control, relay) = udp_associate(
            &proxy,
            #[cfg(target_os = "linux")]
            None,
            #[cfg(target_os = "macos")]
            false,
        )
        .await
        .unwrap();

        // Relay IP substituted with the proxy IP (127.0.0.1), port preserved.
        assert_eq!(relay, SocketAddr::new(proxy_addr.ip(), 7000));
        drop(_control);
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_udp_associate_rejects_http_proxy() {
        let proxy = UpstreamProxy {
            protocol: ProxyProtocol::HttpConnect,
            addr: "127.0.0.1:1".parse().unwrap(),
        };
        let err = udp_associate(
            &proxy,
            #[cfg(target_os = "linux")]
            None,
            #[cfg(target_os = "macos")]
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("requires a SOCKS5"));
    }

    #[tokio::test]
    async fn test_socks5_auth_rejects_overlong_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x02]).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let auth = ProxyAuth::UsernamePassword {
            username: "u".repeat(MAX_SOCKS5_FIELD_LEN + 1),
            password: "p".to_string(),
        };
        let err = socks5_negotiate_auth(&mut stream, &auth).await.unwrap_err();

        assert!(err.to_string().contains("username is 256 bytes"));
        server.await.unwrap();
    }
}
