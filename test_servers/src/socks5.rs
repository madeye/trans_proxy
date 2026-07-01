//! Minimal SOCKS5 proxy server for e2e testing.
//!
//! Supports no-auth CONNECT and UDP ASSOCIATE (RFC 1928). UDP ASSOCIATE lets
//! the gateway e2e exercise the transparent QUIC/HTTP-3 relay path. Tracks the
//! TCP connection count via a shared atomic.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::fwmark;

pub struct Socks5Server {
    listener: TcpListener,
    pub connection_count: Arc<AtomicU64>,
}

impl Socks5Server {
    pub async fn bind(addr: &str, port: u16) -> Result<Self> {
        let listener = TcpListener::bind(format!("{addr}:{port}"))
            .await
            .with_context(|| format!("failed to bind SOCKS5 on {addr}:{port}"))?;
        Ok(Self {
            listener,
            connection_count: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub async fn run(self) -> Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let count = self.connection_count.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks5(stream, count).await {
                    tracing::warn!("socks5 handler error: {e:#}");
                }
            });
        }
    }
}

async fn handle_socks5(mut stream: tokio::net::TcpStream, count: Arc<AtomicU64>) -> Result<()> {
    let mark = fwmark::fwmark_from_env();
    // Read greeting: version (1) + nmethods (1) + methods (nmethods)
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("not SOCKS5");
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // Reply: no auth
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request: ver(1) + cmd(1) + rsv(1) + atyp(1)
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != 0x05 {
        bail!("not SOCKS5 in request");
    }
    let cmd = req_header[1];
    let dest_addr = read_request_addr(&mut stream, req_header[3]).await?;

    match cmd {
        0x01 => handle_connect(stream, dest_addr, count, mark).await,
        0x03 => handle_udp_associate(stream, mark).await,
        other => bail!("unsupported SOCKS5 command 0x{other:02x}"),
    }
}

/// Read a request's `DST.ADDR` + `DST.PORT` for the given `ATYP`, resolving a
/// domain to a socket address.
async fn read_request_addr(stream: &mut tokio::net::TcpStream, atyp: u8) -> Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            Ok(SocketAddr::from((
                Ipv4Addr::from(addr),
                u16::from_be_bytes(port_bytes),
            )))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain_bytes = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain_bytes).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let domain = String::from_utf8(domain_bytes).context("invalid domain")?;
            tokio::net::lookup_host(format!("{domain}:{port}"))
                .await?
                .next()
                .context("DNS lookup failed")
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            Ok(SocketAddr::from((
                Ipv6Addr::from(addr),
                u16::from_be_bytes(port_bytes),
            )))
        }
        other => bail!("unsupported ATYP 0x{other:02x}"),
    }
}

async fn handle_connect(
    mut stream: tokio::net::TcpStream,
    dest_addr: SocketAddr,
    count: Arc<AtomicU64>,
    mark: Option<u32>,
) -> Result<()> {
    // Connect to destination (with fwmark to avoid nftables redirect loop)
    let mut target = fwmark::connect_marked(dest_addr, mark).await?;

    // Send success reply
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    count.fetch_add(1, Ordering::Relaxed);

    // Relay
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
    Ok(())
}

/// Handle a UDP ASSOCIATE: bind a relay socket, advertise it, and shuttle
/// encapsulated datagrams (RFC 1928 §7) to their real destination and back for
/// as long as the TCP control connection stays open.
async fn handle_udp_associate(mut stream: tokio::net::TcpStream, mark: Option<u32>) -> Result<()> {
    // Bind the relay on the same local IP the control connection landed on, so
    // the advertised endpoint is reachable by the client.
    let local_ip = stream.local_addr()?.ip();
    let relay = UdpSocket::bind((local_ip, 0)).await?;
    let relay_port = relay.local_addr()?.port();

    // Advertise BND.ADDR = 0.0.0.0 : relay_port. An unspecified address tells
    // the client to send datagrams to the proxy's own IP (the control peer).
    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    reply.extend_from_slice(&relay_port.to_be_bytes());
    stream.write_all(&reply).await?;

    let relay = Arc::new(relay);
    let pump = tokio::spawn(udp_relay_loop(relay.clone(), mark));

    // Keep the association alive until the control connection closes (EOF).
    let mut sink = [0u8; 16];
    loop {
        match stream.read(&mut sink).await {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    pump.abort();
    Ok(())
}

/// Shuttle SOCKS5-encapsulated UDP datagrams between the client and the real
/// destination. Stateless echo-friendly relay: each inbound datagram is
/// forwarded to its `DST` and the first reply is sent back to the client.
async fn udp_relay_loop(relay: Arc<UdpSocket>, mark: Option<u32>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client_src) = relay.recv_from(&mut buf).await?;
        let Some((dst, payload_off)) = parse_udp_header(&buf[..n]) else {
            continue;
        };
        let payload = buf[payload_off..n].to_vec();
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(e) = relay_one(&relay, client_src, dst, &payload, mark).await {
                tracing::warn!("udp relay to {dst} failed: {e:#}");
            }
        });
    }
}

async fn relay_one(
    relay: &UdpSocket,
    client_src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    mark: Option<u32>,
) -> Result<()> {
    let bind: SocketAddr = if dst.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let onward = UdpSocket::bind(bind).await?;
    fwmark::set_mark(&onward, mark)?;
    onward.connect(dst).await?;
    onward.send(payload).await?;

    let mut rbuf = vec![0u8; 65535];
    let m = tokio::time::timeout(std::time::Duration::from_secs(5), onward.recv(&mut rbuf))
        .await
        .context("upstream UDP reply timed out")??;

    let mut out = encode_udp_header(dst);
    out.extend_from_slice(&rbuf[..m]);
    relay.send_to(&out, client_src).await?;
    Ok(())
}

/// Parse a SOCKS5 UDP request header, returning the destination and the offset
/// at which the encapsulated payload begins. `None` if malformed/fragmented.
fn parse_udp_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.len() < 4 || buf[2] != 0x00 {
        return None;
    }
    match buf[3] {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((SocketAddr::from((ip, port)), 10))
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((SocketAddr::from((Ipv6Addr::from(octets), port)), 22))
        }
        _ => None,
    }
}

/// Build a SOCKS5 UDP reply header for a datagram coming back from `src`.
fn encode_udp_header(src: SocketAddr) -> Vec<u8> {
    let mut hdr = vec![0x00, 0x00, 0x00];
    match src.ip() {
        std::net::IpAddr::V4(ip) => {
            hdr.push(0x01);
            hdr.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            hdr.push(0x04);
            hdr.extend_from_slice(&ip.octets());
        }
    }
    hdr.extend_from_slice(&src.port().to_be_bytes());
    hdr
}
