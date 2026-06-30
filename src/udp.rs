//! Transparent UDP relay (Linux): proxy QUIC / HTTP-3 through a SOCKS5 upstream.
//!
//! The TCP path recovers the original destination of a redirected connection
//! after the fact (`SO_ORIGINAL_DST`). UDP is connectionless and cannot use
//! that mechanism, so this module uses **TPROXY** instead:
//!
//! 1. nftables (`tproxy_prerouting`) diverts forwarded QUIC datagrams to this
//!    process's UDP listener without rewriting their headers, and policy
//!    routing delivers them locally (see [`crate::firewall`]).
//! 2. The listener socket has `IP_TRANSPARENT` (to receive the foreign-destined
//!    datagrams) and `IP_RECVORIGDSTADDR` (so each `recvmsg` reports the real
//!    destination in a control message).
//! 3. Each unique `(client, original-destination)` pair becomes a session that
//!    opens a SOCKS5 UDP ASSOCIATE relay ([`crate::tunnel::udp_associate`]) and
//!    shuttles datagrams in both directions, wrapping/unwrapping the SOCKS5 UDP
//!    request header.
//! 4. Replies are sent back to the client from a per-session `IP_TRANSPARENT`
//!    socket bound to the original destination, so they appear to originate from
//!    the real server — exactly what the client expects.
//!
//! Only forwarded (routed) traffic is intercepted; gateway-originated QUIC is
//! handled by a firewall drop instead, since TPROXY only hooks the forward path.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use libc::c_int;
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, info};

use crate::config::UpstreamProxy;
use crate::dns::DnsTable;
use crate::tunnel;

/// Tear a session down after this long with no datagrams in either direction.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest UDP datagram we handle (theoretical IPv4 maximum).
const MAX_UDP_SIZE: usize = 65535;

// Linux socket-option constants not exposed by the `libc` crate.
const IP_TRANSPARENT: c_int = 19;
const IP_RECVORIGDSTADDR: c_int = 20;
const IP_ORIGDSTADDR: c_int = 20;
const IPV6_TRANSPARENT: c_int = 75;
const IPV6_RECVORIGDSTADDR: c_int = 74;
const IPV6_ORIGDSTADDR: c_int = 74;

/// Session lookup key: the LAN client and the original (real) destination.
type SessionKey = (SocketAddr, SocketAddr);

type SessionMap = Arc<Mutex<HashMap<SessionKey, mpsc::UnboundedSender<Vec<u8>>>>>;

/// Run the transparent UDP relay: bind the TPROXY listener on `listen_addr` and
/// dispatch each datagram to its per-flow SOCKS5 UDP ASSOCIATE session.
///
/// `fwmark` (when `--local-traffic` is enabled) is applied to the upstream TCP
/// control connection for loop prevention, mirroring the TCP path.
pub async fn run(
    listen_addr: SocketAddr,
    proxy: UpstreamProxy,
    dns_table: DnsTable,
    fwmark: Option<u32>,
) -> Result<()> {
    let listener = create_tproxy_listener(listen_addr)
        .with_context(|| format!("Failed to bind transparent UDP listener on {listen_addr}"))?;
    let listener = AsyncFd::new(listener).context("AsyncFd registration failed")?;
    info!("Transparent UDP relay (QUIC/HTTP-3) listening on {listen_addr}");

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; MAX_UDP_SIZE];

    loop {
        let mut guard = listener.readable().await?;
        match guard.try_io(|inner| recv_with_origdst(inner.get_ref().as_raw_fd(), &mut buf)) {
            Ok(Ok((n, client, orig_dst))) => {
                dispatch(
                    &sessions,
                    client,
                    orig_dst,
                    buf[..n].to_vec(),
                    &proxy,
                    &dns_table,
                    fwmark,
                );
            }
            Ok(Err(e)) => debug!("UDP recvmsg failed: {e}"),
            Err(_would_block) => continue,
        }
    }
}

/// Route a datagram to its session, creating one on first sight of the flow.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    sessions: &SessionMap,
    client: SocketAddr,
    orig_dst: SocketAddr,
    payload: Vec<u8>,
    proxy: &UpstreamProxy,
    dns_table: &DnsTable,
    fwmark: Option<u32>,
) {
    let key = (client, orig_dst);
    let mut map = sessions.lock().unwrap();

    if let Some(tx) = map.get(&key) {
        if tx.send(payload).is_ok() {
            return;
        }
        // The session task has exited but not yet removed itself; recreate.
        map.remove(&key);
        // The payload was consumed by the failed send; this datagram is lost,
        // but QUIC retransmits. (Returning here keeps the borrow simple.)
        return;
    }

    let (tx, rx) = mpsc::unbounded_channel();
    let _ = tx.send(payload);
    map.insert(key, tx);

    let sessions = Arc::clone(sessions);
    let proxy = proxy.clone();
    let dns_table = dns_table.clone();
    tokio::spawn(async move {
        if let Err(e) = run_session(key, rx, &proxy, &dns_table, fwmark).await {
            debug!("UDP session {client} -> {orig_dst} ended: {e:#}");
        }
        sessions.lock().unwrap().remove(&key);
    });
}

/// Drive a single SOCKS5 UDP ASSOCIATE session for one `(client, orig_dst)`.
async fn run_session(
    key: SessionKey,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    proxy: &UpstreamProxy,
    dns_table: &DnsTable,
    fwmark: Option<u32>,
) -> Result<()> {
    let (client, orig_dst) = key;

    let (mut control, relay_addr) = tunnel::udp_associate(proxy, fwmark)
        .await
        .context("UDP ASSOCIATE failed")?;
    debug!("UDP ASSOCIATE for {client} -> {orig_dst} via relay {relay_addr}");

    // Socket toward the SOCKS5 UDP relay endpoint.
    let relay = bind_relay_socket(relay_addr).await?;
    // Source-spoofing socket: replies leave from the real destination address.
    let reply =
        transparent_sender(orig_dst).context("Failed to create transparent reply socket")?;

    // Let the proxy resolve the destination when we know its hostname.
    let hostname = dns_table.lookup(&orig_dst.ip());

    let mut rbuf = vec![0u8; MAX_UDP_SIZE];
    let mut ctl = [0u8; 1];

    loop {
        tokio::select! {
            biased;

            // Client -> upstream: wrap in the SOCKS5 UDP header and forward.
            maybe = rx.recv() => {
                let Some(payload) = maybe else { return Ok(()) };
                let pkt = tunnel::encode_socks5_udp(orig_dst, hostname.as_deref(), &payload);
                relay.send(&pkt).await.context("relay send failed")?;
            }

            // Upstream -> client: strip the SOCKS5 UDP header, spoof the source.
            r = relay.recv(&mut rbuf) => {
                let n = r.context("relay recv failed")?;
                if let Some(off) = tunnel::socks5_udp_payload_offset(&rbuf[..n]) {
                    if let Err(e) = reply.send_to(&rbuf[off..n], client).await {
                        debug!("transparent reply to {client} failed: {e}");
                    }
                }
            }

            // The proxy closing the control connection tears down the relay.
            r = control.read(&mut ctl) => {
                match r {
                    Ok(0) => return Ok(()),       // EOF: association closed
                    Ok(_) => {}                    // unexpected control data: ignore
                    Err(e) => return Err(e).context("control connection error"),
                }
            }

            // Idle flows are reaped (the timer re-arms on every iteration).
            _ = tokio::time::sleep(SESSION_IDLE_TIMEOUT) => return Ok(()),
        }
    }
}

/// Open a connected UDP socket toward the SOCKS5 relay endpoint.
async fn bind_relay_socket(relay: SocketAddr) -> Result<UdpSocket> {
    let bind: SocketAddr = if relay.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind)
        .await
        .context("Failed to bind relay socket")?;
    sock.connect(relay)
        .await
        .context("Failed to connect relay socket")?;
    Ok(sock)
}

/// Create a UDP socket bound (via `IP_TRANSPARENT`) to a foreign `src` address,
/// so datagrams sent from it appear to originate from the real destination.
fn transparent_sender(src: SocketAddr) -> Result<UdpSocket> {
    let (domain, level, transparent_opt) = match src {
        SocketAddr::V4(_) => (libc::AF_INET, libc::SOL_IP, IP_TRANSPARENT),
        SocketAddr::V6(_) => (libc::AF_INET6, libc::SOL_IPV6, IPV6_TRANSPARENT),
    };

    let sock = new_udp_socket(domain)?;
    let fd = sock.as_raw_fd();
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    setsockopt_int(fd, level, transparent_opt, 1)?;
    bind_fd(fd, src)?;

    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock).context("from_std failed for transparent sender")
}

/// Build the TPROXY listener: `IP_TRANSPARENT` (receive foreign-destined
/// datagrams) + `IP_RECVORIGDSTADDR` (report the real destination per datagram).
fn create_tproxy_listener(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let (domain, level, transparent_opt, recvorig_opt) = match addr {
        SocketAddr::V4(_) => (
            libc::AF_INET,
            libc::SOL_IP,
            IP_TRANSPARENT,
            IP_RECVORIGDSTADDR,
        ),
        SocketAddr::V6(_) => (
            libc::AF_INET6,
            libc::SOL_IPV6,
            IPV6_TRANSPARENT,
            IPV6_RECVORIGDSTADDR,
        ),
    };

    let sock = new_udp_socket(domain)?;
    let fd = sock.as_raw_fd();
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    setsockopt_int(fd, level, transparent_opt, 1)?;
    setsockopt_int(fd, level, recvorig_opt, 1)?;
    bind_fd(fd, addr)?;

    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Create an owned `std::net::UdpSocket` from a raw `socket(2)` call so that the
/// fd is closed on any early return.
fn new_udp_socket(domain: c_int) -> Result<std::net::UdpSocket> {
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket() failed");
    }
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

fn setsockopt_int(fd: RawFd, level: c_int, opt: c_int, val: c_int) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &val as *const c_int as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bind `fd` to `addr` via `libc::bind` (std offers no bind-after-construction).
fn bind_fd(fd: RawFd, addr: SocketAddr) -> io::Result<()> {
    let ret = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*a.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `recvmsg` a datagram, returning its length, source, and original
/// destination (recovered from the `IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR` cmsg).
fn recv_with_origdst(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut name: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_space = [0u8; 128];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut name as *mut libc::sockaddr_storage as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let client = storage_to_socketaddr(&name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad source address"))?;

        let mut orig_dst = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == IP_ORIGDSTADDR {
                let sin = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                orig_dst = Some(SocketAddr::from((ip, u16::from_be(sin.sin_port))));
            } else if hdr.cmsg_level == libc::SOL_IPV6 && hdr.cmsg_type == IPV6_ORIGDSTADDR {
                let sin6 = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                orig_dst = Some(SocketAddr::from((ip, u16::from_be(sin6.sin6_port))));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        let orig_dst = orig_dst.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing original-destination control message (TPROXY misconfigured?)",
            )
        })?;

        Ok((n as usize, client, orig_dst))
    }
}

/// Convert a kernel `sockaddr_storage` (IPv4/IPv6) to a Rust `SocketAddr`.
unsafe fn storage_to_socketaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as c_int {
        libc::AF_INET => {
            let sin = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6 = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::from((ip, u16::from_be(sin6.sin6_port))))
        }
        _ => None,
    }
}
