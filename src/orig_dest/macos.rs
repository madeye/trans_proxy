//! Original destination recovery for pf-redirected connections on macOS.
//!
//! When macOS pf's `rdr` rule rewrites a packet's destination, the original
//! target is stored in pf's NAT state table. This module queries that table
//! using the `DIOCNATLOOK` ioctl on `/dev/pf` to recover the original
//! destination address.
//!
//! This is the same technique used by [mitmproxy](https://mitmproxy.org/)
//! in transparent mode.
//!
//! # FFI Safety
//!
//! The [`PfiocNatlook`] struct is `#[repr(C)]` and matches the layout of
//! `struct pfioc_natlook` from macOS `net/pfvar.h`. The ioctl number
//! [`DIOCNATLOOK`] is computed at compile time to match the kernel's
//! `_IOWR('D', 23, struct pfioc_natlook)`.
//!
//! # Fallback
//!
//! If `DIOCNATLOOK` fails (e.g., the connection wasn't redirected by pf),
//! [`get_original_dest`] falls back to checking whether `getsockname()`
//! returned a different address than the listen address, which works with
//! `divert-to` rules.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use tokio::net::TcpStream;

/// pf address wrapper matching struct pf_addr (union of v4/v6 in a 16-byte field)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfAddr {
    addr: [u8; 16],
}

/// Matches `struct pfioc_natlook` from macOS `net/pfvar.h`.
/// Verified against macOS 14 / xnu headers.
#[repr(C)]
#[derive(Clone, Copy)]
struct PfiocNatlook {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sport: u16,    // network byte order
    dport: u16,    // network byte order
    rsport: u16,   // network byte order
    rdport: u16,   // network byte order
    af: u8,        // AF_INET = 2
    proto: u8,     // IPPROTO_TCP = 6
    direction: u8, // PF_IN = 0, PF_OUT = 1
    log: u8,
}

impl Default for PfiocNatlook {
    fn default() -> Self {
        // Zero-initialize everything
        unsafe { std::mem::zeroed() }
    }
}

/// DIOCNATLOOK ioctl number for macOS pf.
/// From pfvar.h: #define DIOCNATLOOK _IOWR('D', 23, struct pfioc_natlook)
/// _IOWR encodes: direction(in+out) | size | group | number
/// group 'D' = 0x44, number = 23 = 0x17
/// size = `mem::size_of::<PfiocNatlook>()`
///
/// macOS ioctl encoding:
///   IOC_INOUT (0xC0000000) | (size << 16) | ('D' << 8) | 23
const fn diocnatlook_ioctl() -> libc::c_ulong {
    let size = std::mem::size_of::<PfiocNatlook>() as libc::c_ulong;
    let ioc_inout: libc::c_ulong = 0xC0000000;
    ioc_inout | (size << 16) | (0x44 << 8) | 23
}

const DIOCNATLOOK: libc::c_ulong = diocnatlook_ioctl();

const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;
const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const PF_OUT: u8 = 1;

/// Handle to /dev/pf for NAT lookups.
pub struct NatHandle {
    fd: RawFd,
}

// The fd is only used for ioctl reads, safe to share across threads.
unsafe impl Send for NatHandle {}
unsafe impl Sync for NatHandle {}

impl NatHandle {
    /// Open /dev/pf. Requires root privileges.
    pub fn open() -> Result<Arc<Self>> {
        let fd = unsafe { libc::open(c"/dev/pf".as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to open /dev/pf (are you running as root?)");
        }
        Ok(Arc::new(Self { fd }))
    }
}

impl Drop for NatHandle {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for NatHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Look up the original destination for a redirected connection using DIOCNATLOOK.
fn get_original_dest_pf(
    pf: &NatHandle,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<SocketAddr> {
    let (af, src_octets, src_port, dst_octets, dst_port) = match (client_addr, local_addr) {
        (SocketAddr::V4(c), SocketAddr::V4(l)) => {
            let mut src = [0u8; 16];
            src[..4].copy_from_slice(&c.ip().octets());
            let mut dst = [0u8; 16];
            dst[..4].copy_from_slice(&l.ip().octets());
            (AF_INET, src, c.port(), dst, l.port())
        }
        (SocketAddr::V6(c), SocketAddr::V6(l)) => {
            let mut src = [0u8; 16];
            src.copy_from_slice(&c.ip().octets());
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&l.ip().octets());
            (AF_INET6, src, c.port(), dst, l.port())
        }
        _ => anyhow::bail!("Address family mismatch between client and local addr"),
    };

    let mut nl = PfiocNatlook {
        af,
        proto: IPPROTO_TCP,
        direction: PF_OUT,
        ..PfiocNatlook::default()
    };

    nl.saddr.addr = src_octets;
    nl.sport = src_port.to_be();
    nl.daddr.addr = dst_octets;
    nl.dport = dst_port.to_be();

    let ret = unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
    if ret < 0 {
        nl.direction = 0; // PF_IN
        let ret2 =
            unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
        if ret2 < 0 {
            return Err(std::io::Error::last_os_error())
                .context("DIOCNATLOOK failed for both PF_OUT and PF_IN");
        }
    }

    let port = u16::from_be(nl.rdport);

    match af {
        AF_INET => {
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&nl.rdaddr.addr[..4]);
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip_bytes),
                port,
            )))
        }
        _ => {
            let ip = Ipv6Addr::from(nl.rdaddr.addr);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
    }
}

/// Determine original destination for a connection.
///
/// Tries DIOCNATLOOK first, falls back to getsockname check.
pub fn get_original_dest(
    pf: &NatHandle,
    _stream: &TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<SocketAddr> {
    match get_original_dest_pf(pf, client_addr, local_addr) {
        Ok(dest) => {
            if dest == listen_addr {
                anyhow::bail!("Loop detected: original dest equals listen addr");
            }
            Ok(dest)
        }
        Err(e) => {
            tracing::debug!("DIOCNATLOOK failed: {:#}, trying getsockname fallback", e);

            if local_addr != listen_addr && local_addr.port() != listen_addr.port() {
                Ok(local_addr)
            } else {
                Err(e).context("Could not determine original destination")
            }
        }
    }
}
