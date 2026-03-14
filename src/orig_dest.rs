//! Original destination recovery for pf-redirected connections.
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
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

/// pf address wrapper matching struct pf_addr (union, we only use v4)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfAddr {
    /// union: `[u8; 16]` — we use the first 4 bytes as IPv4
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
const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const PF_OUT: u8 = 1; // We look up outbound NAT translations (rdr rewrites inbound, but state is PF_OUT for reply direction)

/// Handle to /dev/pf for NAT lookups.
pub struct PfHandle {
    fd: RawFd,
}

// The fd is only used for ioctl reads, safe to share across threads.
unsafe impl Send for PfHandle {}
unsafe impl Sync for PfHandle {}

impl PfHandle {
    /// Open /dev/pf. Requires root privileges.
    pub fn open() -> Result<Arc<Self>> {
        let fd = unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to open /dev/pf (are you running as root?)");
        }
        Ok(Arc::new(Self { fd }))
    }
}

impl Drop for PfHandle {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for PfHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Look up the original destination for a redirected connection using DIOCNATLOOK.
///
/// `client_addr`: the source address of the incoming connection
/// `local_addr`: the address the connection arrived on (proxy listen addr after rdr)
pub fn get_original_dest_pf(
    pf: &PfHandle,
    client_addr: SocketAddrV4,
    local_addr: SocketAddrV4,
) -> Result<SocketAddrV4> {
    let mut nl = PfiocNatlook::default();
    nl.af = AF_INET;
    nl.proto = IPPROTO_TCP;
    nl.direction = PF_OUT;

    // Source: the client
    nl.saddr.addr[..4].copy_from_slice(&client_addr.ip().octets());
    nl.sport = client_addr.port().to_be();

    // Destination: what we see (the proxy address after rdr)
    nl.daddr.addr[..4].copy_from_slice(&local_addr.ip().octets());
    nl.dport = local_addr.port().to_be();

    let ret = unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
    if ret < 0 {
        // Try PF_IN direction as fallback
        nl.direction = 0; // PF_IN
        let ret2 =
            unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut nl as *mut PfiocNatlook) };
        if ret2 < 0 {
            return Err(std::io::Error::last_os_error())
                .context("DIOCNATLOOK failed for both PF_OUT and PF_IN");
        }
    }

    let mut ip_bytes = [0u8; 4];
    ip_bytes.copy_from_slice(&nl.rdaddr.addr[..4]);
    let ip = Ipv4Addr::from(ip_bytes);
    let port = u16::from_be(nl.rdport);

    Ok(SocketAddrV4::new(ip, port))
}

/// Determine original destination for a connection.
///
/// Tries DIOCNATLOOK first, falls back to getsockname check.
pub fn get_original_dest(
    pf: &PfHandle,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<SocketAddrV4> {
    let client_v4 = match client_addr {
        SocketAddr::V4(a) => a,
        _ => anyhow::bail!("IPv6 not supported"),
    };
    let local_v4 = match local_addr {
        SocketAddr::V4(a) => a,
        _ => anyhow::bail!("IPv6 not supported"),
    };

    // Try DIOCNATLOOK first
    match get_original_dest_pf(pf, client_v4, local_v4) {
        Ok(dest) => {
            // Loop prevention: if original dest is our own listen address, reject
            let dest_sa = SocketAddr::V4(dest);
            if dest_sa == listen_addr {
                anyhow::bail!("Loop detected: original dest equals listen addr");
            }
            Ok(dest)
        }
        Err(e) => {
            tracing::debug!("DIOCNATLOOK failed: {:#}, trying getsockname fallback", e);

            // Fallback: if local_addr differs from listen_addr, it may be the original dest
            // (works with divert-to rules)
            if local_addr != listen_addr && local_v4.port() != listen_addr.port() {
                Ok(local_v4)
            } else {
                Err(e).context("Could not determine original destination")
            }
        }
    }
}
