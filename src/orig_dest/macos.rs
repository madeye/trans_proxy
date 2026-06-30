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

/// Port/SPI union matching `union pf_state_xport` from `net/pfvar.h`.
///
/// The kernel defines this as:
/// ```c
/// union pf_state_xport {
///     u_int16_t port;
///     u_int16_t call_id;
///     u_int32_t spi;
/// };
/// ```
///
/// Total size: 4 bytes (aligned to u32 due to the `spi` member).
/// Using bare `u16` for ports would make this 2 bytes, producing
/// a wrong struct size (76 instead of 84) and a wrong ioctl number.
#[repr(C)]
#[derive(Clone, Copy)]
union PfStateXport {
    port: u16,
    _call_id: u16,
    _spi: u32,
}

impl Default for PfStateXport {
    fn default() -> Self {
        Self { _spi: 0 }
    }
}

/// Matches `struct pfioc_natlook` from macOS `net/pfvar.h`.
///
/// Total size: 84 bytes. Verified with `offsetof()` against macOS 14 (Sonoma)
/// xnu kernel headers.
///
/// Field layout:
///   saddr        @  0  (16 bytes, struct pf_addr)
///   daddr        @ 16  (16 bytes)
///   rsaddr       @ 32  (16 bytes)
///   rdaddr       @ 48  (16 bytes)
///   sxport       @ 64  ( 4 bytes, union pf_state_xport)
///   dxport       @ 68  ( 4 bytes)
///   rsxport      @ 72  ( 4 bytes)
///   rdxport      @ 76  ( 4 bytes)
///   af           @ 80  ( 1 byte, sa_family_t)
///   proto        @ 81  ( 1 byte)
///   proto_variant @ 82 ( 1 byte)
///   direction    @ 83  ( 1 byte)
#[repr(C)]
#[derive(Clone, Copy)]
struct PfiocNatlook {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sxport: PfStateXport,
    dxport: PfStateXport,
    rsxport: PfStateXport,
    rdxport: PfStateXport,
    af: u8,
    proto: u8,
    proto_variant: u8,
    direction: u8,
}

// Compile-time assertion: struct must be exactly 84 bytes to match the kernel.
const _: () = assert!(std::mem::size_of::<PfiocNatlook>() == 84);

impl Default for PfiocNatlook {
    fn default() -> Self {
        // Safety: all-zeros is valid for this packed C struct
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
    nl.sxport = PfStateXport {
        port: src_port.to_be(),
    };
    nl.daddr.addr = dst_octets;
    nl.dxport = PfStateXport {
        port: dst_port.to_be(),
    };

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

    // Safety: we only ever write the `port` variant into xport unions
    let port = u16::from_be(unsafe { nl.rdxport.port });

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
            tracing::warn!("DIOCNATLOOK failed: {:#}, trying getsockname fallback", e);

            if local_addr != listen_addr && local_addr.port() != listen_addr.port() {
                Ok(local_addr)
            } else {
                Err(e).context("Could not determine original destination")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_kernel() {
        assert_eq!(std::mem::size_of::<PfAddr>(), 16);
        assert_eq!(std::mem::size_of::<PfStateXport>(), 4);
        assert_eq!(std::mem::size_of::<PfiocNatlook>(), 84);
    }

    #[test]
    fn field_offsets_match_kernel() {
        // Verified against macOS 14 xnu `net/pfvar.h`:
        //   saddr @0, daddr @16, rsaddr @32, rdaddr @48,
        //   sxport @64, dxport @68, rsxport @72, rdxport @76,
        //   af @80, proto @81, proto_variant @82, direction @83
        assert_eq!(std::mem::offset_of!(PfiocNatlook, saddr), 0);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, daddr), 16);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, rsaddr), 32);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, rdaddr), 48);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, sxport), 64);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, dxport), 68);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, rsxport), 72);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, rdxport), 76);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, af), 80);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, proto), 81);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, proto_variant), 82);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, direction), 83);
    }

    #[test]
    fn ioctl_number_matches_expected() {
        // DIOCNATLOOK = _IOWR('D', 23, struct pfioc_natlook)
        // With 84-byte struct: 0xC0000000 | (84 << 16) | ('D' << 8) | 23
        //                    = 0xC0000000 | 0x00540000 | 0x4400      | 0x17
        //                    = 0xC0544417
        assert_eq!(DIOCNATLOOK, 0xC0544417);
    }

    #[test]
    fn ioctl_number_not_old_wrong_value() {
        // Before this fix, port fields were bare u16 (2 bytes each) instead of
        // union pf_state_xport (4 bytes each). That produced a 76-byte struct
        // and ioctl number 0xC04C4417, which the kernel rejects with ENOTTY.
        let wrong_ioctl: libc::c_ulong = 0xC0000000 | (76u64 << 16) | (0x44 << 8) | 23;
        assert_eq!(wrong_ioctl, 0xC04C4417);
        assert_ne!(DIOCNATLOOK, wrong_ioctl);
    }

    #[test]
    fn pf_state_xport_alignment() {
        assert_eq!(std::mem::align_of::<PfStateXport>(), 4);
        assert_eq!(std::mem::size_of::<PfStateXport>(), 4);
    }

    #[test]
    fn port_union_round_trip() {
        let xport = PfStateXport {
            port: 443u16.to_be(),
        };
        let recovered = unsafe { xport.port };
        assert_eq!(u16::from_be(recovered), 443);
    }

    #[test]
    fn zero_initialized_default() {
        let nl = PfiocNatlook::default();
        let bytes: [u8; 84] = unsafe { std::mem::transmute::<PfiocNatlook, [u8; 84]>(nl) };
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
