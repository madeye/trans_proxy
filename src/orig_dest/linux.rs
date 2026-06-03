//! Original destination recovery for nftables redirect on Linux.
//!
//! When nftables `redirect` rewrites a packet's destination, the original
//! target can be recovered using `getsockopt(SO_ORIGINAL_DST)` on the
//! accepted socket fd. IPv6 uses `IP6T_SO_ORIGINAL_DST` on `SOL_IPV6`.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::net::TcpStream;

const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// NAT handle for Linux. No shared resource needed -- SO_ORIGINAL_DST
/// works directly on each accepted socket.
pub struct NatHandle;

impl NatHandle {
    /// No-op on Linux. Returns Ok for API compatibility.
    pub fn open() -> Result<Arc<Self>> {
        Ok(Arc::new(Self))
    }
}

/// Retrieve the original IPv4 destination address via SO_ORIGINAL_DST.
fn get_original_dest_v4(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt(SO_ORIGINAL_DST) failed");
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Retrieve the original IPv6 destination address via IP6T_SO_ORIGINAL_DST.
fn get_original_dest_v6(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void,
            &mut len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .context("getsockopt(IP6T_SO_ORIGINAL_DST) failed");
    }

    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);

    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip,
        port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )))
}

/// Determine original destination for a connection using SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST.
pub fn get_original_dest(
    _nat: &NatHandle,
    stream: &TcpStream,
    _client_addr: SocketAddr,
    local_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<SocketAddr> {
    let is_v4_mapped = match local_addr {
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
        _ => false,
    };

    let dest = if is_v4_mapped {
        get_original_dest_v4(stream)
    } else {
        match local_addr {
            SocketAddr::V6(_) => get_original_dest_v6(stream),
            SocketAddr::V4(_) => get_original_dest_v4(stream),
        }
    }
    .context("Could not determine original destination")?;

    if dest == listen_addr {
        anyhow::bail!("Loop detected: original dest equals listen addr");
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_handle_open() {
        let handle = NatHandle::open();
        assert!(handle.is_ok());
    }

    #[tokio::test]
    async fn test_get_original_dest_non_redirected_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let connect = tokio::net::TcpStream::connect(listen_addr);
        let accept = listener.accept();
        let (_client_stream, accept_result) = tokio::join!(connect, accept);
        let (server_stream, client_addr) = accept_result.unwrap();

        let nat = NatHandle::open().unwrap();
        let local_addr = server_stream.local_addr().unwrap();
        let result = get_original_dest(&nat, &server_stream, client_addr, local_addr, listen_addr);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_original_dest_v4_non_redirected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect = tokio::net::TcpStream::connect(addr);
        let accept = listener.accept();
        let (_client, accept_result) = tokio::join!(connect, accept);
        let (server, _) = accept_result.unwrap();

        let result = get_original_dest_v4(&server);
        if let Ok(SocketAddr::V4(dest)) = result {
            assert_eq!(dest.ip(), &Ipv4Addr::new(127, 0, 0, 1));
        }
    }

    #[tokio::test]
    async fn test_get_original_dest_v6_non_redirected() {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect = tokio::net::TcpStream::connect(addr);
        let accept = listener.accept();
        let (_client, accept_result) = tokio::join!(connect, accept);
        let (server, _) = accept_result.unwrap();

        let result = get_original_dest_v6(&server);
        if let Ok(SocketAddr::V6(dest)) = result {
            assert_eq!(*dest.ip(), Ipv6Addr::LOCALHOST);
        }
    }
}
