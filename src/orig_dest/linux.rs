//! Original destination recovery for nftables redirect on Linux.
//!
//! When nftables `redirect` rewrites a packet's destination, the original
//! target can be recovered using `getsockopt(SO_ORIGINAL_DST)` on the
//! accepted socket fd.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::net::TcpStream;

/// NAT handle for Linux. No shared resource needed -- SO_ORIGINAL_DST
/// works directly on each accepted socket.
pub struct NatHandle;

impl NatHandle {
    /// No-op on Linux. Returns Ok for API compatibility.
    pub fn open() -> Result<Arc<Self>> {
        Ok(Arc::new(Self))
    }
}

/// Retrieve the original destination address via SO_ORIGINAL_DST.
fn get_original_dest_so(stream: &TcpStream) -> Result<SocketAddrV4> {
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

    Ok(SocketAddrV4::new(ip, port))
}

/// Determine original destination for a connection using SO_ORIGINAL_DST.
pub fn get_original_dest(
    _nat: &NatHandle,
    stream: &TcpStream,
    _client_addr: SocketAddr,
    _local_addr: SocketAddr,
    listen_addr: SocketAddr,
) -> Result<SocketAddrV4> {
    let dest = get_original_dest_so(stream).context("Could not determine original destination")?;

    // Loop prevention: if original dest is our own listen address, reject
    let dest_sa = SocketAddr::V4(dest);
    if dest_sa == listen_addr {
        anyhow::bail!("Loop detected: original dest equals listen addr");
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_handle_open() {
        // NatHandle::open() is a no-op on Linux and should always succeed
        let handle = NatHandle::open();
        assert!(handle.is_ok());
    }

    #[tokio::test]
    async fn test_get_original_dest_non_redirected_socket() {
        // A plain TCP connection (not redirected by nftables) should either:
        // - fail because SO_ORIGINAL_DST has no NAT state, or
        // - return the socket's own address (some kernels), triggering loop detection
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let connect = tokio::net::TcpStream::connect(listen_addr);
        let accept = listener.accept();
        let (_client_stream, accept_result) = tokio::join!(connect, accept);
        let (server_stream, client_addr) = accept_result.unwrap();

        let nat = NatHandle::open().unwrap();
        let local_addr = server_stream.local_addr().unwrap();
        // Pass the actual listen_addr so loop detection triggers if SO_ORIGINAL_DST
        // returns the socket's own address (which happens on some kernels)
        let result = get_original_dest(&nat, &server_stream, client_addr, local_addr, listen_addr);

        // Should fail: either SO_ORIGINAL_DST error or loop detection
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_original_dest_so_non_redirected() {
        // On a non-redirected socket, SO_ORIGINAL_DST may either fail or
        // return the socket's own address depending on the kernel version
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect = tokio::net::TcpStream::connect(addr);
        let accept = listener.accept();
        let (_client, accept_result) = tokio::join!(connect, accept);
        let (server, _) = accept_result.unwrap();

        let result = get_original_dest_so(&server);
        // Either an error or the socket's own address is acceptable
        if let Ok(dest) = result {
            assert_eq!(dest.ip(), &Ipv4Addr::new(127, 0, 0, 1));
        }
    }
}
