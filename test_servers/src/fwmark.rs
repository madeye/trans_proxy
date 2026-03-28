//! Outbound TCP connect with optional SO_MARK (Linux fwmark).
//!
//! When running under nftables OUTPUT chain redirection, the test servers'
//! outbound connections must also carry the fwmark to avoid being redirected
//! back into trans_proxy (creating a loop).

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpStream;

/// Read the fwmark value from the `FWMARK` environment variable.
/// Returns `None` if unset or not on Linux.
pub fn fwmark_from_env() -> Option<u32> {
    std::env::var("FWMARK").ok()?.parse().ok()
}

/// Connect to `addr`, setting SO_MARK if `fwmark` is provided (Linux only).
pub async fn connect_marked(addr: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let _ = &fwmark; // used on linux only
    #[cfg(target_os = "linux")]
    if let Some(mark) = fwmark {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };

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
            return Err(std::io::Error::last_os_error()).context("failed to set SO_MARK");
        }

        return socket.connect(addr).await.context("connect failed");
    }

    TcpStream::connect(addr).await.context("connect failed")
}
