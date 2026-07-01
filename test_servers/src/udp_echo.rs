//! Minimal UDP echo server for e2e testing of the QUIC/HTTP-3 relay path.
//!
//! Whatever datagram it receives, it sends straight back to the sender — the
//! UDP analogue of [`crate::http_dest`]. The gateway e2e drives this through
//! the transparent UDP relay (SOCKS5 UDP ASSOCIATE) to prove that forwarded
//! UDP is genuinely proxied, not dropped.

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

pub struct UdpEchoServer {
    socket: UdpSocket,
}

impl UdpEchoServer {
    pub async fn bind(addr: &str, port: u16) -> Result<Self> {
        let socket = UdpSocket::bind(format!("{addr}:{port}"))
            .await
            .with_context(|| format!("failed to bind UDP echo on {addr}:{port}"))?;
        Ok(Self { socket })
    }

    pub fn port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }

    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            if let Err(e) = self.socket.send_to(&buf[..n], src).await {
                tracing::warn!("udp_echo reply to {src} failed: {e}");
            }
        }
    }
}
