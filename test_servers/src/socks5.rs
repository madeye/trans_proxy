//! Minimal SOCKS5 proxy server for e2e testing.
//!
//! Supports no-auth CONNECT only. Tracks connection count via a shared atomic.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::fwmark;

pub struct Socks5Server {
    listener: TcpListener,
    pub connection_count: Arc<AtomicU64>,
}

impl Socks5Server {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
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

    // Read CONNECT request: ver(1) + cmd(1) + rsv(1) + atyp(1)
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != 0x05 || req_header[1] != 0x01 {
        bail!("unsupported SOCKS5 command");
    }

    let dest_addr: SocketAddr = match req_header[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            SocketAddr::from((Ipv4Addr::from(addr), port))
        }
        0x03 => {
            // Domain
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
                .context("DNS lookup failed")?
        }
        other => bail!("unsupported ATYP 0x{other:02x}"),
    };

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
