//! Minimal HTTP CONNECT proxy server for e2e testing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::fwmark;

pub struct HttpConnectServer {
    listener: TcpListener,
    pub connection_count: Arc<AtomicU64>,
}

impl HttpConnectServer {
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
                if let Err(e) = handle_connect(stream, count).await {
                    tracing::warn!("http_connect handler error: {e:#}");
                }
            });
        }
    }
}

async fn handle_connect(mut stream: tokio::net::TcpStream, count: Arc<AtomicU64>) -> Result<()> {
    let mark = fwmark::fwmark_from_env();
    // Read request until \r\n\r\n
    let mut buf = vec![0u8; 8192];
    let mut filled = 0;

    loop {
        if filled >= buf.len() {
            bail!("request too large");
        }
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            bail!("connection closed before headers complete");
        }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_str = std::str::from_utf8(&buf[..filled]).context("invalid UTF-8")?;
    let first_line = header_str.lines().next().context("empty request")?;

    // Parse "CONNECT host:port HTTP/1.1"
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        bail!("not a CONNECT request: {first_line}");
    }
    let target = parts[1];

    // Connect to destination (with fwmark to avoid nftables redirect loop)
    let target_addr: std::net::SocketAddr = target
        .parse()
        .or_else(|_| {
            // Try resolving as host:port
            use std::net::ToSocketAddrs;
            target
                .to_socket_addrs()
                .map(|mut addrs| addrs.next().unwrap())
        })
        .context("invalid target address")?;
    let mut dest = fwmark::connect_marked(target_addr, mark).await?;

    // Send 200 response
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;

    count.fetch_add(1, Ordering::Relaxed);

    // Relay
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut dest).await;
    Ok(())
}
