//! Simple HTTP destination server for e2e testing.
//!
//! Accepts TCP connections, reads HTTP request headers, responds with a known body.

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const RESPONSE_BODY: &str = "trans_proxy_e2e_ok\n";

pub struct HttpDestServer {
    listener: TcpListener,
}

impl HttpDestServer {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub async fn run(self) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = async {
                    // Read until \r\n\r\n
                    let mut buf = vec![0u8; 4096];
                    let mut filled = 0;
                    loop {
                        if filled >= buf.len() {
                            bail!("request too large");
                        }
                        let n = stream.read(&mut buf[filled..]).await?;
                        if n == 0 {
                            bail!("connection closed");
                        }
                        filled += n;
                        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        RESPONSE_BODY.len(),
                        RESPONSE_BODY
                    );
                    stream.write_all(response.as_bytes()).await?;
                    stream.shutdown().await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    tracing::warn!("http_dest handler error: {e:#}");
                }
            });
        }
    }
}
