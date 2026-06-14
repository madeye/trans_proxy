//! TCP accept loop and per-connection transparent proxy handler.
//!
//! For each accepted connection:
//! 1. Recovers the original destination via [`crate::orig_dest`]
//! 2. Validates the destination (loop detection, listen-addr check)
//! 3. Attempts SNI extraction via [`crate::sni`] (port 443)
//! 4. Falls back to DNS table lookup via [`crate::dns`]
//! 5. Opens an upstream tunnel (HTTP CONNECT or SOCKS5) via [`crate::tunnel`]
//! 6. Relays data bidirectionally between client and upstream proxy
//!
//! Handles both forwarded LAN traffic and locally-originated traffic
//! (when `--local-traffic` is enabled).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration, Sleep};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::dns::DnsTable;
use crate::orig_dest::{get_original_dest, NatHandle};
use crate::sni::extract_sni;
use crate::tunnel::connect_via_proxy;

/// Maximum time to wait for the client's TLS ClientHello before proceeding
/// without SNI (a silent client must not park the task forever).
const SNI_TIMEOUT: Duration = Duration::from_secs(3);

/// Pause before retrying after a failed `accept()` (EMFILE, ECONNABORTED, ...)
/// so the loop doesn't spin while the condition persists.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Per-direction relay buffer size (tokio's 8 KB default costs ~8x more
/// syscalls per MB on bulk transfers).
const RELAY_BUF_SIZE: usize = 64 * 1024;

/// After one side of the relay reaches EOF, the remaining direction has this
/// long to flush buffered data before the connection is forcibly closed.
/// Prevents CLOSE-WAIT / FIN-WAIT-2 fd leaks when the upstream proxy doesn't
/// close its side of the tunnel in a timely manner.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Run the transparent proxy accept loop.
pub async fn run(config: Config, dns_table: DnsTable) -> Result<()> {
    let nat_handle = NatHandle::open()?;
    #[cfg(target_os = "macos")]
    info!("Opened /dev/pf for NAT lookups");
    #[cfg(target_os = "linux")]
    info!("NAT handle ready (SO_ORIGINAL_DST)");

    let listener = TcpListener::bind(config.listen_addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "Failed to listen on {}: port already in use by another process",
                config.listen_addr
            )
        } else {
            anyhow::anyhow!("Failed to listen on {}: {}", config.listen_addr, e)
        }
    })?;
    info!("Listening on {}", config.listen_addr);

    loop {
        // Transient accept errors (fd exhaustion, connections dying in the
        // backlog) must not kill the whole proxy — log, back off, retry.
        let (stream, client_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Accept failed: {}; retrying", e);
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let nat_handle = Arc::clone(&nat_handle);
        let config = config.clone();
        let dns_table = dns_table.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, client_addr, &nat_handle, &config, &dns_table).await
            {
                warn!("{} [failed] {:#}", client_addr, e);
            }
        });
    }
}

/// Handle a single inbound connection: recover original destination, resolve
/// hostname, establish upstream tunnel, and relay data bidirectionally.
async fn handle_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    nat_handle: &NatHandle,
    config: &Config,
    dns_table: &DnsTable,
) -> Result<()> {
    // Disable Nagle's algorithm: a relay's small writes (handshakes, request/
    // response turnarounds) would otherwise stall on delayed ACKs.
    if let Err(e) = inbound.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on inbound socket: {}", e);
    }

    let local_addr = inbound.local_addr()?;

    let orig_dest = get_original_dest(
        nat_handle,
        &inbound,
        client_addr,
        local_addr,
        config.listen_addr,
    )?;

    // Try to extract SNI hostname from TLS ClientHello (port 443 traffic)
    let orig_ip = orig_dest.ip();
    let sni_hostname = if config.sni && orig_dest.port() == 443 {
        // Bounded wait: a client that never sends a ClientHello must not
        // park this task forever — proceed without SNI on timeout.
        match timeout(SNI_TIMEOUT, extract_sni(&inbound)).await {
            Ok(Ok(Some(h))) => {
                debug!("SNI extracted: {}", h);
                Some(h)
            }
            Ok(Ok(None)) => {
                debug!("No SNI in ClientHello (non-TLS or missing extension)");
                None
            }
            Ok(Err(e)) => {
                debug!("SNI extraction failed: {:#}", e);
                None
            }
            Err(_) => {
                debug!("SNI extraction timed out after {:?}", SNI_TIMEOUT);
                None
            }
        }
    } else {
        None
    };

    let hostname = sni_hostname.or_else(|| {
        let h = dns_table.lookup(&orig_ip);
        if let Some(ref name) = h {
            debug!("DNS table lookup: {} -> {}", orig_ip, name);
        }
        h
    });

    let dest_display = match &hostname {
        Some(h) => format!("{}({}:{})", h, orig_ip, orig_dest.port()),
        None => format!("{}:{}", orig_ip, orig_dest.port()),
    };
    info!("{} -> {} [connecting]", client_addr, dest_display);

    #[cfg(target_os = "linux")]
    let fwmark = if config.local_traffic {
        Some(config.fwmark)
    } else {
        None
    };
    let (mut outbound, leftover) = connect_via_proxy(
        &config.upstream_proxy,
        orig_dest,
        hostname.as_deref(),
        #[cfg(target_os = "linux")]
        fwmark,
        #[cfg(target_os = "macos")]
        config.local_traffic,
    )
    .await?;
    debug!("{} -> {} [tunnel established]", client_addr, dest_display);

    if let Err(e) = outbound.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on outbound socket: {}", e);
    }

    // Deliver any payload bytes the upstream coalesced with its CONNECT
    // response (server-speaks-first protocols) before starting the relay
    if !leftover.is_empty() {
        inbound.write_all(&leftover).await?;
    }

    let (client_bytes, server_bytes) = relay_with_shutdown(
        &mut inbound,
        &mut outbound,
        RELAY_BUF_SIZE,
        SHUTDOWN_GRACE_PERIOD,
    )
    .await?;
    info!(
        "{} -> {} [closed] tx={} rx={}",
        client_addr, dest_display, client_bytes, server_bytes
    );

    Ok(())
}

/// Bidirectional relay with graceful shutdown.
///
/// When either side reaches EOF, the other side's write half is shut down.
/// If the remaining direction doesn't complete within
/// [`SHUTDOWN_GRACE_PERIOD`], the connection is forcibly closed to prevent
/// CLOSE-WAIT / FIN-WAIT-2 fd leaks.
async fn relay_with_shutdown(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
    buf_size: usize,
    grace_period: Duration,
) -> io::Result<(u64, u64)> {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let mut client_bytes = 0u64;
    let mut server_bytes = 0u64;
    let mut client_eof = false;
    let mut server_eof = false;

    let mut cbuf = vec![0u8; buf_size];
    let mut sbuf = vec![0u8; buf_size];
    let mut grace_timer: Option<std::pin::Pin<Box<Sleep>>> = None;

    loop {
        if client_eof && server_eof {
            break;
        }

        tokio::select! {
            // Client -> Upstream
            result = ri.read(&mut cbuf), if !client_eof => {
                match result? {
                    0 => {
                        client_eof = true;
                        if !server_eof && grace_timer.is_none() {
                            grace_timer = Some(Box::pin(tokio::time::sleep(grace_period)));
                        }
                        let _ = wo.shutdown().await;
                    }
                    n => {
                        wo.write_all(&cbuf[..n]).await?;
                        client_bytes += n as u64;
                    }
                }
            }
            // Upstream -> Client
            result = ro.read(&mut sbuf), if !server_eof => {
                match result? {
                    0 => {
                        server_eof = true;
                        if !client_eof && grace_timer.is_none() {
                            grace_timer = Some(Box::pin(tokio::time::sleep(grace_period)));
                        }
                        let _ = wi.shutdown().await;
                    }
                    n => {
                        wi.write_all(&sbuf[..n]).await?;
                        server_bytes += n as u64;
                    }
                }
            }
            // Grace period: one side closed, the other hasn't finished flushing
            _ = async {
                if let Some(timer) = grace_timer.as_mut() {
                    timer.as_mut().await;
                }
            }, if grace_timer.is_some() && !(client_eof && server_eof) => {
                if !client_eof {
                    let _ = wo.shutdown().await;
                    client_eof = true;
                }
                if !server_eof {
                    let _ = wi.shutdown().await;
                    server_eof = true;
                }
            }
        }
    }

    Ok((client_bytes, server_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_relay_grace_period_is_absolute_after_half_close() {
        let (mut inbound_peer, mut inbound) = tcp_pair().await;
        let (mut outbound_peer, mut outbound) = tcp_pair().await;

        inbound_peer.shutdown().await.unwrap();

        let writer = tokio::spawn(async move {
            let chunk = vec![b'x'; 1024];
            loop {
                if outbound_peer.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let started = Instant::now();
        let result =
            relay_with_shutdown(&mut inbound, &mut outbound, 1024, Duration::from_millis(50))
                .await
                .unwrap();

        assert_eq!(result.0, 0);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "relay grace period was extended by continued upstream data"
        );

        drop(inbound);
        drop(outbound);
        let _ = writer.await;
    }
}
