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

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{copy_bidirectional_with_sizes, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
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

    let (client_bytes, server_bytes) =
        copy_bidirectional_with_sizes(&mut inbound, &mut outbound, RELAY_BUF_SIZE, RELAY_BUF_SIZE)
            .await?;
    info!(
        "{} -> {} [closed] tx={} rx={}",
        client_addr, dest_display, client_bytes, server_bytes
    );

    Ok(())
}
