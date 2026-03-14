use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::config::Config;
use crate::dns::DnsTable;
use crate::orig_dest::{get_original_dest, PfHandle};
use crate::sni::extract_sni;
use crate::tunnel::connect_via_proxy;

/// Run the transparent proxy accept loop.
pub async fn run(config: Config, dns_table: DnsTable) -> Result<()> {
    let pf = PfHandle::open()?;
    info!("Opened /dev/pf for NAT lookups");

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!("Listening on {}", config.listen_addr);

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let pf = Arc::clone(&pf);
        let config = config.clone();
        let dns_table = dns_table.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, client_addr, &pf, &config, &dns_table).await {
                debug!("Connection from {} failed: {:#}", client_addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    client_addr: SocketAddr,
    pf: &PfHandle,
    config: &Config,
    dns_table: &DnsTable,
) -> Result<()> {
    let local_addr = inbound.local_addr()?;

    let orig_dest = get_original_dest(pf, client_addr, local_addr, config.listen_addr)?;

    // Try to extract SNI hostname from TLS ClientHello (port 443 traffic)
    let sni_hostname = if orig_dest.port() == 443 {
        match extract_sni(&inbound).await {
            Ok(Some(h)) => {
                debug!("SNI extracted: {}", h);
                Some(h)
            }
            Ok(None) => {
                debug!("No SNI in ClientHello (non-TLS or missing extension)");
                None
            }
            Err(e) => {
                debug!("SNI extraction failed: {:#}", e);
                None
            }
        }
    } else {
        None
    };

    // Fallback: look up hostname from DNS table if SNI wasn't available
    let hostname = sni_hostname.or_else(|| {
        let h = dns_table.lookup(orig_dest.ip());
        if let Some(ref name) = h {
            debug!("DNS table lookup: {} -> {}", orig_dest.ip(), name);
        }
        h
    });

    let dest_display = match &hostname {
        Some(h) => format!("{}({}:{})", h, orig_dest.ip(), orig_dest.port()),
        None => format!("{}:{}", orig_dest.ip(), orig_dest.port()),
    };
    debug!("Connection from {} -> {}", client_addr, dest_display);

    let mut outbound = connect_via_proxy(
        config.upstream_proxy,
        orig_dest,
        hostname.as_deref(),
    ).await?;
    debug!("CONNECT tunnel established to {}", dest_display);

    let (client_bytes, server_bytes) = copy_bidirectional(&mut inbound, &mut outbound).await?;
    debug!(
        "Connection {} -> {}:{} closed (client={}, server={})",
        client_addr,
        orig_dest.ip(),
        orig_dest.port(),
        client_bytes,
        server_bytes
    );

    Ok(())
}
