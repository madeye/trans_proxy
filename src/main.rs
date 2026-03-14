mod config;
mod dns;
mod orig_dest;
mod proxy;
mod sni;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::dns::DnsTable;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&config.log_level)
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let dns_table = DnsTable::new();

    // Start DNS forwarder if configured
    if let Some(dns_listen) = config.dns_listen {
        let table = dns_table.clone();
        let upstream = config.dns_upstream;
        tokio::spawn(async move {
            if let Err(e) = dns::run(dns_listen, upstream, table).await {
                tracing::error!("DNS forwarder failed: {:#}", e);
            }
        });
        info!("DNS forwarder started on {}", dns_listen);
    }

    proxy::run(config, dns_table).await
}
