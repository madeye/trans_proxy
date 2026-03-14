//! # trans_proxy
//!
//! A transparent proxy for macOS that intercepts TCP traffic redirected by
//! [`pf(4)`](https://man.openbsd.org/pf) and forwards it through an upstream
//! HTTP CONNECT proxy.
//!
//! ## Architecture
//!
//! ```text
//! [Client devices] ──gateway──> [macOS pf rdr] ──> [trans_proxy :8443]
//!                                                       │
//!                                                       ▼
//!                                                  [Upstream HTTP CONNECT proxy]
//!                                                       │
//!                                                       ▼
//!                                                  [Original destination]
//! ```
//!
//! ## Modules
//!
//! - [`config`] — CLI argument parsing via clap
//! - [`orig_dest`] — Original destination recovery using `DIOCNATLOOK` ioctl
//! - [`sni`] — TLS ClientHello SNI extraction
//! - [`dns`] — Local DNS forwarder with IP→domain mapping
//! - [`tunnel`] — HTTP CONNECT tunnel establishment
//! - [`proxy`] — TCP accept loop and per-connection handler
//!
//! ## Usage
//!
//! ```bash
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 \
//!     --dns-listen 0.0.0.0:5353
//! ```

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
