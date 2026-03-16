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
//! - [`daemon`] — Unix double-fork daemonization with PID file management
//! - [`service`] — macOS launchd service installation and removal
//! - [`orig_dest`] — Original destination recovery using `DIOCNATLOOK` ioctl
//! - [`sni`] — TLS ClientHello SNI extraction
//! - [`dns`] — DNS forwarder on gateway interface port 53 (UDP and DoH upstream)
//! - [`tunnel`] — HTTP CONNECT tunnel establishment
//! - [`proxy`] — TCP accept loop and per-connection handler
//!
//! ## Usage
//!
//! ```bash
//! # Foreground with DNS on interface en0 (port 53)
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns
//!
//! # Daemon mode
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns -d
//!
//! # Install as a launchd service
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns --install
//! ```

mod config;
mod daemon;
mod dns;
mod orig_dest;
mod proxy;
mod service;
mod sni;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::dns::DnsTable;

fn main() -> Result<()> {
    let config = Config::parse();

    // Handle service install/uninstall before anything else
    if config.uninstall {
        return service::uninstall();
    }
    if config.install {
        // Collect the proxy-relevant args (skip the binary name)
        let args: Vec<String> = std::env::args().skip(1).collect();
        return service::install(&args);
    }

    // Daemonize before starting the async runtime
    if config.daemon {
        daemon::daemonize(&config.pid_file)?;
    }

    // Set up logging — write to file in daemon mode, stderr otherwise
    let filter = EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let log_file = config.log_file.clone().or_else(|| {
        if config.daemon {
            Some(std::path::PathBuf::from("/var/log/trans_proxy.log"))
        } else {
            None
        }
    });

    if let Some(ref path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open log file {}: {}", path.display(), e))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .init();
    }

    info!("Log level: {}", config.log_level);

    if config.daemon {
        info!("Daemonized, PID file: {}", config.pid_file.display());
    }

    // Build and run the tokio runtime
    let pid_file = config.pid_file.clone();
    let is_daemon = config.daemon;

    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let dns_table = DnsTable::new();

        if let Some(dns_listen) = config.resolve_dns_listen() {
            let table = dns_table.clone();
            let upstream = config.dns_upstream.clone();
            tokio::spawn(async move {
                if let Err(e) = dns::run(dns_listen, upstream, table).await {
                    tracing::error!("DNS forwarder failed: {:#}", e);
                }
            });
            info!("DNS forwarder started on {}", dns_listen);
        }

        proxy::run(config, dns_table).await
    });

    // Cleanup PID file
    if is_daemon {
        daemon::remove_pid_file(&pid_file);
    }

    result
}
