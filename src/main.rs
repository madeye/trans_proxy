//! # trans_proxy
//!
//! A transparent proxy that intercepts TCP traffic redirected by the OS
//! firewall and forwards it through an upstream HTTP CONNECT or SOCKS5 proxy.
//!
//! Designed to run on a machine acting as a side router (gateway) for other
//! devices on the LAN, with optional interception of locally-originated traffic.
//!
//! ## Platform support
//!
//! - **macOS**: pf `rdr` rules with `DIOCNATLOOK` ioctl for original destination recovery
//! - **Linux**: nftables `redirect` rules with `SO_ORIGINAL_DST` getsockopt
//!
//! ## Architecture
//!
//! ```text
//! [Client devices] ──gateway──> [NAT redirect] ──> [trans_proxy :8443]
//!                                                       │
//!                                                       ▼
//!                                                  [Upstream proxy (HTTP CONNECT / SOCKS5)]
//!                                                       │
//!                                                       ▼
//!                                                  [Original destination]
//! ```
//!
//! ## Key features
//!
//! - **SOCKS5 & HTTP CONNECT** upstream proxy support (with optional auth)
//! - **SNI extraction** from TLS ClientHello for hostname-based routing
//! - **DNS forwarder** with DoH and UDP upstream, building an IP→domain lookup table
//! - **Local traffic interception** via fwmark (Linux) or IP_BOUND_IF (macOS)
//! - **Port-selective redirection** via `--ports` flag
//! - **Daemon mode** and **system service** installation (launchd / systemd)
//! - **End-to-end tested** on both Linux (nftables) and macOS (pf) in CI
//!
//! ## Modules
//!
//! - [`config`] — CLI argument parsing via clap
//! - [`daemon`] — Unix double-fork daemonization with PID file management
//! - [`service`] — System service installation (launchd on macOS, systemd on Linux)
//! - [`orig_dest`] — Original destination recovery (pf on macOS, SO_ORIGINAL_DST on Linux)
//! - [`sni`] — TLS ClientHello SNI extraction
//! - [`dns`] — DNS forwarder on gateway interface port 53 (UDP + TCP listeners, UDP and DoH upstream)
//! - [`tunnel`] — HTTP CONNECT / SOCKS5 tunnel establishment with loop prevention
//! - [`proxy`] — TCP accept loop and per-connection handler
//!
//! ## Usage
//!
//! ```bash
//! # Foreground with DNS
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns
//!
//! # With SOCKS5 upstream
//! sudo trans_proxy --upstream-proxy socks5://127.0.0.1:1080 --dns
//!
//! # Only redirect specific ports
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns --ports 80,443
//!
//! # Intercept local traffic too
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns --local-traffic
//!
//! # Install as a system service
//! sudo trans_proxy --upstream-proxy 127.0.0.1:1082 --dns --install
//! ```

mod config;
mod daemon;
mod dns;
mod firewall;
mod gateway;
mod orig_dest;
mod proxy;
mod service;
mod sni;
mod tunnel;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::dns::DnsTable;

fn main() -> Result<()> {
    let config = Config::parse();

    // Handle service commands before anything else
    if config.uninstall {
        return service::uninstall();
    }
    if config.install {
        // Collect the proxy-relevant args (skip the binary name)
        let args: Vec<String> = std::env::args().skip(1).collect();
        return service::install(&args);
    }
    if config.start {
        return service::start();
    }
    if config.stop {
        return service::stop();
    }
    if config.teardown_firewall {
        return firewall::teardown();
    }
    if config.setup_firewall {
        let fw_config = firewall::FirewallConfig::from_config(&config);
        return firewall::setup(&fw_config);
    }

    // Set up logging — write to file in daemon mode, stderr otherwise
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let log_file = config.log_file.clone().or_else(|| {
        if config.daemon {
            Some(std::path::PathBuf::from("/var/log/trans_proxy.log"))
        } else {
            None
        }
    });

    let log_writer = if let Some(ref path) = log_file {
        Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to open log file {}: {}", path.display(), e)
                })?,
        )
    } else {
        None
    };

    // Daemonize only after startup-only file checks have succeeded. If the log
    // path is invalid, the foreground parent should return an error instead of
    // exiting successfully while the child immediately dies.
    if config.daemon {
        daemon::daemonize(&config.pid_file)?;
    }

    if let Some(file) = log_writer {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
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
        let server = async {
            let dns_table = DnsTable::new();

            let dns_task = if let Some(dns_listen) = config.resolve_dns_listen() {
                let table = dns_table.clone();
                let upstream = config.dns_upstream.clone();
                let upstream_proxy = config
                    .upstream_proxy
                    .clone()
                    .expect("upstream proxy is required when DNS forwarding runs");
                let strip_aaaa = config.dns_strip_aaaa;
                let handle = tokio::spawn(async move {
                    dns::run(dns_listen, upstream, table, &upstream_proxy, strip_aaaa).await
                });
                info!("DNS forwarder started on {}", dns_listen);
                Some(handle)
            } else {
                None
            };

            if config.gateway {
                let iface = config.interface.clone();
                tokio::spawn(async move {
                    if let Err(e) = gateway::run(&iface).await {
                        tracing::error!("Gateway advertisement failed: {:#}", e);
                    }
                });
            }

            // The firewall redirects all LAN port-53 traffic to the DNS forwarder,
            // so a dead forwarder silently blackholes DNS for every client. Treat
            // forwarder exit as fatal so the service manager can restart us (and
            // ExecStopPost / teardown can clean up the firewall rules).
            if let Some(dns_task) = dns_task {
                tokio::select! {
                    res = proxy::run(config, dns_table) => res,
                    res = dns_task => match res {
                        Ok(Ok(())) => Err(anyhow::anyhow!("DNS forwarder exited unexpectedly")),
                        Ok(Err(e)) => Err(e.context("DNS forwarder failed")),
                        Err(e) => Err(anyhow::anyhow!("DNS forwarder task panicked: {e}")),
                    },
                }
            } else {
                proxy::run(config, dns_table).await
            }
        };

        tokio::select! {
            res = server => res,
            res = shutdown_signal() => {
                let signal = res?;
                info!("Received {}, shutting down", signal);
                Ok(())
            }
        }
    });

    // Cleanup PID file
    if is_daemon {
        daemon::remove_pid_file(&pid_file);
    }

    result
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<&'static str> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;

    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res.context("failed to install Ctrl-C handler")?;
            Ok("SIGINT")
        }
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to install Ctrl-C handler")?;
    Ok("SIGINT")
}
