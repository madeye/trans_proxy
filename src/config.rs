//! CLI configuration for trans_proxy.
//!
//! All settings are provided via command-line flags — no config files.
//! Uses [`clap`] derive macros for parsing and help generation.

use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug, Clone)]
#[command(name = "trans_proxy", about = "Transparent proxy for macOS pf redirection")]
pub struct Config {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub listen_addr: SocketAddr,

    /// Upstream HTTP CONNECT proxy address (host:port)
    #[arg(long)]
    pub upstream_proxy: SocketAddr,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Enable local DNS forwarder for IP→domain mapping
    #[arg(long)]
    pub dns_listen: Option<std::net::SocketAddr>,

    /// Upstream DNS server to forward queries to (used with --dns-listen)
    #[arg(long, default_value = "8.8.8.8:53")]
    pub dns_upstream: std::net::SocketAddr,

    /// Run as a background daemon
    #[arg(long, short = 'd')]
    pub daemon: bool,

    /// PID file path (used with --daemon)
    #[arg(long, default_value = "/var/run/trans_proxy.pid")]
    pub pid_file: std::path::PathBuf,

    /// Log file path (used with --daemon, defaults to stderr in foreground)
    #[arg(long)]
    pub log_file: Option<std::path::PathBuf>,
}
