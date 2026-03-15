//! CLI configuration for trans_proxy.
//!
//! All settings are provided via command-line flags — no config files.
//! Uses [`clap`] derive macros for parsing and help generation.

use clap::Parser;
use std::net::SocketAddr;

/// Upstream DNS target: either a UDP address or a DoH URL.
#[derive(Debug, Clone)]
pub enum DnsUpstream {
    /// Traditional UDP DNS (e.g., "8.8.8.8:53")
    Udp(SocketAddr),
    /// DNS-over-HTTPS (e.g., "https://1.1.1.1/dns-query")
    Https(String),
}

impl std::fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsUpstream::Udp(addr) => write!(f, "{}", addr),
            DnsUpstream::Https(url) => write!(f, "{}", url),
        }
    }
}

impl std::str::FromStr for DnsUpstream {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("https://") {
            Ok(DnsUpstream::Https(s.to_string()))
        } else {
            s.parse::<SocketAddr>()
                .map(DnsUpstream::Udp)
                .map_err(|e| format!("invalid DNS upstream '{}': expected socket address or https:// URL: {}", s, e))
        }
    }
}

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

    /// Upstream DNS server: address:port for UDP, or https:// URL for DoH
    #[arg(long, default_value = "https://cloudflare-dns.com/dns-query")]
    pub dns_upstream: DnsUpstream,

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
