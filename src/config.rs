//! CLI configuration for trans_proxy.
//!
//! All settings are provided via command-line flags — no config files.
//! Uses [`clap`] derive macros for parsing and help generation.

use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};

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

fn default_log_level() -> String {
    "info".to_string()
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
    #[arg(long, default_value_t = default_log_level())]
    pub log_level: String,

    /// Enable DNS forwarder on the gateway interface (port 53).
    /// Listens directly on the interface IP for incoming DNS queries from LAN clients.
    #[arg(long)]
    pub dns: bool,

    /// Override DNS listen address (default: auto-detect interface IP, port 53).
    /// Use this to bind to a specific address or port.
    #[arg(long)]
    pub dns_listen: Option<std::net::SocketAddr>,

    /// Upstream DNS server: address:port for UDP, or https:// URL for DoH
    #[arg(long, default_value = "https://cloudflare-dns.com/dns-query")]
    pub dns_upstream: DnsUpstream,

    /// Network interface for DNS binding (e.g., en0). Used with --dns to auto-detect IP.
    #[arg(long, default_value = "en0")]
    pub interface: String,

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

impl Config {
    /// Resolve the DNS listen address.
    /// - If `--dns-listen` is set, use it directly.
    /// - If `--dns` is set, auto-detect the interface IP and bind to port 53.
    /// - Otherwise, DNS is disabled.
    pub fn resolve_dns_listen(&self) -> Option<SocketAddr> {
        if let Some(addr) = self.dns_listen {
            return Some(addr);
        }
        if self.dns {
            let ip = get_interface_ip(&self.interface)
                .unwrap_or_else(|| {
                    eprintln!(
                        "Warning: could not detect IP for interface '{}', using 0.0.0.0",
                        self.interface
                    );
                    Ipv4Addr::UNSPECIFIED
                });
            return Some(SocketAddr::new(ip.into(), 53));
        }
        None
    }
}

/// Get the IPv4 address of a network interface by name.
fn get_interface_ip(name: &str) -> Option<Ipv4Addr> {
    use std::ffi::CString;

    let ifname = CString::new(name).ok()?;

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return None;
        }

        let mut cursor = ifaddrs;
        let mut result = None;

        while !cursor.is_null() {
            let ifa = &*cursor;
            let ifa_name = std::ffi::CStr::from_ptr(ifa.ifa_name);

            if ifa_name == ifname.as_c_str() && !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if sa.sa_family == libc::AF_INET as u8 {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    result = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    break;
                }
            }

            cursor = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
        result
    }
}
