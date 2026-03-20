//! CLI configuration for trans_proxy.
//!
//! All settings are provided via command-line flags — no config files.
//! Uses [`clap`] derive macros for parsing and help generation.

use clap::Parser;
use std::fmt;
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
            s.parse::<SocketAddr>().map(DnsUpstream::Udp).map_err(|e| {
                format!(
                    "invalid DNS upstream '{}': expected socket address or https:// URL: {}",
                    s, e
                )
            })
        }
    }
}

/// SOCKS5 authentication method.
///
/// Used with [`ProxyProtocol::Socks5`] to specify how to authenticate
/// with the upstream SOCKS5 proxy server.
#[derive(Debug, Clone)]
pub enum ProxyAuth {
    /// No authentication (SOCKS5 method `0x00`).
    None,
    /// Username/password authentication per [RFC 1929](https://tools.ietf.org/html/rfc1929).
    UsernamePassword {
        /// SOCKS5 username (max 255 bytes).
        username: String,
        /// SOCKS5 password (max 255 bytes).
        password: String,
    },
}

/// Upstream proxy protocol selection.
///
/// Determines which handshake is performed after the TCP connection
/// to the upstream proxy is established.
#[derive(Debug, Clone)]
pub enum ProxyProtocol {
    /// HTTP CONNECT tunnel ([RFC 7231 &sect;4.3.6](https://tools.ietf.org/html/rfc7231#section-4.3.6)).
    HttpConnect,
    /// SOCKS5 tunnel ([RFC 1928](https://tools.ietf.org/html/rfc1928)) with the given auth method.
    Socks5(ProxyAuth),
}

/// Parsed upstream proxy configuration.
///
/// Combines a [`ProxyProtocol`] with a socket address. Parsed from the
/// `--upstream-proxy` CLI flag via the [`FromStr`](std::str::FromStr) impl.
///
/// # Accepted formats
///
/// | Input | Protocol |
/// |-------|----------|
/// | `host:port` | HTTP CONNECT |
/// | `http://host:port` | HTTP CONNECT |
/// | `socks5://host:port` | SOCKS5 (no auth) |
/// | `socks5://user:pass@host:port` | SOCKS5 (username/password) |
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    /// The proxy protocol and authentication method.
    pub protocol: ProxyProtocol,
    /// The proxy server's socket address.
    pub addr: SocketAddr,
}

impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.protocol {
            ProxyProtocol::HttpConnect => write!(f, "http://{}", self.addr),
            ProxyProtocol::Socks5(ProxyAuth::None) => write!(f, "socks5://{}", self.addr),
            ProxyProtocol::Socks5(ProxyAuth::UsernamePassword { username, .. }) => {
                write!(f, "socks5://{}@{}", username, self.addr)
            }
        }
    }
}

impl std::str::FromStr for UpstreamProxy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("socks5://") {
            // socks5://[user:pass@]host:port
            let (auth, addr_str) = if let Some(at_pos) = rest.rfind('@') {
                let userinfo = &rest[..at_pos];
                let addr_part = &rest[at_pos + 1..];
                let (user, pass) = userinfo.split_once(':').ok_or_else(|| {
                    format!("invalid socks5 userinfo '{}': expected user:pass", userinfo)
                })?;
                (
                    ProxyAuth::UsernamePassword {
                        username: user.to_string(),
                        password: pass.to_string(),
                    },
                    addr_part,
                )
            } else {
                (ProxyAuth::None, rest)
            };
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e| format!("invalid socks5 address '{}': {}", addr_str, e))?;
            Ok(UpstreamProxy {
                protocol: ProxyProtocol::Socks5(auth),
                addr,
            })
        } else {
            // http://host:port or bare host:port
            let addr_str = s.strip_prefix("http://").unwrap_or(s);
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e| format!("invalid proxy address '{}': {}", addr_str, e))?;
            Ok(UpstreamProxy {
                protocol: ProxyProtocol::HttpConnect,
                addr,
            })
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(target_os = "macos")]
const DEFAULT_INTERFACE: &str = "en0";
#[cfg(target_os = "linux")]
const DEFAULT_INTERFACE: &str = "eth0";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "trans_proxy",
    about = "Transparent proxy with upstream HTTP CONNECT and SOCKS5 support"
)]
pub struct Config {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub listen_addr: SocketAddr,

    /// Upstream proxy: host:port or http://host:port for HTTP CONNECT,
    /// socks5://host:port or socks5://user:pass@host:port for SOCKS5
    #[arg(long)]
    pub upstream_proxy: UpstreamProxy,

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
    #[arg(long, default_value = DEFAULT_INTERFACE)]
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

    /// Intercept locally-originated traffic (OUTPUT chain on Linux, route-to on macOS)
    #[arg(long)]
    pub local_traffic: bool,

    /// System user for loop prevention when --local-traffic is enabled.
    /// Traffic from this user is excluded from interception.
    #[arg(long, default_value = "trans_proxy")]
    pub proxy_user: String,

    /// Install as a system service (launchd on macOS, systemd on Linux)
    #[arg(long)]
    pub install: bool,

    /// Uninstall the system service
    #[arg(long)]
    pub uninstall: bool,
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
            let ip = get_interface_ip(&self.interface).unwrap_or_else(|| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_interface() {
        #[cfg(target_os = "macos")]
        assert_eq!(DEFAULT_INTERFACE, "en0");
        #[cfg(target_os = "linux")]
        assert_eq!(DEFAULT_INTERFACE, "eth0");
    }

    #[test]
    fn test_dns_upstream_parse_https() {
        let upstream: DnsUpstream = "https://1.1.1.1/dns-query".parse().unwrap();
        match upstream {
            DnsUpstream::Https(url) => assert_eq!(url, "https://1.1.1.1/dns-query"),
            _ => panic!("expected Https variant"),
        }
    }

    #[test]
    fn test_dns_upstream_parse_udp() {
        let upstream: DnsUpstream = "8.8.8.8:53".parse().unwrap();
        match upstream {
            DnsUpstream::Udp(addr) => assert_eq!(addr.to_string(), "8.8.8.8:53"),
            _ => panic!("expected Udp variant"),
        }
    }

    #[test]
    fn test_dns_upstream_parse_invalid() {
        let result: Result<DnsUpstream, _> = "not-valid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_upstream_display() {
        let udp: DnsUpstream = "8.8.8.8:53".parse().unwrap();
        assert_eq!(format!("{}", udp), "8.8.8.8:53");

        let https: DnsUpstream = "https://1.1.1.1/dns-query".parse().unwrap();
        assert_eq!(format!("{}", https), "https://1.1.1.1/dns-query");
    }

    #[test]
    fn test_upstream_proxy_parse_bare_addr() {
        let proxy: UpstreamProxy = "127.0.0.1:1082".parse().unwrap();
        assert!(matches!(proxy.protocol, ProxyProtocol::HttpConnect));
        assert_eq!(proxy.addr.to_string(), "127.0.0.1:1082");
    }

    #[test]
    fn test_upstream_proxy_parse_http_scheme() {
        let proxy: UpstreamProxy = "http://127.0.0.1:1082".parse().unwrap();
        assert!(matches!(proxy.protocol, ProxyProtocol::HttpConnect));
        assert_eq!(proxy.addr.to_string(), "127.0.0.1:1082");
    }

    #[test]
    fn test_upstream_proxy_parse_socks5() {
        let proxy: UpstreamProxy = "socks5://127.0.0.1:1080".parse().unwrap();
        assert!(matches!(
            proxy.protocol,
            ProxyProtocol::Socks5(ProxyAuth::None)
        ));
        assert_eq!(proxy.addr.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn test_upstream_proxy_parse_socks5_auth() {
        let proxy: UpstreamProxy = "socks5://myuser:mypass@127.0.0.1:1080".parse().unwrap();
        match &proxy.protocol {
            ProxyProtocol::Socks5(ProxyAuth::UsernamePassword { username, password }) => {
                assert_eq!(username, "myuser");
                assert_eq!(password, "mypass");
            }
            _ => panic!("expected Socks5 with UsernamePassword auth"),
        }
        assert_eq!(proxy.addr.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn test_upstream_proxy_parse_invalid() {
        let result: Result<UpstreamProxy, _> = "not-valid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_upstream_proxy_display() {
        let http: UpstreamProxy = "127.0.0.1:1082".parse().unwrap();
        assert_eq!(format!("{}", http), "http://127.0.0.1:1082");

        let socks: UpstreamProxy = "socks5://127.0.0.1:1080".parse().unwrap();
        assert_eq!(format!("{}", socks), "socks5://127.0.0.1:1080");

        let socks_auth: UpstreamProxy = "socks5://user:pass@127.0.0.1:1080".parse().unwrap();
        assert_eq!(format!("{}", socks_auth), "socks5://user@127.0.0.1:1080");
    }

    #[test]
    fn test_get_interface_ip_loopback() {
        // lo0 on macOS, lo on Linux — test whichever exists
        #[cfg(target_os = "macos")]
        let result = get_interface_ip("lo0");
        #[cfg(target_os = "linux")]
        let result = get_interface_ip("lo");

        assert_eq!(result, Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_get_interface_ip_nonexistent() {
        let result = get_interface_ip("nonexistent_iface_xyz");
        assert_eq!(result, None);
    }

    #[test]
    fn test_local_traffic_flags() {
        let config = Config::parse_from([
            "trans_proxy",
            "--upstream-proxy",
            "127.0.0.1:1082",
            "--local-traffic",
            "--proxy-user",
            "myuser",
        ]);
        assert!(config.local_traffic);
        assert_eq!(config.proxy_user, "myuser");
    }

    #[test]
    fn test_local_traffic_defaults() {
        let config = Config::parse_from(["trans_proxy", "--upstream-proxy", "127.0.0.1:1082"]);
        assert!(!config.local_traffic);
        assert_eq!(config.proxy_user, "trans_proxy");
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
                if sa.sa_family as libc::c_int == libc::AF_INET {
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
