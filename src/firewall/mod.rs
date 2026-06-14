use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;

use crate::config::Config;

#[cfg(target_os = "macos")]
mod pf;
#[cfg(target_os = "macos")]
pub use pf::{setup, teardown};

#[cfg(target_os = "linux")]
mod nftables;
#[cfg(target_os = "linux")]
pub use nftables::{setup, teardown};

pub struct InterfaceAddrs {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

pub struct FirewallConfig {
    pub interface: String,
    pub proxy_port: u16,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fwmark: Option<u32>,
    pub upstream_addr: Option<SocketAddr>,
    pub ports: Option<Vec<u16>>,
    /// Resolved DNS forwarder listen address. `None` disables DNS interception.
    pub dns_listen: Option<SocketAddr>,
}

impl FirewallConfig {
    pub fn from_config(config: &Config) -> Self {
        let proxy_port = config.listen_addr.port();

        let fwmark = if config.local_traffic {
            Some(config.fwmark)
        } else {
            None
        };

        let upstream_addr = if config.local_traffic {
            config.upstream_proxy.as_ref().map(|p| p.addr)
        } else {
            None
        };

        let ports = config.ports.as_ref().map(|p| p.0.clone());

        FirewallConfig {
            interface: config.interface.clone(),
            proxy_port,
            fwmark,
            upstream_addr,
            ports,
            dns_listen: config.resolve_dns_listen(),
        }
    }

    /// IPv4 dnat/rdr target for intercepted DNS.
    ///
    /// Uses the resolved listen address when it is a specific IPv4 address;
    /// falls back to the detected interface IPv4 (with the configured port)
    /// when the forwarder binds a wildcard address. Returns `None` when the
    /// forwarder cannot receive IPv4 traffic (bound to a specific IPv6
    /// address) or no target IP is available.
    pub(crate) fn dns_target_v4(&self, iface_v4: Option<Ipv4Addr>) -> Option<(Ipv4Addr, u16)> {
        let listen = self.dns_listen?;
        match listen.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => Some((ip, listen.port())),
            // 0.0.0.0 binds all IPv4; :: usually accepts IPv4-mapped traffic too
            IpAddr::V4(_) => iface_v4.map(|ip| (ip, listen.port())),
            IpAddr::V6(ip) if ip.is_unspecified() => iface_v4.map(|ip| (ip, listen.port())),
            IpAddr::V6(_) => None,
        }
    }

    /// IPv6 dnat/rdr target for intercepted DNS.
    ///
    /// Uses the resolved listen address when it is a specific IPv6 address;
    /// falls back to the detected interface IPv6 when the forwarder binds the
    /// IPv6 wildcard. Returns `None` for IPv4 binds, which cannot receive
    /// IPv6 traffic — emitting a rule would blackhole LAN IPv6 DNS.
    pub(crate) fn dns_target_v6(&self, iface_v6: Option<Ipv6Addr>) -> Option<(Ipv6Addr, u16)> {
        let listen = self.dns_listen?;
        match listen.ip() {
            IpAddr::V6(ip) if !ip.is_unspecified() => Some((ip, listen.port())),
            IpAddr::V6(_) => iface_v6.map(|ip| (ip, listen.port())),
            IpAddr::V4(_) => None,
        }
    }
}

pub fn get_interface_ips(name: &str) -> InterfaceAddrs {
    use std::ffi::CString;

    let ifname = match CString::new(name) {
        Ok(n) => n,
        Err(_) => {
            return InterfaceAddrs {
                ipv4: None,
                ipv6: None,
            }
        }
    };

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return InterfaceAddrs {
                ipv4: None,
                ipv6: None,
            };
        }

        let mut cursor = ifaddrs;
        let mut ipv4 = None;
        let mut ipv6 = None;

        while !cursor.is_null() {
            let ifa = &*cursor;
            let ifa_name = std::ffi::CStr::from_ptr(ifa.ifa_name);

            if ifa_name == ifname.as_c_str() && !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if sa.sa_family as libc::c_int == libc::AF_INET && ipv4.is_none() {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    ipv4 = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                } else if sa.sa_family as libc::c_int == libc::AF_INET6 && ipv6.is_none() {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    // Skip loopback and link-local addresses
                    if !ip.is_loopback() && (ip.segments()[0] & 0xfe80) != 0xfe80 {
                        ipv6 = Some(ip);
                    }
                }
            }

            cursor = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
        InterfaceAddrs { ipv4, ipv6 }
    }
}

pub(crate) fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {cmd}"))?;
    if !status.success() {
        bail!(
            "{cmd} {} failed (exit code: {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn run_cmd_ignore(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_interface_ips_loopback() {
        #[cfg(target_os = "macos")]
        let addrs = get_interface_ips("lo0");
        #[cfg(target_os = "linux")]
        let addrs = get_interface_ips("lo");

        assert_eq!(addrs.ipv4, Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_get_interface_ips_nonexistent() {
        let addrs = get_interface_ips("nonexistent_iface_xyz");
        assert_eq!(addrs.ipv4, None);
        assert_eq!(addrs.ipv6, None);
    }

    #[test]
    fn test_firewall_config_from_config_basic() {
        use clap::Parser;
        let config = Config::parse_from([
            "trans_proxy",
            "--upstream-proxy",
            "127.0.0.1:1082",
            "--interface",
            "eth0",
        ]);
        let fw = FirewallConfig::from_config(&config);
        assert_eq!(fw.interface, "eth0");
        assert_eq!(fw.proxy_port, 8443);
        assert!(fw.fwmark.is_none());
        assert!(fw.upstream_addr.is_none());
        assert!(fw.ports.is_none());
        assert!(fw.dns_listen.is_none());
    }

    #[test]
    fn test_firewall_config_uses_resolved_dns_listen() {
        use clap::Parser;
        let config = Config::parse_from([
            "trans_proxy",
            "--upstream-proxy",
            "127.0.0.1:1082",
            "--dns",
            "--dns-listen",
            "192.168.1.1:5353",
        ]);
        let fw = FirewallConfig::from_config(&config);
        assert_eq!(fw.dns_listen, Some("192.168.1.1:5353".parse().unwrap()));
    }

    fn fw_with_dns_listen(listen: Option<&str>) -> FirewallConfig {
        FirewallConfig {
            interface: "eth0".to_string(),
            proxy_port: 8443,
            fwmark: None,
            upstream_addr: None,
            ports: None,
            dns_listen: listen.map(|s| s.parse().unwrap()),
        }
    }

    #[test]
    fn test_dns_target_v4_specific_listen_addr() {
        let fw = fw_with_dns_listen(Some("192.168.1.1:5353"));
        let iface_v4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            fw.dns_target_v4(iface_v4),
            Some((Ipv4Addr::new(192, 168, 1, 1), 5353))
        );
        // A specific IPv4 bind cannot receive IPv6 traffic
        assert_eq!(
            fw.dns_target_v6(Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            None
        );
    }

    #[test]
    fn test_dns_target_v4_unspecified_falls_back_to_interface() {
        let fw = fw_with_dns_listen(Some("0.0.0.0:53"));
        let iface_v4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            fw.dns_target_v4(iface_v4),
            Some((Ipv4Addr::new(10, 0, 0, 1), 53))
        );
        assert_eq!(fw.dns_target_v4(None), None);
    }

    #[test]
    fn test_dns_target_v6_specific_listen_addr() {
        let fw = fw_with_dns_listen(Some("[2001:db8::1]:5353"));
        let iface_v6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            fw.dns_target_v6(iface_v6),
            Some((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 5353))
        );
    }

    #[test]
    fn test_dns_target_v6_unspecified_dual_stack() {
        // [::]:53 accepts both families: v6 falls back to the interface IPv6,
        // v4 falls back to the interface IPv4 (IPv4-mapped traffic).
        let fw = fw_with_dns_listen(Some("[::]:53"));
        let iface_v4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        let iface_v6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            fw.dns_target_v6(iface_v6),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 53))
        );
        assert_eq!(
            fw.dns_target_v4(iface_v4),
            Some((Ipv4Addr::new(10, 0, 0, 1), 53))
        );
    }

    #[test]
    fn test_dns_target_none_when_dns_disabled() {
        let fw = fw_with_dns_listen(None);
        assert_eq!(fw.dns_target_v4(Some(Ipv4Addr::new(10, 0, 0, 1))), None);
        assert_eq!(
            fw.dns_target_v6(Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
            None
        );
    }

    #[test]
    fn test_firewall_config_from_config_local_traffic() {
        use clap::Parser;
        let config = Config::parse_from([
            "trans_proxy",
            "--upstream-proxy",
            "127.0.0.1:1082",
            "--local-traffic",
            "--fwmark",
            "42",
        ]);
        let fw = FirewallConfig::from_config(&config);
        assert_eq!(fw.fwmark, Some(42));
        assert_eq!(fw.upstream_addr, Some("127.0.0.1:1082".parse().unwrap()));
    }

    #[test]
    fn test_firewall_config_from_config_with_ports() {
        use clap::Parser;
        let config = Config::parse_from([
            "trans_proxy",
            "--upstream-proxy",
            "127.0.0.1:1082",
            "--ports",
            "80,443",
        ]);
        let fw = FirewallConfig::from_config(&config);
        assert_eq!(fw.ports, Some(vec![80, 443]));
    }
}
