use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
    pub dns: bool,
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
            Some(config.upstream_proxy.addr)
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
            dns: config.dns,
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
            "--dns",
            "--interface",
            "eth0",
        ]);
        let fw = FirewallConfig::from_config(&config);
        assert_eq!(fw.interface, "eth0");
        assert_eq!(fw.proxy_port, 8443);
        assert!(fw.fwmark.is_none());
        assert!(fw.upstream_addr.is_none());
        assert!(fw.ports.is_none());
        assert!(fw.dns);
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
