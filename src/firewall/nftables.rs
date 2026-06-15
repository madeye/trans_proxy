use anyhow::Result;
use std::net::{IpAddr, SocketAddr};

use super::{get_interface_ips, run_cmd, run_cmd_ignore, FirewallConfig};

#[derive(Clone, Copy)]
enum NftFamily {
    Ip,
    Ip6,
}

pub fn setup(config: &FirewallConfig) -> Result<()> {
    // Remove existing tables for idempotent setup
    run_cmd_ignore("nft", &["delete", "table", "ip", "trans_proxy"]);
    run_cmd_ignore("nft", &["delete", "table", "ip6", "trans_proxy"]);

    println!("Enabling IP forwarding...");
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=1"])
        .status();

    let addrs = get_interface_ips(&config.interface);

    // --- IPv4 ---
    println!(
        "Adding nftables IPv4 NAT redirect rules on {} -> port {}...",
        config.interface, config.proxy_port
    );
    run_cmd("nft", &["add", "table", "ip", "trans_proxy"])?;
    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            "trans_proxy",
            "prerouting",
            "{ type nat hook prerouting priority -100 ; }",
        ],
    )?;

    let port_str = config.proxy_port.to_string();
    let iface = &config.interface;

    // DNS interception — must be added before the per-port / catch-all TCP
    // redirect rules below: nftables NAT chains match in rule order and
    // redirect/dnat verdicts are terminal, so a later TCP/53 dnat would
    // never match.
    if let Some((dns_ip, dns_port)) = config.dns_target_v4(addrs.ipv4) {
        let dns_target = format!("{dns_ip}:{dns_port}");
        println!("Adding DNS interception rules (UDP+TCP port 53 -> {dns_target})...");
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "udp",
                "dport",
                "53",
                "dnat",
                "to",
                &dns_target,
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "tcp",
                "dport",
                "53",
                "dnat",
                "to",
                &dns_target,
            ],
        )?;
    }

    if let Some(ref ports) = config.ports {
        for p in ports {
            let ps = p.to_string();
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip",
                    "trans_proxy",
                    "prerouting",
                    "iifname",
                    iface,
                    "tcp",
                    "dport",
                    &ps,
                    "redirect",
                    "to",
                    &format!(":{port_str}"),
                ],
            )?;
        }
    } else {
        // Bypass SSH to interface IP to prevent lockout
        if let Some(ip4) = addrs.ipv4 {
            let ip_str = ip4.to_string();
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip",
                    "trans_proxy",
                    "prerouting",
                    "iifname",
                    iface,
                    "ip",
                    "daddr",
                    &ip_str,
                    "tcp",
                    "dport",
                    "22",
                    "return",
                ],
            )?;
        }
        // Never transparent-proxy traffic addressed to the gateway itself
        // (e.g. a LAN device reaching a service bound to one of the Pi's own
        // addresses). `fib daddr type local` matches any local address, so it
        // is robust to rotating dynamic addresses and must precede the
        // catch-all redirect below.
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "fib",
                "daddr",
                "type",
                "local",
                "return",
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "meta",
                "l4proto",
                "tcp",
                "redirect",
                "to",
                &format!(":{port_str}"),
            ],
        )?;
    }

    // OUTPUT chain for local traffic interception
    if let Some(fwmark) = config.fwmark {
        let mark_str = fwmark.to_string();
        println!("Adding IPv4 OUTPUT chain for local traffic (fwmark={mark_str})...");
        run_cmd(
            "nft",
            &[
                "add",
                "chain",
                "ip",
                "trans_proxy",
                "output",
                "{ type nat hook output priority -100 ; }",
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "output",
                "meta",
                "mark",
                &mark_str,
                "return",
            ],
        )?;

        if let Some(upstream) = config.upstream_addr {
            if let Some(args) = upstream_output_exclusion_args(NftFamily::Ip, upstream) {
                println!("  Excluding upstream proxy destination {upstream}...");
                run_nft_args(&args)?;
            }
        }

        // Do not redirect locally-originated connections that are already
        // addressed to this host; otherwise --local-traffic breaks local
        // services such as 127.0.0.1:<port> or the gateway's own LAN IPs.
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "output",
                "fib",
                "daddr",
                "type",
                "local",
                "return",
            ],
        )?;

        if let Some(ref ports) = config.ports {
            for p in ports {
                let ps = p.to_string();
                run_cmd(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "ip",
                        "trans_proxy",
                        "output",
                        "tcp",
                        "dport",
                        &ps,
                        "redirect",
                        "to",
                        &format!(":{port_str}"),
                    ],
                )?;
            }
        } else {
            if let Some(ip4) = addrs.ipv4 {
                let ip_str = ip4.to_string();
                run_cmd(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "ip",
                        "trans_proxy",
                        "output",
                        "ip",
                        "daddr",
                        &ip_str,
                        "tcp",
                        "dport",
                        "22",
                        "return",
                    ],
                )?;
            }
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip",
                    "trans_proxy",
                    "output",
                    "meta",
                    "l4proto",
                    "tcp",
                    "redirect",
                    "to",
                    &format!(":{port_str}"),
                ],
            )?;
        }
    }

    // Drop forwarded QUIC / HTTP-3 so it can't bypass the TCP-only proxy.
    setup_quic_block(config, NftFamily::Ip)?;

    // --- IPv6 (best-effort) ---
    if let Err(e) = setup_ipv6(config, &addrs) {
        println!("Warning: IPv6 NAT redirect setup failed ({e:#}), skipping.");
    }

    println!("Done. Firewall rules configured.");
    Ok(())
}

fn setup_ipv6(config: &FirewallConfig, addrs: &super::InterfaceAddrs) -> Result<()> {
    let port_str = config.proxy_port.to_string();
    let iface = &config.interface;

    println!(
        "Adding nftables IPv6 NAT redirect rules on {} -> port {}...",
        iface, config.proxy_port
    );
    run_cmd("nft", &["add", "table", "ip6", "trans_proxy"])?;
    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip6",
            "trans_proxy",
            "prerouting",
            "{ type nat hook prerouting priority -100 ; }",
        ],
    )?;

    // DNS interception (IPv6) — must be added before the per-port / catch-all
    // TCP redirect rules below (NAT verdicts are terminal, rules match in order).
    if let Some((dns_ip, dns_port)) = config.dns_target_v6(addrs.ipv6) {
        // nft requires brackets around an IPv6 address with a port
        let dns_target = format!("[{dns_ip}]:{dns_port}");
        println!("Adding IPv6 DNS interception rules (UDP+TCP port 53 -> {dns_target})...");
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "udp",
                "dport",
                "53",
                "dnat",
                "to",
                &dns_target,
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "tcp",
                "dport",
                "53",
                "dnat",
                "to",
                &dns_target,
            ],
        )?;
    }

    if let Some(ref ports) = config.ports {
        for p in ports {
            let ps = p.to_string();
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip6",
                    "trans_proxy",
                    "prerouting",
                    "iifname",
                    iface,
                    "tcp",
                    "dport",
                    &ps,
                    "redirect",
                    "to",
                    &format!(":{port_str}"),
                ],
            )?;
        }
    } else {
        if let Some(ip6) = addrs.ipv6 {
            let ip_str = ip6.to_string();
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip6",
                    "trans_proxy",
                    "prerouting",
                    "iifname",
                    iface,
                    "ip6",
                    "daddr",
                    &ip_str,
                    "tcp",
                    "dport",
                    "22",
                    "return",
                ],
            )?;
        }
        // Never transparent-proxy traffic addressed to the gateway itself.
        // `fib daddr type local` matches any of the Pi's own addresses, which
        // is essential for IPv6 where dynamic addresses rotate; must precede
        // the catch-all redirect below.
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "fib",
                "daddr",
                "type",
                "local",
                "return",
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "prerouting",
                "iifname",
                iface,
                "meta",
                "l4proto",
                "tcp",
                "redirect",
                "to",
                &format!(":{port_str}"),
            ],
        )?;
    }

    // OUTPUT chain for local traffic (IPv6)
    if let Some(fwmark) = config.fwmark {
        let mark_str = fwmark.to_string();
        println!("Adding IPv6 OUTPUT chain for local traffic (fwmark={mark_str})...");
        run_cmd(
            "nft",
            &[
                "add",
                "chain",
                "ip6",
                "trans_proxy",
                "output",
                "{ type nat hook output priority -100 ; }",
            ],
        )?;
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "output",
                "meta",
                "mark",
                &mark_str,
                "return",
            ],
        )?;

        if let Some(upstream) = config.upstream_addr {
            if let Some(args) = upstream_output_exclusion_args(NftFamily::Ip6, upstream) {
                println!("  Excluding upstream proxy destination {upstream}...");
                run_nft_args(&args)?;
            }
        }

        // Do not redirect locally-originated connections that are already
        // addressed to this host; otherwise --local-traffic breaks local
        // services such as ::1:<port> or the gateway's own LAN IPs.
        run_cmd(
            "nft",
            &[
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "output",
                "fib",
                "daddr",
                "type",
                "local",
                "return",
            ],
        )?;

        if let Some(ref ports) = config.ports {
            for p in ports {
                let ps = p.to_string();
                run_cmd(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "ip6",
                        "trans_proxy",
                        "output",
                        "tcp",
                        "dport",
                        &ps,
                        "redirect",
                        "to",
                        &format!(":{port_str}"),
                    ],
                )?;
            }
        } else {
            if let Some(ip6) = addrs.ipv6 {
                let ip_str = ip6.to_string();
                run_cmd(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "ip6",
                        "trans_proxy",
                        "output",
                        "ip6",
                        "daddr",
                        &ip_str,
                        "tcp",
                        "dport",
                        "22",
                        "return",
                    ],
                )?;
            }
            run_cmd(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip6",
                    "trans_proxy",
                    "output",
                    "meta",
                    "l4proto",
                    "tcp",
                    "redirect",
                    "to",
                    &format!(":{port_str}"),
                ],
            )?;
        }
    }

    // Drop forwarded QUIC / HTTP-3 (IPv6) so it can't bypass the proxy.
    setup_quic_block(config, NftFamily::Ip6)?;

    Ok(())
}

impl NftFamily {
    fn table(self) -> &'static str {
        match self {
            NftFamily::Ip => "ip",
            NftFamily::Ip6 => "ip6",
        }
    }
}

/// Drop QUIC / HTTP-3 (UDP) destined for the proxied ports so it cannot bypass
/// the TCP-only transparent proxy.
///
/// QUIC is dropped (not redirected): the proxy speaks only TCP, so the goal is
/// to make UDP 443 unreachable, which causes browsers to fall back to TCP
/// (HTTP/1.1 / HTTP/2) — the path that is actually proxied.
///
/// - `forward` hook drops QUIC arriving from LAN clients (the gateway case).
/// - `output` hook drops QUIC originated by the gateway itself, but only when
///   `--local-traffic` is enabled (signalled by `fwmark`), mirroring the
///   existing TCP redirect scope.
///
/// Uses dedicated `filter` chains so a `drop` verdict is reliable; a `drop` in
/// the `nat` chains would only see the first packet of a flow.
fn setup_quic_block(config: &FirewallConfig, family: NftFamily) -> Result<()> {
    let ports = config.quic_block_ports();
    if ports.is_empty() {
        return Ok(());
    }
    let table = family.table();
    let iface = &config.interface;

    let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    println!(
        "Dropping forwarded QUIC/HTTP-3 (UDP {}) so it can't bypass the proxy...",
        port_list.join(",")
    );

    run_cmd(
        "nft",
        &[
            "add",
            "chain",
            table,
            "trans_proxy",
            "quic_forward",
            "{ type filter hook forward priority 0 ; }",
        ],
    )?;
    for port in &ports {
        run_nft_args(&quic_drop_rule_args(
            family,
            "quic_forward",
            "iifname",
            iface,
            *port,
        ))?;
    }

    // Gateway-originated QUIC: only intercepted alongside other local traffic.
    if config.fwmark.is_some() {
        run_cmd(
            "nft",
            &[
                "add",
                "chain",
                table,
                "trans_proxy",
                "quic_output",
                "{ type filter hook output priority 0 ; }",
            ],
        )?;
        for port in &ports {
            run_nft_args(&quic_drop_rule_args(
                family,
                "quic_output",
                "oifname",
                iface,
                *port,
            ))?;
        }
    }

    Ok(())
}

/// Build the `nft add rule` args for a single QUIC drop rule.
///
/// `dir` is the interface-match keyword: `iifname` (forward hook, LAN ingress)
/// or `oifname` (output hook, gateway egress).
fn quic_drop_rule_args(
    family: NftFamily,
    chain: &str,
    dir: &str,
    iface: &str,
    port: u16,
) -> Vec<String> {
    vec![
        "add".to_string(),
        "rule".to_string(),
        family.table().to_string(),
        "trans_proxy".to_string(),
        chain.to_string(),
        dir.to_string(),
        iface.to_string(),
        "udp".to_string(),
        "dport".to_string(),
        port.to_string(),
        "drop".to_string(),
    ]
}

fn upstream_output_exclusion_args(family: NftFamily, upstream: SocketAddr) -> Option<Vec<String>> {
    let (table_family, addr_keyword) = match (family, upstream.ip()) {
        (NftFamily::Ip, IpAddr::V4(_)) => ("ip", "ip"),
        (NftFamily::Ip6, IpAddr::V6(_)) => ("ip6", "ip6"),
        _ => return None,
    };

    Some(vec![
        "add".to_string(),
        "rule".to_string(),
        table_family.to_string(),
        "trans_proxy".to_string(),
        "output".to_string(),
        addr_keyword.to_string(),
        "daddr".to_string(),
        upstream.ip().to_string(),
        "tcp".to_string(),
        "dport".to_string(),
        upstream.port().to_string(),
        "return".to_string(),
    ])
}

fn run_nft_args(args: &[String]) -> Result<()> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cmd("nft", &refs)
}

pub fn teardown() -> Result<()> {
    println!("Removing nftables trans_proxy tables...");
    run_cmd_ignore("nft", &["delete", "table", "ip", "trans_proxy"]);
    run_cmd_ignore("nft", &["delete", "table", "ip6", "trans_proxy"]);

    println!("Disabling IP forwarding...");
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=0"])?;
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=0"])
        .status();

    println!("Done.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{quic_drop_rule_args, upstream_output_exclusion_args, NftFamily};

    #[test]
    fn builds_ipv4_quic_forward_drop_rule() {
        let args = quic_drop_rule_args(NftFamily::Ip, "quic_forward", "iifname", "eth0", 443);
        assert_eq!(
            args,
            [
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "quic_forward",
                "iifname",
                "eth0",
                "udp",
                "dport",
                "443",
                "drop"
            ]
        );
    }

    #[test]
    fn builds_ipv6_quic_output_drop_rule() {
        let args = quic_drop_rule_args(NftFamily::Ip6, "quic_output", "oifname", "eth0", 8443);
        assert_eq!(
            args,
            [
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "quic_output",
                "oifname",
                "eth0",
                "udp",
                "dport",
                "8443",
                "drop"
            ]
        );
    }

    #[test]
    fn builds_ipv4_upstream_exclusion_for_ipv4_table() {
        let args =
            upstream_output_exclusion_args(NftFamily::Ip, "192.0.2.10:1080".parse().unwrap())
                .unwrap();

        assert_eq!(
            args,
            [
                "add",
                "rule",
                "ip",
                "trans_proxy",
                "output",
                "ip",
                "daddr",
                "192.0.2.10",
                "tcp",
                "dport",
                "1080",
                "return"
            ]
        );
    }

    #[test]
    fn builds_ipv6_upstream_exclusion_for_ipv6_table() {
        let args =
            upstream_output_exclusion_args(NftFamily::Ip6, "[2001:db8::10]:1080".parse().unwrap())
                .unwrap();

        assert_eq!(
            args,
            [
                "add",
                "rule",
                "ip6",
                "trans_proxy",
                "output",
                "ip6",
                "daddr",
                "2001:db8::10",
                "tcp",
                "dport",
                "1080",
                "return"
            ]
        );
    }

    #[test]
    fn skips_upstream_exclusion_for_mismatched_address_family() {
        assert!(upstream_output_exclusion_args(
            NftFamily::Ip,
            "[2001:db8::10]:1080".parse().unwrap(),
        )
        .is_none());
        assert!(
            upstream_output_exclusion_args(NftFamily::Ip6, "192.0.2.10:1080".parse().unwrap(),)
                .is_none()
        );
    }
}
