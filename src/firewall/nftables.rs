use anyhow::Result;

use super::{get_interface_ips, run_cmd, run_cmd_ignore, FirewallConfig};

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
            let up_ip = upstream.ip().to_string();
            let up_port = upstream.port().to_string();
            println!("  Excluding upstream proxy destination {upstream}...");
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
                    &up_ip,
                    "tcp",
                    "dport",
                    &up_port,
                    "return",
                ],
            )?;
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
            let up_ip = upstream.ip().to_string();
            let up_port = upstream.port().to_string();
            let _ = std::process::Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "ip6",
                    "trans_proxy",
                    "output",
                    "ip6",
                    "daddr",
                    &up_ip,
                    "tcp",
                    "dport",
                    &up_port,
                    "return",
                ])
                .status();
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

    Ok(())
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
