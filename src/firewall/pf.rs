use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

use super::{get_interface_ips, run_cmd, FirewallConfig};

const ANCHOR: &str = "trans_proxy";

pub fn setup(config: &FirewallConfig) -> Result<()> {
    println!("==> Enabling IP forwarding");
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;
    run_cmd("sysctl", &["-w", "net.inet6.ip6.forwarding=1"])?;

    let addrs = get_interface_ips(&config.interface);
    let iface = &config.interface;
    let port = config.proxy_port;

    // Build port filter clause
    let (port_filter, ssh_bypass) = if let Some(ref ports) = config.ports {
        let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let filter = format!(" port {{{}}}", port_list.join(", "));
        (filter, String::new())
    } else {
        let bypass = if let Some(ip4) = addrs.ipv4 {
            format!("pass in quick on {iface} proto tcp from any to {ip4} port 22\n")
        } else {
            String::new()
        };
        (String::new(), bypass)
    };

    // IPv6 SSH bypass
    let ssh6_bypass = if config.ports.is_none() {
        if let Some(ip6) = addrs.ipv6 {
            format!("pass in quick on {iface} inet6 proto tcp from any to {ip6} port 22\n")
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // DNS interception rules
    let dns_rdr = if config.dns {
        let mut rules = String::new();
        if let Some(ip4) = addrs.ipv4 {
            rules.push_str(&format!(
                "rdr on {iface} inet proto udp from any to any port 53 -> {ip4} port 53\n\
                 rdr on {iface} inet proto tcp from any to any port 53 -> {ip4} port 53\n"
            ));
        }
        if let Some(ip6) = addrs.ipv6 {
            rules.push_str(&format!(
                "rdr on {iface} inet6 proto udp from any to any port 53 -> {ip6} port 53\n\
                 rdr on {iface} inet6 proto tcp from any to any port 53 -> {ip6} port 53\n"
            ));
        }
        rules
    } else {
        String::new()
    };

    // Build the anchor rules
    let rules = if let Some(upstream) = config.upstream_addr {
        let up_ip = upstream.ip();
        let up_port = upstream.port();
        format!(
            "{dns_rdr}\
             rdr on {iface} inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on lo0 inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on {iface} inet6 proto tcp from any to any{port_filter} -> ::1 port {port}\n\
             rdr on lo0 inet6 proto tcp from any to any{port_filter} -> ::1 port {port}\n\
             {ssh_bypass}{ssh6_bypass}\
             pass out quick on {iface} proto tcp from any to {up_ip} port {up_port}\n\
             pass out on {iface} inet route-to (lo0 127.0.0.1) proto tcp from any to any{port_filter}\n\
             pass out on {iface} inet6 route-to (lo0 ::1) proto tcp from any to any{port_filter}"
        )
    } else {
        format!(
            "{dns_rdr}\
             rdr on {iface} inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on {iface} inet6 proto tcp from any to any{port_filter} -> ::1 port {port}\n\
             {ssh_bypass}{ssh6_bypass}"
        )
    };

    println!("==> Loading pf anchor '{ANCHOR}'");

    // Check if anchor already exists
    let existing = Command::new("pfctl")
        .args(["-s", "rules"])
        .output()
        .context("Failed to query pf rules")?;
    let existing_rules = String::from_utf8_lossy(&existing.stdout);

    if !existing_rules.contains(&format!("anchor \"{ANCHOR}\"")) {
        println!("    Adding anchor to pf.conf");
        let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
    }

    // Load rules into anchor via stdin
    load_pf_rules(&rules)?;

    println!("==> Enabling pf");
    let _ = Command::new("pfctl").arg("-e").status();

    println!("==> Verifying anchor rules");
    let _ = Command::new("pfctl")
        .args(["-a", ANCHOR, "-s", "rules"])
        .status();

    println!();
    println!("Done.");
    if let Some(ip4) = addrs.ipv4 {
        println!("  Gateway IP:  {ip4} ({iface})");
    }
    if let Some(ref ports) = config.ports {
        let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        println!("  Ports:       {} -> 127.0.0.1:{port}", port_list.join(","));
    } else {
        println!("  Ports:       all TCP -> 127.0.0.1:{port}");
    }
    if let Some(upstream) = config.upstream_addr {
        println!("  Upstream:    {upstream} (excluded from interception)");
    }
    if config.dns {
        println!(
            "  DNS:         all DNS traffic intercepted -> {}:53",
            addrs
                .ipv4
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "<interface-ip>".into())
        );
    }
    println!();
    println!(
        "Configure client devices to use {} as their gateway.",
        addrs
            .ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "this machine".into())
    );

    Ok(())
}

fn load_pf_rules(rules: &str) -> Result<()> {
    let mut child = Command::new("pfctl")
        .args(["-a", ANCHOR, "-f", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn pfctl")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rules.as_bytes())
            .context("Failed to write pf rules to pfctl stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for pfctl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("pfctl failed: {stderr}");
    }
    Ok(())
}

pub fn teardown() -> Result<()> {
    println!("==> Flushing anchor '{ANCHOR}' rules");
    let _ = Command::new("pfctl")
        .args(["-a", ANCHOR, "-F", "all"])
        .status();

    println!("==> Disabling IP forwarding");
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=0"])?;

    println!("Done. pf anchor '{ANCHOR}' has been flushed.");
    println!(
        "Note: pf itself was left enabled. Run 'sudo pfctl -d' to disable pf entirely if desired."
    );

    Ok(())
}
