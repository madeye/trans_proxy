use anyhow::{bail, Context, Result};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use super::{get_interface_ips, run_cmd, FirewallConfig};

const ANCHOR: &str = "trans_proxy";
const PF_CONF: &str = "/etc/pf.conf";

pub fn setup(config: &FirewallConfig) -> Result<()> {
    println!("==> Enabling IP forwarding");
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;
    run_cmd("sysctl", &["-w", "net.inet6.ip6.forwarding=1"])?;

    let addrs = get_interface_ips(&config.interface);
    let rules = build_rules(config, &addrs);

    println!("==> Loading pf anchor '{ANCHOR}'");

    // Load rules into anchor via stdin
    load_pf_rules(&rules)?;

    // pf does not evaluate unreferenced anchors: the main ruleset must
    // contain rdr-anchor/anchor references for our rules to take effect.
    println!("==> Referencing anchor '{ANCHOR}' from the main pf ruleset");
    if anchor_referenced() {
        println!("    Already referenced, leaving main ruleset untouched");
    } else {
        ensure_anchor_referenced()?;
    }

    println!("==> Enabling pf");
    let _ = Command::new("pfctl").arg("-E").status();

    println!("==> Verifying anchor rules");
    let _ = Command::new("pfctl")
        .args(["-a", ANCHOR, "-s", "rules"])
        .status();

    println!();
    println!("Done.");
    if let Some(ip4) = addrs.ipv4 {
        println!("  Gateway IP:  {ip4} ({})", config.interface);
    }
    if let Some(ref ports) = config.ports {
        let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        println!(
            "  Ports:       {} -> 127.0.0.1:{}",
            port_list.join(","),
            config.proxy_port
        );
    } else {
        println!("  Ports:       all TCP -> 127.0.0.1:{}", config.proxy_port);
    }
    if let Some(upstream) = config.upstream_addr {
        println!("  Upstream:    {upstream} (excluded from interception)");
    }
    if let Some(dns_listen) = config.dns_listen {
        println!(
            "  DNS:         all DNS traffic intercepted -> {}",
            config
                .dns_target_v4(addrs.ipv4)
                .map(|(ip, p)| format!("{ip}:{p}"))
                .unwrap_or_else(|| dns_listen.to_string())
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

fn build_rules(config: &FirewallConfig, addrs: &super::InterfaceAddrs) -> String {
    let iface = &config.interface;
    let port = config.proxy_port;

    // Build port filter clause
    let port_filter = if let Some(ref ports) = config.ports {
        let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        format!(" port {{{}}}", port_list.join(", "))
    } else {
        String::new()
    };

    // DNS interception rules, targeting the resolved forwarder listen address
    let dns_rdr = if config.dns_listen.is_some() {
        let mut rules = String::new();
        if let Some((ip4, dns_port)) = config.dns_target_v4(addrs.ipv4) {
            rules.push_str(&format!(
                "rdr on {iface} inet proto udp from any to any port 53 -> {ip4} port {dns_port}\n\
                 rdr on {iface} inet proto tcp from any to any port 53 -> {ip4} port {dns_port}\n"
            ));
        }
        if let Some((ip6, dns_port)) = config.dns_target_v6(addrs.ipv6) {
            rules.push_str(&format!(
                "rdr on {iface} inet6 proto udp from any to any port 53 -> {ip6} port {dns_port}\n\
                 rdr on {iface} inet6 proto tcp from any to any port 53 -> {ip6} port {dns_port}\n"
            ));
        }
        rules
    } else {
        String::new()
    };

    // Never transparent-proxy traffic addressed to the gateway itself (for
    // example LAN clients reaching SSH or another service on this machine).
    // pf translation rules are evaluated before filter `pass` rules, so this
    // must be a `no rdr` rule and it must precede the broad TCP redirects.
    let mut local_no_rdr = String::new();
    if let Some(ip4) = addrs.ipv4 {
        local_no_rdr.push_str(&format!(
            "no rdr on {iface} inet proto tcp from any to {ip4}{port_filter}\n"
        ));
    }
    if let Some(ip6) = addrs.ipv6 {
        local_no_rdr.push_str(&format!(
            "no rdr on {iface} inet6 proto tcp from any to {ip6}{port_filter}\n"
        ));
    }

    // Build the anchor rules
    if let Some(upstream) = config.upstream_addr {
        let up_ip = upstream.ip();
        let up_port = upstream.port();
        // Exempt the upstream proxy and our own listener from the lo0 rdr
        // below. Without this, a localhost upstream (e.g. 127.0.0.1:1082)
        // would be redirected back into the proxy's listener: the proxy's
        // own tunnel connections and the DoH client loop forever.
        // `no rdr` rules must precede the matching rdr rules.
        let up_af = match up_ip {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        };
        let no_rdr = format!(
            "no rdr on lo0 {up_af} proto tcp from any to {up_ip} port {up_port}\n\
             no rdr on lo0 inet proto tcp from any to any port {port}\n\
             no rdr on lo0 inet6 proto tcp from any to any port {port}\n"
        );
        format!(
            "{no_rdr}{dns_rdr}{local_no_rdr}\
             rdr on {iface} inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on lo0 inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on {iface} inet6 proto tcp from any to any{port_filter} -> ::1 port {port}\n\
             rdr on lo0 inet6 proto tcp from any to any{port_filter} -> ::1 port {port}\n\
             pass out quick on {iface} proto tcp from any to {up_ip} port {up_port}\n\
             pass out on {iface} inet route-to (lo0 127.0.0.1) proto tcp from any to any{port_filter}\n\
             pass out on {iface} inet6 route-to (lo0 ::1) proto tcp from any to any{port_filter}"
        )
    } else {
        format!(
            "{dns_rdr}{local_no_rdr}\
             rdr on {iface} inet proto tcp from any to any{port_filter} -> 127.0.0.1 port {port}\n\
             rdr on {iface} inet6 proto tcp from any to any{port_filter} -> ::1 port {port}"
        )
    }
}

/// Check whether the live main pf ruleset already references our anchor.
///
/// `pfctl -s rules` lists filter rules (where `anchor` references appear)
/// and `pfctl -s nat` lists translation rules (where `rdr-anchor`
/// references appear) — both are required for the anchor to be evaluated.
fn anchor_referenced() -> bool {
    let filter = Command::new("pfctl").args(["-s", "rules"]).output();
    let nat = Command::new("pfctl").args(["-s", "nat"]).output();
    match (filter, nat) {
        (Ok(f), Ok(n)) => {
            String::from_utf8_lossy(&f.stdout).contains(&format!("anchor \"{ANCHOR}\""))
                && String::from_utf8_lossy(&n.stdout).contains(&format!("rdr-anchor \"{ANCHOR}\""))
        }
        _ => false,
    }
}

/// Load the main pf ruleset with `rdr-anchor`/`anchor` references appended.
///
/// pf does not evaluate unreferenced anchors, and the stock macOS
/// /etc/pf.conf only references the com.apple anchors. Mirroring the e2e
/// harness, this takes the system pf.conf content, appends references to our
/// anchor (only if not already present in the file), and loads the combined
/// ruleset via stdin. /etc/pf.conf itself is never modified on disk, so
/// teardown restores the pristine ruleset with `pfctl -f /etc/pf.conf`.
/// The anchor's own rules (loaded separately into the anchor) are unaffected
/// by reloading the main ruleset.
fn ensure_anchor_referenced() -> Result<()> {
    let mut full_conf = std::fs::read_to_string(PF_CONF).unwrap_or_default();
    if !full_conf.contains(&format!("rdr-anchor \"{ANCHOR}\"")) {
        full_conf.push_str(&format!("\nrdr-anchor \"{ANCHOR}\"\n"));
    }
    if !full_conf.contains(&format!("anchor \"{ANCHOR}\"")) {
        full_conf.push_str(&format!("anchor \"{ANCHOR}\"\n"));
    }

    let mut child = Command::new("pfctl")
        .args(["-f", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn pfctl to load main ruleset")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(full_conf.as_bytes())
            .context("Failed to write pf.conf to pfctl stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for pfctl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("pfctl failed to load main ruleset with anchor references: {stderr}");
    }
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

    // Restore the pristine system ruleset, removing the rdr-anchor/anchor
    // references that setup() appended (setup never modifies the file itself).
    println!("==> Restoring main pf ruleset from {PF_CONF}");
    let _ = Command::new("pfctl").args(["-f", PF_CONF]).status();

    println!("==> Disabling IP forwarding");
    run_cmd("sysctl", &["-w", "net.inet.ip.forwarding=0"])?;
    let _ = Command::new("sysctl")
        .args(["-w", "net.inet6.ip6.forwarding=0"])
        .status();

    println!("Done. pf anchor '{ANCHOR}' has been flushed.");
    println!(
        "Note: pf itself was left enabled. Run 'sudo pfctl -d' to disable pf entirely if desired."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn config(ports: Option<Vec<u16>>, dns_listen: Option<SocketAddr>) -> FirewallConfig {
        FirewallConfig {
            interface: "en0".to_string(),
            proxy_port: 8443,
            fwmark: None,
            upstream_addr: None,
            ports,
            dns_listen,
        }
    }

    fn addrs() -> super::super::InterfaceAddrs {
        super::super::InterfaceAddrs {
            ipv4: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ipv6: Some(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1)),
        }
    }

    #[test]
    fn test_gateway_local_no_rdr_precedes_catch_all_redirects() {
        let rules = build_rules(&config(None, None), &addrs());

        let no_rdr_v4 = rules
            .find("no rdr on en0 inet proto tcp from any to 192.168.1.1\n")
            .unwrap();
        let rdr_v4 = rules
            .find("rdr on en0 inet proto tcp from any to any -> 127.0.0.1 port 8443")
            .unwrap();
        let no_rdr_v6 = rules
            .find("no rdr on en0 inet6 proto tcp from any to 2001:db8:1:2::1\n")
            .unwrap();
        let rdr_v6 = rules
            .find("rdr on en0 inet6 proto tcp from any to any -> ::1 port 8443")
            .unwrap();

        assert!(no_rdr_v4 < rdr_v4);
        assert!(no_rdr_v6 < rdr_v6);
        assert!(!rules.contains("pass in quick on en0"));
    }

    #[test]
    fn test_dns_redirect_precedes_gateway_local_no_rdr() {
        let rules = build_rules(
            &config(None, Some("192.168.1.1:5353".parse().unwrap())),
            &addrs(),
        );

        let dns_rdr = rules
            .find("rdr on en0 inet proto tcp from any to any port 53 -> 192.168.1.1 port 5353")
            .unwrap();
        let local_no_rdr = rules
            .find("no rdr on en0 inet proto tcp from any to 192.168.1.1\n")
            .unwrap();

        assert!(dns_rdr < local_no_rdr);
    }

    #[test]
    fn test_gateway_local_no_rdr_respects_port_filter() {
        let rules = build_rules(&config(Some(vec![80, 443]), None), &addrs());

        assert!(
            rules.contains("no rdr on en0 inet proto tcp from any to 192.168.1.1 port {80, 443}")
        );
        assert!(rules
            .contains("no rdr on en0 inet6 proto tcp from any to 2001:db8:1:2::1 port {80, 443}"));
    }
}
