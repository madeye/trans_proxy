# Configurable Port Redirection

## Summary

Change trans_proxy from hardcoded port 80/443 redirection to all-TCP-by-default, with an optional `--ports` flag to restrict which ports are redirected.

## Motivation

The proxy's core (NAT destination recovery, bidirectional relay, HTTP CONNECT / SOCKS5 tunneling) is port-agnostic, but the firewall scripts and setup are hardcoded to ports 80 and 443. Users need to proxy other TCP protocols (e.g., SSH on port 22) without modifying scripts manually.

## Design

### CLI: `--ports` flag

Add to `Config` in `src/config.rs`:

```
--ports <PORTS>  Comma-separated list of ports to redirect (default: all TCP)
```

- Type: `Option<Vec<u16>>` (None = all TCP, Some = specific ports only)
- Example: `--ports 22,80,443`
- When omitted, all TCP traffic is redirected

### Firewall script: `pf_setup.sh` (macOS)

Accept an optional 4th positional argument for ports:

```bash
# $0 <interface> [proxy_port] [proxy_user] [ports]
PORTS="${4:-}"
```

- When `PORTS` is empty: rules use no port filter (all TCP)
  - `rdr on ${IFACE} proto tcp from any to any -> 127.0.0.1 port ${PROXY_PORT}`
- When `PORTS` is set (e.g., `22,80,443`): rules filter by port
  - `rdr on ${IFACE} proto tcp from any to any port {22, 80, 443} -> 127.0.0.1 port ${PROXY_PORT}`
- Same logic applies to the `lo0` rdr rule and `route-to` pass rule in local-traffic mode

### Firewall script: `nftables_setup.sh` (Linux)

Accept an optional 4th positional argument for ports:

- When empty: single rule without `tcp dport` filter
  - `nft add rule ip trans_proxy prerouting iifname "$IFACE" meta l4proto tcp redirect to :"$PORT"`
- When set: one rule per port (current behavior, extended to arbitrary ports)
  - `nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport $p redirect to :"$PORT"`
- Same logic for OUTPUT chain rules in local-traffic mode

### Proxy code (`src/proxy.rs`)

No changes. The proxy already handles any TCP port. SNI extraction remains gated on `orig_dest.port() == 443`.

### Service install

The `--ports` flag value is passed through to the service definition (launchd plist / systemd unit) so the firewall setup scripts receive the correct arguments on service start.

## Files to modify

1. `src/config.rs` -- add `--ports` field to `Config` struct
2. `scripts/pf_setup.sh` -- accept optional ports arg, conditional port filtering
3. `scripts/nftables_setup.sh` -- accept optional ports arg, conditional port filtering
4. `src/service.rs` -- pass ports to firewall scripts (if scripts are invoked from service setup)
5. `README.md` / `README_zh.md` -- document the new flag

## Backward compatibility

Default behavior changes from "ports 80,443 only" to "all TCP". Users who want the old behavior can use `--ports 80,443`.
