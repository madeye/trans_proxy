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
- Implement a custom `FromStr`-based parser (wrapper type `PortList`) consistent with existing patterns (`DnsUpstream`, `UpstreamProxy`)
- Validation: reject port 0, reject non-numeric values, deduplicate silently

### Firewall script: `pf_setup.sh` (macOS)

Script signature becomes:

```bash
# $0 <interface> [proxy_port] [proxy_user] [ports]
PORTS="${4:-}"
```

Note: `proxy_user` is positional arg 3 (empty string `""` when not using local-traffic mode), and `ports` is always arg 4.

- When `PORTS` is empty: rules use no port filter (all TCP)
  - `rdr on ${IFACE} proto tcp from any to any -> 127.0.0.1 port ${PROXY_PORT}`
- When `PORTS` is set (e.g., `22,80,443`): rules filter by port
  - `rdr on ${IFACE} proto tcp from any to any port {22, 80, 443} -> 127.0.0.1 port ${PROXY_PORT}`
- Same logic applies to the `lo0` rdr rule and `route-to` pass rule in local-traffic mode
- Update the summary echo line (currently hardcoded to "ports 80,443") to reflect actual ports or "all TCP"

### Firewall script: `nftables_setup.sh` (Linux)

Same signature: `$0 <interface> [proxy_port] [proxy_user] [ports]`

- When `PORTS` is empty: single rule without `tcp dport` filter
  - `nft add rule ip trans_proxy prerouting iifname "$IFACE" meta l4proto tcp redirect to :"$PORT"`
- When `PORTS` is set: one rule per port (current behavior, extended to arbitrary ports)
  - `nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport $p redirect to :"$PORT"`
- Same logic for OUTPUT chain rules in local-traffic mode

### Proxy code (`src/proxy.rs`)

No changes. The proxy already handles any TCP port. SNI extraction remains gated on `orig_dest.port() == 443`.

### Service install

- **Linux (`src/service/linux.rs`)**: The `generate_unit` function builds `ExecStartPre` to call `nftables_setup.sh`. Update it to extract `--ports` from args and pass as the 4th positional argument. When `--local-traffic` is active: `nftables_setup.sh <iface> <port> <proxy_user> <ports>`. Without: `nftables_setup.sh <iface> <port> "" <ports>`.
- **macOS (`src/service/macos.rs`)**: The launchd plist only launches the `trans_proxy` binary — it does NOT call `pf_setup.sh`. The `--ports` flag is passed through to the binary via `ProgramArguments` (already handled by `filtered_args`). Users must run `pf_setup.sh` manually with the ports argument. No code changes needed in `macos.rs`.

## Files to modify

1. `src/config.rs` -- add `--ports` field with `PortList` wrapper type and `FromStr` parser
2. `scripts/pf_setup.sh` -- accept optional ports arg (4th positional), conditional port filtering, update echo summary
3. `scripts/nftables_setup.sh` -- accept optional ports arg (4th positional), conditional port filtering
4. `src/service/linux.rs` -- update `generate_unit` to extract and pass `--ports` to `nftables_setup.sh`
5. `README.md` / `README_zh.md` -- document the new flag

## Backward compatibility

**Breaking change**: Default behavior changes from "ports 80,443 only" to "all TCP". Users who previously relied on only ports 80/443 being redirected will now have all TCP traffic redirected. To restore the previous behavior, use `--ports 80,443`.
