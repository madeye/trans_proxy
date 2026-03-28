#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [upstream_proxy] [ports]

Set up macOS pf (packet filter) rules to redirect TCP traffic
through trans_proxy.

Arguments:
  interface       Network interface for redirection (e.g., en0)
  proxy_port      trans_proxy listen port (default: 8443)
  upstream_proxy  Upstream proxy address (ip:port) for destination-based
                  exclusion when intercepting local traffic. Pass "" to skip
                  (no local traffic interception).
  ports           Comma-separated ports to redirect (default: all TCP)

Loop prevention: when upstream_proxy is set, the proxy's outbound connections
are excluded from interception via two mechanisms:
  1. IP_BOUND_IF (set in the proxy binary) binds outbound sockets to lo0
     when the upstream is on localhost, keeping them off the physical interface.
  2. A "pass out quick" pf rule skips traffic destined to the upstream proxy,
     covering remote upstreams and library connections (e.g., DoH via reqwest).

Examples:
  $0 en0                                    # redirect all TCP on en0 to port 8443
  $0 en0 8443 "" 80,443                     # redirect only ports 80,443
  $0 en0 8443 127.0.0.1:1082               # all TCP + local traffic
  $0 en0 8443 127.0.0.1:1082 22,80,443     # ports 22,80,443 + local traffic

Requires root privileges (uses sudo internally).
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [upstream_proxy] [ports]}"
PROXY_PORT="${2:-8443}"
UPSTREAM="${3:-}"
PORTS="${4:-}"
ANCHOR="trans_proxy"

# Validate individual ports in the comma-separated list
if [ -n "$PORTS" ]; then
    IFS=',' read -ra _VALIDATE_PORTS <<< "$PORTS"
    for _vp in "${_VALIDATE_PORTS[@]}"; do
        if ! echo "$_vp" | grep -qE '^[0-9]+$' || [ "$_vp" -lt 1 ] || [ "$_vp" -gt 65535 ]; then
            echo "Error: invalid port '$_vp' in ports list (must be 1-65535)." >&2
            exit 1
        fi
    done
fi

# Validate upstream proxy address
if [ -n "$UPSTREAM" ]; then
    UPSTREAM_IP="${UPSTREAM%:*}"
    UPSTREAM_PORT="${UPSTREAM##*:}"
    if [ -z "$UPSTREAM_IP" ] || [ -z "$UPSTREAM_PORT" ]; then
        echo "Error: invalid upstream proxy address '$UPSTREAM' (expected ip:port)." >&2
        exit 1
    fi
    if ! echo "$UPSTREAM_PORT" | grep -qE '^[0-9]+$' || [ "$UPSTREAM_PORT" -lt 1 ] || [ "$UPSTREAM_PORT" -gt 65535 ]; then
        echo "Error: invalid upstream proxy port '$UPSTREAM_PORT' (must be 1-65535)." >&2
        exit 1
    fi
fi

echo "==> Enabling IP forwarding"
sudo sysctl -w net.inet.ip.forwarding=1

echo "==> Loading pf anchor '${ANCHOR}'"

# Build port filter clause
if [ -n "$PORTS" ]; then
    # Convert comma-separated to pf syntax: {22, 80, 443}
    PORT_LIST=$(echo "$PORTS" | sed 's/,/, /g')
    PORT_FILTER=" port {${PORT_LIST}}"
else
    PORT_FILTER=""
fi

# Build the anchor rules
if [ -n "$UPSTREAM" ]; then
    RULES="rdr on ${IFACE} proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
rdr on lo0 proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
pass out quick on ${IFACE} proto tcp from any to ${UPSTREAM_IP} port ${UPSTREAM_PORT}
pass out on ${IFACE} route-to (lo0 127.0.0.1) proto tcp from any to any${PORT_FILTER}"
else
    RULES="rdr on ${IFACE} proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}"
fi

# Add anchor reference to main pf.conf if not already present
if ! sudo pfctl -s rules 2>/dev/null | grep -q "anchor \"${ANCHOR}\""; then
    echo "    Adding anchor to pf.conf"
    # Create a temporary config that loads the anchor
    TMPFILE=$(mktemp)
    cat > "$TMPFILE" <<EOF
# trans_proxy anchor - managed by pf_setup.sh
rdr-anchor "${ANCHOR}"
anchor "${ANCHOR}"
EOF
    # Load the anchor definition
    sudo pfctl -f /etc/pf.conf 2>/dev/null || true
    echo "$RULES" | sudo pfctl -a "${ANCHOR}" -f /dev/stdin
else
    echo "    Anchor already exists, updating rules"
    echo "$RULES" | sudo pfctl -a "${ANCHOR}" -f /dev/stdin
fi

echo "==> Enabling pf"
sudo pfctl -e 2>/dev/null || true

echo "==> Verifying anchor rules"
sudo pfctl -a "${ANCHOR}" -s rules

GATEWAY_IP=$(ifconfig "${IFACE}" inet | awk '/inet /{print $2}')

echo ""
echo "Done."
echo "  Gateway IP:  ${GATEWAY_IP:-<unknown>} (${IFACE})"
if [ -n "$PORTS" ]; then
    echo "  Ports:       ${PORTS} -> 127.0.0.1:${PROXY_PORT}"
else
    echo "  Ports:       all TCP -> 127.0.0.1:${PROXY_PORT}"
fi
if [ -n "$UPSTREAM" ]; then
    echo "  Upstream:    ${UPSTREAM} (excluded from interception)"
fi
echo "  DNS:         use --dns flag to listen on ${GATEWAY_IP:-<interface-ip>}:53 directly"
echo ""
echo "Configure client devices to use ${GATEWAY_IP:-this machine} as their gateway."
echo "Set DNS server to ${GATEWAY_IP:-this machine} on client devices."
echo "Run scripts/pf_teardown.sh to undo."
