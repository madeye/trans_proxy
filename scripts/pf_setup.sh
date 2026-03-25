#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user] [ports]

Set up macOS pf (packet filter) rules to redirect TCP traffic
through trans_proxy.

Arguments:
  interface    Network interface for redirection (e.g., en0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic with UID-based
               exclusion to prevent loops (pass "" to skip)
  ports        Comma-separated ports to redirect (default: all TCP)

Examples:
  $0 en0                        # redirect all TCP on en0 to port 8443
  $0 en0 8443 "" 80,443         # redirect only ports 80,443
  $0 en0 8443 _proxy            # all TCP + local traffic (exclude user _proxy)
  $0 en0 8443 _proxy 22,80,443  # ports 22,80,443 + local traffic

Requires root privileges (uses sudo internally).
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [proxy_user]}"
PROXY_PORT="${2:-8443}"
PROXY_USER="${3:-}"
PORTS="${4:-}"
ANCHOR="trans_proxy"

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
if [ -n "$PROXY_USER" ]; then
    RULES="rdr on ${IFACE} proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
rdr on lo0 proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
pass out on ${IFACE} route-to (lo0 127.0.0.1) proto tcp from any to any${PORT_FILTER} user != ${PROXY_USER}"
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
echo "  DNS:         use --dns flag to listen on ${GATEWAY_IP:-<interface-ip>}:53 directly"
echo ""
echo "Configure client devices to use ${GATEWAY_IP:-this machine} as their gateway."
echo "Set DNS server to ${GATEWAY_IP:-this machine} on client devices."
echo "Run scripts/pf_teardown.sh to undo."
