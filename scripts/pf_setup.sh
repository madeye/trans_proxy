#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user]

Set up macOS pf (packet filter) rules to redirect HTTP/HTTPS traffic
through trans_proxy.

Arguments:
  interface    Network interface for redirection (e.g., en0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic with UID-based
               exclusion to prevent loops

Examples:
  $0 en0              # redirect LAN traffic on en0 to port 8443
  $0 en0 9000         # redirect LAN traffic on en0 to port 9000
  $0 en0 8443 _proxy  # also intercept local traffic (exclude user _proxy)

Requires root privileges (uses sudo internally).
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [proxy_user]}"
PROXY_PORT="${2:-8443}"
PROXY_USER="${3:-}"
ANCHOR="trans_proxy"

echo "==> Enabling IP forwarding"
sudo sysctl -w net.inet.ip.forwarding=1

echo "==> Loading pf anchor '${ANCHOR}'"

# Build the anchor rules
if [ -n "$PROXY_USER" ]; then
    # Local traffic mode: rdr on interface + rdr on lo0 + route-to for local outbound
    RULES="rdr on ${IFACE} proto tcp from any to any port {80, 443} -> 127.0.0.1 port ${PROXY_PORT}
rdr on lo0 proto tcp from any to any port {80, 443} -> 127.0.0.1 port ${PROXY_PORT}
pass out on ${IFACE} route-to (lo0 127.0.0.1) proto tcp from any to any port {80, 443} user != ${PROXY_USER}"
else
    # LAN-only mode: rdr on interface only
    RULES="rdr on ${IFACE} proto tcp from any to any port {80, 443} -> 127.0.0.1 port ${PROXY_PORT}"
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
echo "  HTTP/HTTPS:  ports 80,443 -> 127.0.0.1:${PROXY_PORT}"
echo "  DNS:         use --dns flag to listen on ${GATEWAY_IP:-<interface-ip>}:53 directly"
echo ""
echo "Configure client devices to use ${GATEWAY_IP:-this machine} as their gateway."
echo "Set DNS server to ${GATEWAY_IP:-this machine} on client devices."
echo "Run scripts/pf_teardown.sh to undo."
