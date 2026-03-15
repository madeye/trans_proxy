#!/bin/bash
set -euo pipefail

# Usage: pf_setup.sh <interface> [proxy_port]
# Example: pf_setup.sh en0 8443

IFACE="${1:?Usage: $0 <interface> [proxy_port]}"
PROXY_PORT="${2:-8443}"
ANCHOR="trans_proxy"

echo "==> Enabling IP forwarding"
sudo sysctl -w net.inet.ip.forwarding=1

echo "==> Loading pf anchor '${ANCHOR}'"

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
    sudo pfctl -a "${ANCHOR}" -f /dev/stdin <<EOF
# Redirect HTTP and HTTPS traffic arriving on ${IFACE} to transparent proxy
rdr on ${IFACE} proto tcp from any to any port {80, 443} -> 127.0.0.1 port ${PROXY_PORT}
EOF
else
    echo "    Anchor already exists, updating rules"
    sudo pfctl -a "${ANCHOR}" -f /dev/stdin <<EOF
rdr on ${IFACE} proto tcp from any to any port {80, 443} -> 127.0.0.1 port ${PROXY_PORT}
EOF
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
