#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user]

Set up nftables NAT redirect rules for trans_proxy on Linux.

Arguments:
  interface    Network interface for prerouting rules (e.g., eth0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic (OUTPUT chain)
               with UID-based exclusion for loop prevention

Examples:
  sudo $0 eth0              # redirect LAN traffic on eth0 to port 8443
  sudo $0 eth0 9000         # redirect LAN traffic on eth0 to port 9000
  sudo $0 eth0 8443 proxy   # also intercept local traffic (exclude user proxy)

Must be run as root.
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [proxy_user]}"
PORT="${2:-8443}"
PROXY_USER="${3:-}"

# Validate interface exists
if [ ! -d "/sys/class/net/$IFACE" ]; then
    echo "Error: network interface '$IFACE' does not exist." >&2
    echo "Available interfaces: $(ls /sys/class/net/ | tr '\n' ' ')" >&2
    exit 1
fi

# Validate port is numeric and in range
if ! echo "$PORT" | grep -qE '^[0-9]+$' || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: invalid port '$PORT' (must be 1-65535)." >&2
    exit 1
fi

# Remove existing rules to avoid duplicates
if nft list table ip trans_proxy &>/dev/null; then
    echo "Removing existing trans_proxy nftables table..."
    nft delete table ip trans_proxy
fi

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "Adding nftables NAT redirect rules on $IFACE -> port $PORT..."
nft add table ip trans_proxy
nft add chain ip trans_proxy prerouting { type nat hook prerouting priority -100 \; }
nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport 80 redirect to :"$PORT"
nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport 443 redirect to :"$PORT"

# When proxy_user is set, also intercept locally-originated traffic
if [ -n "$PROXY_USER" ]; then
    echo "Adding OUTPUT chain for local traffic (excluding user '$PROXY_USER')..."
    nft add chain ip trans_proxy output { type nat hook output priority -100 \; }
    nft add rule ip trans_proxy output meta skuid "$PROXY_USER" return
    nft add rule ip trans_proxy output tcp dport 80 redirect to :"$PORT"
    nft add rule ip trans_proxy output tcp dport 443 redirect to :"$PORT"
fi

echo "Done. Current trans_proxy rules:"
nft list table ip trans_proxy
