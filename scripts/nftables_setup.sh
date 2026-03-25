#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user] [ports]

Set up nftables NAT redirect rules for trans_proxy on Linux.

Arguments:
  interface    Network interface for prerouting rules (e.g., eth0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic (OUTPUT chain)
               with UID-based exclusion for loop prevention (pass "" to skip)
  ports        Comma-separated ports to redirect (default: all TCP)

Examples:
  sudo $0 eth0                        # redirect all TCP on eth0 to port 8443
  sudo $0 eth0 8443 "" 80,443         # redirect only ports 80,443
  sudo $0 eth0 8443 proxy             # all TCP + local traffic (exclude user proxy)
  sudo $0 eth0 8443 proxy 22,80,443   # ports 22,80,443 + local traffic

Must be run as root.
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [proxy_user] [ports]}"
PORT="${2:-8443}"
PROXY_USER="${3:-}"
PORTS="${4:-}"

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
if [ -n "$PORTS" ]; then
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    for p in "${PORT_ARRAY[@]}"; do
        nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport "$p" redirect to :"$PORT"
    done
else
    nft add rule ip trans_proxy prerouting iifname "$IFACE" meta l4proto tcp redirect to :"$PORT"
fi

if [ -n "$PROXY_USER" ]; then
    echo "Adding OUTPUT chain for local traffic (excluding user '$PROXY_USER')..."
    nft add chain ip trans_proxy output { type nat hook output priority -100 \; }
    nft add rule ip trans_proxy output meta skuid "$PROXY_USER" return
    if [ -n "$PORTS" ]; then
        IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
        for p in "${PORT_ARRAY[@]}"; do
            nft add rule ip trans_proxy output tcp dport "$p" redirect to :"$PORT"
        done
    else
        nft add rule ip trans_proxy output meta l4proto tcp redirect to :"$PORT"
    fi
fi

echo "Done. Current trans_proxy rules:"
nft list table ip trans_proxy
