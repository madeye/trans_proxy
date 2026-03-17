#!/bin/bash
# Set up nftables NAT redirect rules for trans_proxy on Linux.
#
# Usage: sudo ./nftables_setup.sh <interface> [proxy_port]
#   interface:  network interface for prerouting rules (e.g., eth0)
#   proxy_port: trans_proxy listen port (default: 8443)

set -euo pipefail

IFACE="${1:?Usage: $0 <interface> [proxy_port]}"
PORT="${2:-8443}"

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "Adding nftables NAT redirect rules on $IFACE -> port $PORT..."
nft add table ip trans_proxy
nft add chain ip trans_proxy prerouting { type nat hook prerouting priority -100 \; }
nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport 80 redirect to :"$PORT"
nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport 443 redirect to :"$PORT"

echo "Done. Current trans_proxy rules:"
nft list table ip trans_proxy
