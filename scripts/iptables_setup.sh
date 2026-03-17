#!/bin/bash
# Set up iptables NAT REDIRECT rules for trans_proxy on Linux.
#
# Usage: sudo ./iptables_setup.sh <interface> [proxy_port]
#   interface:  network interface for PREROUTING rules (e.g., eth0)
#   proxy_port: trans_proxy listen port (default: 8443)

set -euo pipefail

IFACE="${1:?Usage: $0 <interface> [proxy_port]}"
PORT="${2:-8443}"

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "Adding iptables NAT REDIRECT rules on $IFACE -> port $PORT..."
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT"
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 443 -j REDIRECT --to-port "$PORT"

echo "Done. Current NAT rules:"
iptables -t nat -L PREROUTING -n -v
