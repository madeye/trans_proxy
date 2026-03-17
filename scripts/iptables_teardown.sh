#!/bin/bash
# Remove iptables NAT REDIRECT rules for trans_proxy on Linux.
#
# Usage: sudo ./iptables_teardown.sh

set -euo pipefail

echo "Flushing iptables NAT PREROUTING rules..."
iptables -t nat -F PREROUTING

echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0

echo "Done. Current NAT rules:"
iptables -t nat -L PREROUTING -n -v
