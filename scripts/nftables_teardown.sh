#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0

Remove nftables NAT redirect rules for trans_proxy on Linux.

Deletes the trans_proxy nftables table and disables IP forwarding.

Must be run as root.
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

echo "Removing nftables trans_proxy tables..."
nft delete table ip trans_proxy 2>/dev/null || echo "IPv4 table 'trans_proxy' not found, skipping."
nft delete table ip6 trans_proxy 2>/dev/null || echo "IPv6 table 'trans_proxy' not found, skipping."

echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0

echo "Done."
