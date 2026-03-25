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

echo "Removing nftables trans_proxy table..."
nft delete table ip trans_proxy 2>/dev/null || echo "Table 'trans_proxy' not found, skipping."

echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0

echo "Done."
