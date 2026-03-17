#!/bin/bash
# Remove nftables NAT redirect rules for trans_proxy on Linux.
#
# Usage: sudo ./nftables_teardown.sh

set -euo pipefail

echo "Removing nftables trans_proxy table..."
nft delete table ip trans_proxy 2>/dev/null || echo "Table 'trans_proxy' not found, skipping."

echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0

echo "Done."
