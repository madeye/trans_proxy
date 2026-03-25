#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0

Remove macOS pf (packet filter) rules set up by pf_setup.sh.

Flushes the trans_proxy pf anchor and disables IP forwarding.
pf itself is left enabled; run 'sudo pfctl -d' to disable it entirely.

Requires root privileges (uses sudo internally).
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

ANCHOR="trans_proxy"

echo "==> Flushing anchor '${ANCHOR}' rules"
sudo pfctl -a "${ANCHOR}" -F all 2>/dev/null || true

echo "==> Disabling IP forwarding"
sudo sysctl -w net.inet.ip.forwarding=0

echo "Done. pf anchor '${ANCHOR}' has been flushed."
echo "Note: pf itself was left enabled. Run 'sudo pfctl -d' to disable pf entirely if desired."
