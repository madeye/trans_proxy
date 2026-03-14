#!/bin/bash
set -euo pipefail

ANCHOR="trans_proxy"

echo "==> Flushing anchor '${ANCHOR}' rules"
sudo pfctl -a "${ANCHOR}" -F all 2>/dev/null || true

echo "==> Disabling IP forwarding"
sudo sysctl -w net.inet.ip.forwarding=0

echo "Done. pf anchor '${ANCHOR}' has been flushed."
echo "Note: pf itself was left enabled. Run 'sudo pfctl -d' to disable pf entirely if desired."
