#!/bin/bash
set -euo pipefail

# End-to-end test runner for trans_proxy.
# Builds the workspace and runs the e2e test binary (requires root on Linux).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check for root (nftables + SO_MARK require CAP_NET_ADMIN)
if [ "$(id -u)" -ne 0 ]; then
    echo "E2E tests require root. Re-running with sudo..."
    exec sudo -E env "PATH=$PATH" "$0" "$@"
fi

echo "Building workspace (release)..."
cargo build --release --workspace

echo "Running e2e tests..."
./target/release/e2e
