#!/usr/bin/env bash
# Run the multi-container gateway e2e (docker/gateway-e2e.yml).
#
# Exercises the REAL forwarded-traffic path that the loopback e2e cannot:
# a client container routes through a trans_proxy "gateway" container (PREROUTING
# redirect for TCP, TPROXY for UDP) to a WAN server container. Two scenarios:
#
#   1. SOCKS5 upstream      → TCP proxied, UDP/QUIC relayed (echo returns).
#   2. HTTP CONNECT upstream → TCP proxied, UDP/QUIC dropped (no echo).
#
# Usage: scripts/docker_gateway_e2e.sh
# Requires: docker + docker-compose (or `docker compose`). Run from the repo root.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=trans_proxy_e2e:latest
COMPOSE_FILE=docker/gateway-e2e.yml

# Pick whichever compose front-end is available.
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: need 'docker compose' or 'docker-compose'." >&2
  exit 1
fi

echo "=== Building image $IMAGE ==="
docker build -t "$IMAGE" .

run_scenario() {
  local name=$1 upstream=$2 expect_udp=$3
  echo
  echo "############################################################"
  echo "# Scenario: $name (upstream=$upstream, expect_udp=$expect_udp)"
  echo "############################################################"

  # -p isolates project state per scenario so networks/containers don't clash.
  local project="tpgw_${name}"
  # --exit-code-from implies --abort-on-container-exit and returns the client's
  # exit code. Guard against errexit so we always reach the teardown below.
  set +e
  GATEWAY_UPSTREAM="$upstream" EXPECT_UDP="$expect_udp" SCENARIO="$name" \
    "${COMPOSE[@]}" -p "$project" -f "$COMPOSE_FILE" up \
      --exit-code-from client
  local code=$?
  set -e

  # Always tear down (volumes + networks), even on success.
  GATEWAY_UPSTREAM="$upstream" EXPECT_UDP="$expect_udp" SCENARIO="$name" \
    "${COMPOSE[@]}" -p "$project" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true

  if [[ $code -ne 0 ]]; then
    echo "*** Scenario $name FAILED (exit $code) ***" >&2
    return "$code"
  fi
  echo "*** Scenario $name PASSED ***"
}

rc=0
run_scenario socks5 "socks5://10.20.0.2:1080" 1 || rc=$?
run_scenario http_connect "10.20.0.2:3128" 0 || rc=$?

echo
if [[ $rc -eq 0 ]]; then
  echo "=== Docker gateway e2e: ALL SCENARIOS PASSED ==="
else
  echo "=== Docker gateway e2e: FAILURES (rc=$rc) ===" >&2
fi
exit "$rc"
