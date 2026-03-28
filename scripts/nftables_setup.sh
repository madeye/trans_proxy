#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [fwmark] [upstream_proxy] [ports]

Set up nftables NAT redirect rules for trans_proxy on Linux.

Arguments:
  interface       Network interface for prerouting rules (e.g., eth0)
  proxy_port      trans_proxy listen port (default: 8443)
  fwmark          When set, also intercept local traffic (OUTPUT chain)
                  with fwmark-based exclusion for loop prevention (pass "" to skip).
                  The proxy sets SO_MARK on its outbound sockets to this value.
  upstream_proxy  Upstream proxy address (ip:port) to exclude from interception.
                  Prevents loops for traffic the proxy cannot mark (e.g., DoH via reqwest).
                  Pass "" to skip.
  ports           Comma-separated ports to redirect (default: all TCP, SSH to
                  interface IP is bypassed to prevent lockout)

Examples:
  sudo $0 eth0                              # redirect all TCP on eth0 (except SSH) to port 8443
  sudo $0 eth0 8443 "" "" 80,443            # redirect only ports 80,443
  sudo $0 eth0 8443 1 127.0.0.1:1082       # all TCP + local traffic (fwmark=1)
  sudo $0 eth0 8443 1 127.0.0.1:1082 22,80,443  # ports 22,80,443 + local traffic

Must be run as root.
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

IFACE="${1:?Usage: $0 <interface> [proxy_port] [fwmark] [upstream_proxy] [ports]}"
PORT="${2:-8443}"
FWMARK="${3:-}"
UPSTREAM="${4:-}"
PORTS="${5:-}"

# Validate interface exists
if [ ! -d "/sys/class/net/$IFACE" ]; then
    echo "Error: network interface '$IFACE' does not exist." >&2
    echo "Available interfaces: $(ls /sys/class/net/ | tr '\n' ' ')" >&2
    exit 1
fi

# Validate port is numeric and in range
if ! echo "$PORT" | grep -qE '^[0-9]+$' || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: invalid port '$PORT' (must be 1-65535)." >&2
    exit 1
fi

# Validate fwmark is numeric
if [ -n "$FWMARK" ]; then
    if ! echo "$FWMARK" | grep -qE '^[0-9]+$'; then
        echo "Error: invalid fwmark '$FWMARK' (must be a positive integer)." >&2
        exit 1
    fi
fi

# Validate upstream proxy address
if [ -n "$UPSTREAM" ]; then
    UPSTREAM_IP="${UPSTREAM%:*}"
    UPSTREAM_PORT="${UPSTREAM##*:}"
    if [ -z "$UPSTREAM_IP" ] || [ -z "$UPSTREAM_PORT" ]; then
        echo "Error: invalid upstream proxy address '$UPSTREAM' (expected ip:port)." >&2
        exit 1
    fi
    if ! echo "$UPSTREAM_PORT" | grep -qE '^[0-9]+$' || [ "$UPSTREAM_PORT" -lt 1 ] || [ "$UPSTREAM_PORT" -gt 65535 ]; then
        echo "Error: invalid upstream proxy port '$UPSTREAM_PORT' (must be 1-65535)." >&2
        exit 1
    fi
fi

# Validate individual ports in the comma-separated list
if [ -n "$PORTS" ]; then
    IFS=',' read -ra _VALIDATE_PORTS <<< "$PORTS"
    for _vp in "${_VALIDATE_PORTS[@]}"; do
        if ! echo "$_vp" | grep -qE '^[0-9]+$' || [ "$_vp" -lt 1 ] || [ "$_vp" -gt 65535 ]; then
            echo "Error: invalid port '$_vp' in ports list (must be 1-65535)." >&2
            exit 1
        fi
    done
fi

# Remove existing rules to avoid duplicates
if nft list table ip trans_proxy &>/dev/null; then
    echo "Removing existing trans_proxy nftables table..."
    nft delete table ip trans_proxy
fi

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

# Get interface IP for SSH bypass
IFACE_IP=$(ip -4 addr show "$IFACE" | grep -oP 'inet \K[0-9.]+' | head -1)

echo "Adding nftables NAT redirect rules on $IFACE -> port $PORT..."
nft add table ip trans_proxy
nft add chain ip trans_proxy prerouting { type nat hook prerouting priority -100 \; }
if [ -n "$PORTS" ]; then
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    for p in "${PORT_ARRAY[@]}"; do
        nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport "$p" redirect to :"$PORT"
    done
else
    # Bypass SSH to interface IP to prevent lockout
    if [ -n "$IFACE_IP" ]; then
        nft add rule ip trans_proxy prerouting iifname "$IFACE" ip daddr "$IFACE_IP" tcp dport 22 return
    fi
    nft add rule ip trans_proxy prerouting iifname "$IFACE" meta l4proto tcp redirect to :"$PORT"
fi

if [ -n "$FWMARK" ]; then
    echo "Adding OUTPUT chain for local traffic (fwmark=$FWMARK)..."
    nft add chain ip trans_proxy output { type nat hook output priority -100 \; }
    # Skip packets marked by the proxy (SO_MARK) to prevent loops
    nft add rule ip trans_proxy output meta mark "$FWMARK" return
    # Skip traffic destined to the upstream proxy (covers connections the proxy
    # cannot mark, e.g. DoH via reqwest)
    if [ -n "$UPSTREAM" ]; then
        echo "  Excluding upstream proxy destination $UPSTREAM..."
        nft add rule ip trans_proxy output ip daddr "$UPSTREAM_IP" tcp dport "$UPSTREAM_PORT" return
    fi
    if [ -n "$PORTS" ]; then
        IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
        for p in "${PORT_ARRAY[@]}"; do
            nft add rule ip trans_proxy output tcp dport "$p" redirect to :"$PORT"
        done
    else
        # Bypass SSH to interface IP to prevent lockout
        if [ -n "$IFACE_IP" ]; then
            nft add rule ip trans_proxy output ip daddr "$IFACE_IP" tcp dport 22 return
        fi
        nft add rule ip trans_proxy output meta l4proto tcp redirect to :"$PORT"
    fi
fi

echo "Done. Current trans_proxy rules:"
nft list table ip trans_proxy
