#!/bin/bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0

Optimize Linux kernel parameters for trans_proxy.

Tunes sysctl and file descriptor limits for high-throughput proxying.
Based on https://shadowsocks.org/doc/advanced.html

Settings applied:
  /etc/sysctl.d/99-trans-proxy.conf     Kernel network tuning
  /etc/security/limits.d/99-trans-proxy.conf  File descriptor limits

Must be run as root.
EOF
    exit 0
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && usage

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root." >&2
    exit 1
fi

SYSCTL_CONF="/etc/sysctl.d/99-trans-proxy.conf"
LIMITS_CONF="/etc/security/limits.d/99-trans-proxy.conf"

echo "Writing sysctl settings to ${SYSCTL_CONF}..."
cat > "$SYSCTL_CONF" << 'EOF'
# trans_proxy kernel optimizations
# Based on https://shadowsocks.org/doc/advanced.html

# Max open files
fs.file-max = 51200

# Socket buffer sizes (64MB max)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864

# Accept queue & backlog
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096

# TCP SYN
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192

# Connection recycling
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_tw_buckets = 5000

# Keepalive
net.ipv4.tcp_keepalive_time = 1200

# Ephemeral port range
net.ipv4.ip_local_port_range = 10000 65000

# TCP Fast Open (client + server)
net.ipv4.tcp_fastopen = 3

# TCP memory (pages): min, pressure, max
net.ipv4.tcp_mem = 25600 51200 102400

# TCP buffer sizes: min, default, max
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# MTU probing for path MTU discovery
net.ipv4.tcp_mtu_probing = 1
EOF

echo "Writing file descriptor limits to ${LIMITS_CONF}..."
cat > "$LIMITS_CONF" << 'EOF'
# trans_proxy file descriptor limits
* soft nofile 51200
* hard nofile 51200
root soft nofile 51200
root hard nofile 51200
EOF

echo "Applying sysctl settings..."
sysctl -p "$SYSCTL_CONF"

echo ""
echo "Done. File descriptor limits will take effect on next login."
echo "To apply immediately for the current shell: ulimit -n 51200"
