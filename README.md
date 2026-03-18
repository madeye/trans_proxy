# trans_proxy

[中文文档](README_zh.md)

A transparent proxy for macOS and Linux that intercepts TCP traffic redirected by the OS firewall and forwards it through an upstream HTTP CONNECT proxy.

Designed to run on a machine acting as a side router (gateway) for other devices on the LAN.

```
[Client devices] --gateway--> [NAT redirect] --> [trans_proxy :8443]
                                                      |
                                                      v
                                                 [Upstream HTTP CONNECT proxy]
                                                      |
                                                      v
                                                 [Original destination]
```

## Features

- **macOS pf integration** — Uses `DIOCNATLOOK` ioctl on `/dev/pf` to recover original destinations from pf's NAT state table
- **Linux nftables integration** — Uses `SO_ORIGINAL_DST` getsockopt to recover original destinations from nftables redirect
- **SNI extraction** — Peeks at TLS ClientHello to extract hostnames, sending proper `CONNECT host:port` instead of raw IPs
- **DNS forwarder** — Listens directly on the gateway interface (port 53) for LAN client DNS queries, building an IP→domain lookup table. Supports DNS-over-HTTPS (DoH) with HTTP/2 connection pooling, TTL-aware caching, and query coalescing, as well as traditional UDP upstream.
- **Anchor-based pf rules** (macOS) / **nftables table** (Linux) — Won't clobber your existing firewall config
- **Daemon mode** — Run as a background process with PID file and log file support
- **Service install** — launchd on macOS, systemd on Linux. On Linux, nftables NAT rules are automatically managed via ExecStartPre/ExecStopPost
- **Async I/O** — Built on tokio with per-connection task spawning

## Requirements

- **macOS**: macOS 12+ (uses pf and `DIOCNATLOOK` ioctl)
- **Linux**: Kernel 3.7+ with nftables
- Rust 1.70+ and Cargo (for building from source)
- Root privileges (for NAT lookups and port 53 binding)
- An upstream HTTP CONNECT proxy (e.g., Squid, mitmproxy, or any CONNECT-capable proxy)

## Build

### From source

```bash
# Clone the repository
git clone https://github.com/madeye/trans_proxy.git
cd trans_proxy

# Build release binary
cargo build --release

# Binary will be at ./target/release/trans_proxy
```

### Verify the build

```bash
cargo test
./target/release/trans_proxy --help
```

## Quick Start

### macOS

This example assumes your upstream HTTP proxy runs on `127.0.0.1:1082` and your LAN interface is `en0`.

```bash
# Step 1: Start the transparent proxy with DNS on the gateway interface
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns

# Step 2: Set up pf redirection
sudo scripts/pf_setup.sh en0 8443

# Step 3: Configure client devices (see "Client Setup" below)

# Step 4: When done, tear down
sudo scripts/pf_teardown.sh
sudo kill $(cat /var/run/trans_proxy.pid)
```

### Linux

This example assumes your upstream HTTP proxy runs on `127.0.0.1:7890` and your LAN interface is `eth0`.

```bash
# Step 1: Start the transparent proxy with DNS
sudo ./trans_proxy \
  --upstream-proxy 127.0.0.1:7890 \
  --dns --interface eth0

# Step 2: Set up nftables redirection
sudo scripts/nftables_setup.sh eth0 8443

# Step 3: Configure client devices (see "Client Setup" below)

# Step 4: When done, tear down
sudo scripts/nftables_teardown.sh
sudo kill $(cat /var/run/trans_proxy.pid)
```

## Usage

### Starting the proxy

The proxy requires root for NAT lookups (`/dev/pf` on macOS, `SO_ORIGINAL_DST` on Linux):

```bash
# Minimal — proxy only, no DNS
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port>

# With DNS on the gateway interface (auto-detects en0 IP, listens on port 53)
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns

# Specify a different interface
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --interface en1

# Override DNS listen address manually
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns-listen 192.168.1.42:53

# Use a specific DoH provider
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --dns-upstream https://dns.google/dns-query

# Use traditional UDP DNS instead of DoH
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --dns-upstream 8.8.8.8:53

# Run as a background daemon
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# Daemon with custom PID and log file
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d --pid-file /tmp/trans_proxy.pid \
  --log-file /tmp/trans_proxy.log
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `0.0.0.0:8443` | Address and port the proxy listens on |
| `--upstream-proxy` | *(required)* | Upstream HTTP CONNECT proxy address (`host:port`) |
| `--log-level` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `--dns` | off | Enable DNS forwarder on the gateway interface (port 53) |
| `--interface` | `en0` (macOS) / `eth0` (Linux) | Network interface for DNS auto-detection (used with `--dns`) |
| `--dns-listen` | *(auto)* | Override DNS listen address (e.g., `192.168.1.42:53`) |
| `--dns-upstream` | `https://cloudflare-dns.com/dns-query` | Upstream DNS: `host:port` for UDP, or `https://` URL for DoH |
| `-d` / `--daemon` | off | Run as a background daemon |
| `--pid-file` | `/var/run/trans_proxy.pid` | PID file path (used with `--daemon`) |
| `--log-file` | `/var/log/trans_proxy.log` (daemon) / stderr | Log file path |
| `--install` | off | Install as a system service (launchd on macOS, systemd on Linux) |
| `--uninstall` | off | Uninstall the system service |

### Setting up NAT redirection

#### macOS (pf)

The included scripts manage pf rules via an anchor (won't interfere with existing firewall rules).

```bash
sudo scripts/pf_setup.sh <interface> [proxy_port]
sudo scripts/pf_setup.sh en0 8443

# Tear down
sudo scripts/pf_teardown.sh
```

#### Linux (nftables)

The included scripts create a dedicated nftables table for trans_proxy.

```bash
sudo scripts/nftables_setup.sh <interface> [proxy_port]
sudo scripts/nftables_setup.sh eth0 8443

# Tear down
sudo scripts/nftables_teardown.sh
```

### Linux Kernel Optimization

For high-throughput proxy workloads, optimize kernel parameters and file descriptor limits:

```bash
sudo scripts/optimize_linux.sh
```

This tunes sysctl settings (TCP buffers, backlog, connection recycling, TCP Fast Open) and raises file descriptor limits. Based on [shadowsocks optimization guide](https://shadowsocks.org/doc/advanced.html#optimize-the-shadowsocks-server-on-linux).

### Daemon Mode

Run trans_proxy as a background process:

```bash
# Start as daemon
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# Check status
cat /var/run/trans_proxy.pid
tail -f /var/log/trans_proxy.log

# Stop
sudo kill $(cat /var/run/trans_proxy.pid)
```

In daemon mode:
- The process forks into the background and detaches from the terminal
- A PID file is written (default `/var/run/trans_proxy.pid`)
- Logs are written to a file (default `/var/log/trans_proxy.log`) instead of stderr
- The PID file is cleaned up on exit

### Service Install

Install trans_proxy as a system service for automatic startup on boot:

```bash
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --install
```

On **macOS**, this installs a LaunchDaemon. On **Linux**, this installs a systemd service with automatic nftables setup/teardown — NAT redirect rules are created when the service starts and removed when it stops.

To uninstall:

```bash
sudo trans_proxy --uninstall
```

### Client Setup

On each device you want to route through the proxy:

1. **Set the default gateway** to the Mac's IP address (shown by the setup script)
2. **Set the DNS server** to the Mac's IP address (if using `--dns`)

#### macOS / iOS
Settings → Wi-Fi → (i) → Configure IP → Manual → Router: `<gateway_ip>`, DNS: `<gateway_ip>`

#### Windows
Settings → Network → Wi-Fi → Properties → Edit IP → Manual → Gateway: `<gateway_ip>`, DNS: `<gateway_ip>`

#### Linux
```bash
sudo ip route replace default via <gateway_ip>
echo "nameserver <gateway_ip>" | sudo tee /etc/resolv.conf
```

#### Android
Settings → Wi-Fi → Long press network → Modify → Advanced → IP settings: Static → Gateway: `<gateway_ip>`, DNS: `<gateway_ip>`

## How It Works

### Traffic Flow

1. Client device sends a packet to `example.com:443` (resolved to e.g., `93.184.216.34`)
2. Packet arrives on the gateway's LAN interface
3. NAT redirect rule rewrites the destination to `127.0.0.1:8443` (pf on macOS, nftables on Linux)
4. trans_proxy accepts the connection
5. Original destination is recovered (`DIOCNATLOOK` on macOS, `SO_ORIGINAL_DST` on Linux)
6. trans_proxy peeks at the TLS ClientHello to extract SNI (`example.com`)
7. Sends `CONNECT example.com:443 HTTP/1.1` to the upstream proxy
8. Bidirectional relay between client and upstream proxy

### Hostname Resolution

The proxy resolves hostnames for CONNECT requests using a fallback chain:

1. **SNI extraction** — Parses the TLS ClientHello to read the Server Name Indication extension (port 443 only). No TLS termination or certificate generation required.
2. **DNS table lookup** — If `--dns` is enabled, the built-in DNS forwarder records IP→domain mappings from A record responses. Works for both HTTP (port 80) and HTTPS (port 443).
3. **Raw IP** — Falls back to the IP address if no hostname can be determined.

### Original Destination Recovery

NAT redirect rules rewrite the destination address before the socket layer sees it. trans_proxy recovers the original destination using platform-specific mechanisms:

- **macOS**: `DIOCNATLOOK` ioctl on `/dev/pf` queries pf's NAT state table (same approach as mitmproxy)
- **Linux**: `SO_ORIGINAL_DST` getsockopt on the accepted socket fd recovers the pre-redirect destination

## Troubleshooting

### macOS: "Failed to open /dev/pf"
Run with `sudo`. The proxy needs root to access `/dev/pf`.

### macOS: "No ALTQ support in kernel"
This is a harmless warning from `pfctl`. macOS doesn't include ALTQ — pf redirection works fine without it.

### macOS: "DIOCNATLOOK failed"
- Ensure pf rules are loaded: `sudo pfctl -a trans_proxy -s rules`
- Ensure pf is enabled: `sudo pfctl -s info | head -1`
- Check that traffic is actually arriving on the expected interface

### Linux: "SO_ORIGINAL_DST failed"
- Ensure nftables redirect rules are active: `sudo nft list table ip trans_proxy`
- Ensure IP forwarding is enabled: `sysctl net.ipv4.ip_forward` (should be `1`)

### Connections hang or timeout
- Verify the upstream proxy is running and accepts CONNECT requests
- Check with `--log-level debug` for detailed per-connection logging
- Ensure IP forwarding is enabled

### DNS not resolving on client devices
- Ensure `--dns` is set and the DNS forwarder is running
- Check that trans_proxy logs show `DNS forwarder listening on <ip>:53`
- Test: `dig @<gateway_ip> example.com`

## License

[MIT](LICENSE)
