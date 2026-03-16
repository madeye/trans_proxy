# trans_proxy

[中文文档](README_zh.md)

A transparent proxy for macOS that intercepts TCP traffic redirected by pf and forwards it through an upstream HTTP CONNECT proxy.

Designed to run on a Mac acting as a side router (gateway) for other devices on the LAN.

```
[Client devices] --gateway--> [macOS pf rdr] --> [trans_proxy :8443]
                                                      |
                                                      v
                                                 [Upstream HTTP CONNECT proxy]
                                                      |
                                                      v
                                                 [Original destination]
```

## Features

- **pf integration** — Uses `DIOCNATLOOK` ioctl on `/dev/pf` to recover original destinations from pf's NAT state table
- **SNI extraction** — Peeks at TLS ClientHello to extract hostnames, sending proper `CONNECT host:port` instead of raw IPs
- **DNS forwarder** — Listens directly on the gateway interface (port 53) for LAN client DNS queries, building an IP→domain lookup table. Supports DNS-over-HTTPS (DoH) and traditional UDP upstream.
- **Anchor-based pf rules** — Won't clobber your existing firewall config
- **Daemon mode** — Run as a background process with PID file and log file support
- **launchd service** — Install as a macOS LaunchDaemon for automatic startup on boot
- **Async I/O** — Built on tokio with per-connection task spawning

## Requirements

- macOS 12+ (uses pf and `DIOCNATLOOK` ioctl)
- Rust 1.70+ and Cargo
- Root privileges (for `/dev/pf` access and port 53 binding)
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

This example assumes your upstream HTTP proxy runs on `127.0.0.1:1082` and your LAN interface is `en0`.

```bash
# Step 1: Start the transparent proxy with DNS on the gateway interface
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns

# Or run as a daemon
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# Step 2: Set up pf redirection (in another terminal, or same if using -d)
sudo scripts/pf_setup.sh en0 8443

# Step 3: Configure client devices (see "Client Setup" below)

# Step 4: When done, tear down
sudo scripts/pf_teardown.sh
# If running as daemon, stop it
sudo kill $(cat /var/run/trans_proxy.pid)
```

## Usage

### Starting the proxy

The proxy requires root to open `/dev/pf` for NAT lookups:

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
| `--interface` | `en0` | Network interface for DNS auto-detection (used with `--dns`) |
| `--dns-listen` | *(auto)* | Override DNS listen address (e.g., `192.168.1.42:53`) |
| `--dns-upstream` | `https://cloudflare-dns.com/dns-query` | Upstream DNS: `host:port` for UDP, or `https://` URL for DoH |
| `-d` / `--daemon` | off | Run as a background daemon |
| `--pid-file` | `/var/run/trans_proxy.pid` | PID file path (used with `--daemon`) |
| `--log-file` | `/var/log/trans_proxy.log` (daemon) / stderr | Log file path |
| `--install` | off | Install as a macOS launchd service (LaunchDaemon) |
| `--uninstall` | off | Uninstall the macOS launchd service |

### Setting up pf redirection

The included scripts manage pf rules via an anchor (won't interfere with existing firewall rules).
DNS no longer needs pf redirection — trans_proxy listens directly on port 53.

```bash
# Set up HTTP/HTTPS redirection
sudo scripts/pf_setup.sh <interface> [proxy_port]
sudo scripts/pf_setup.sh en0 8443
```

The setup script prints the gateway IP and configuration summary:

```
==> Enabling IP forwarding
==> Loading pf anchor 'trans_proxy'
==> Enabling pf
==> Verifying anchor rules

Done.
  Gateway IP:  192.168.1.42 (en0)
  HTTP/HTTPS:  ports 80,443 -> 127.0.0.1:8443
  DNS:         use --dns flag to listen on 192.168.1.42:53 directly

Configure client devices to use 192.168.1.42 as their gateway.
Set DNS server to 192.168.1.42 on client devices.
Run scripts/pf_teardown.sh to undo.
```

To tear down:

```bash
sudo scripts/pf_teardown.sh
```

This flushes the anchor rules and disables IP forwarding. pf itself is left enabled — run `sudo pfctl -d` to disable it entirely.

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

### Service Install (launchd)

Install trans_proxy as a macOS LaunchDaemon so it starts automatically on boot and restarts if it crashes:

```bash
# Install with your desired options
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --install
```

This will:
- Copy the binary to `/usr/local/bin/trans_proxy`
- Generate a launchd plist at `/Library/LaunchDaemons/com.github.madeye.trans_proxy.plist`
- Configure `RunAtLoad` and `KeepAlive` for automatic startup and restart
- Logs go to `/var/log/trans_proxy.log`
- Load and start the service immediately

Manage the service with `launchctl`:

```bash
sudo launchctl stop  com.github.madeye.trans_proxy
sudo launchctl start com.github.madeye.trans_proxy
```

To uninstall:

```bash
sudo trans_proxy --uninstall
```

This unloads the service, removes the plist, and removes the installed binary.

**Note:** The `--daemon`, `--pid-file`, and `--log-file` flags are not needed with `--install` — launchd manages the process lifecycle directly.

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
2. Packet arrives on the Mac's LAN interface (the Mac is the gateway)
3. macOS pf `rdr` rule rewrites the destination to `127.0.0.1:8443`
4. trans_proxy accepts the connection
5. `DIOCNATLOOK` ioctl recovers the original destination (`93.184.216.34:443`) from pf's NAT state table
6. trans_proxy peeks at the TLS ClientHello to extract SNI (`example.com`)
7. Sends `CONNECT example.com:443 HTTP/1.1` to the upstream proxy
8. Bidirectional relay between client and upstream proxy

### Hostname Resolution

The proxy resolves hostnames for CONNECT requests using a fallback chain:

1. **SNI extraction** — Parses the TLS ClientHello to read the Server Name Indication extension (port 443 only). No TLS termination or certificate generation required.
2. **DNS table lookup** — If `--dns` is enabled, the built-in DNS forwarder records IP→domain mappings from A record responses. Works for both HTTP (port 80) and HTTPS (port 443).
3. **Raw IP** — Falls back to the IP address if no hostname can be determined.

### Why DIOCNATLOOK?

macOS pf's `rdr` rules rewrite the destination address *before* the socket layer sees it. This means `getsockname()` on the accepted connection returns the proxy's own address, not the original destination. The `DIOCNATLOOK` ioctl queries pf's NAT state table to recover the original destination — this is the same approach used by mitmproxy.

## Troubleshooting

### "Failed to open /dev/pf"
Run with `sudo`. The proxy needs root to access `/dev/pf`.

### "No ALTQ support in kernel"
This is a harmless warning from `pfctl`. macOS doesn't include ALTQ — pf redirection works fine without it.

### "DIOCNATLOOK failed"
- Ensure pf rules are loaded: `sudo pfctl -a trans_proxy -s rules`
- Ensure pf is enabled: `sudo pfctl -s info | head -1`
- Check that traffic is actually arriving on the expected interface

### Connections hang or timeout
- Verify the upstream proxy is running and accepts CONNECT requests
- Check with `--log-level debug` for detailed per-connection logging
- Ensure IP forwarding is enabled: `sysctl net.inet.ip.forwarding` (should be `1`)

### DNS not resolving on client devices
- Ensure `--dns` is set and the DNS forwarder is running
- Check that trans_proxy logs show `DNS forwarder listening on <ip>:53`
- Test: `dig @<gateway_ip> example.com`

## License

[MIT](LICENSE)
