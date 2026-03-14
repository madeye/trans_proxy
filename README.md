# trans_proxy

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
- **DNS interception** — Optional local DNS forwarder that builds an IP→domain lookup table as a fallback for hostname resolution
- **Anchor-based pf rules** — Won't clobber your existing firewall config
- **Async I/O** — Built on tokio with per-connection task spawning

## Requirements

- macOS (uses pf and `DIOCNATLOOK`)
- Root privileges (for `/dev/pf` access and pf rule management)
- An upstream HTTP CONNECT proxy

## Build

```bash
cargo build --release
```

## Usage

```bash
# Start the proxy (requires root)
sudo ./target/release/trans_proxy \
  --upstream-proxy 192.168.1.100:3128

# With DNS interception
sudo ./target/release/trans_proxy \
  --upstream-proxy 192.168.1.100:3128 \
  --dns-listen 0.0.0.0:5353 \
  --dns-upstream 8.8.8.8:53

# Set up pf redirection on interface en0
sudo scripts/pf_setup.sh en0 8443        # without DNS
sudo scripts/pf_setup.sh en0 8443 5353   # with DNS redirect

# Tear down
sudo scripts/pf_teardown.sh
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `0.0.0.0:8443` | Proxy listen address |
| `--upstream-proxy` | *(required)* | Upstream HTTP CONNECT proxy |
| `--log-level` | `info` | Log level (trace, debug, info, warn, error) |
| `--dns-listen` | *(disabled)* | Enable DNS forwarder on this address |
| `--dns-upstream` | `8.8.8.8:53` | Upstream DNS server |

### Client Setup

Configure client devices to use the Mac's IP as their default gateway. The setup script prints the gateway IP:

```
Done.
  Gateway IP:  192.168.1.42 (en0)
  HTTP/HTTPS:  ports 80,443 -> 127.0.0.1:8443
  DNS:         port 53 -> 127.0.0.1:5353

Configure client devices to use 192.168.1.42 as their gateway.
Set DNS server to 192.168.1.42 on client devices.
```

## Hostname Resolution

The proxy resolves hostnames for CONNECT requests using a fallback chain:

1. **SNI** — extracted from TLS ClientHello (port 443)
2. **DNS table** — IP→domain mapping from intercepted DNS responses (if `--dns-listen` is enabled)
3. **Raw IP** — used as last resort

## License

MIT
