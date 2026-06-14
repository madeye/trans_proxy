# trans_proxy

Transparent TCP proxy that intercepts traffic via OS firewall rules and forwards through an upstream HTTP CONNECT or SOCKS5 proxy. Designed for side-router / gateway deployments.

## Build

```bash
# Native (macOS or Linux)
cargo build --release

# Cross-compile for Linux aarch64 (e.g., Raspberry Pi)
# Requires: cargo install cargo-zigbuild  (+ a Zig toolchain: brew install zig)
#           rustup target add aarch64-unknown-linux-gnu
# No Docker needed, so this works from any path (including /Volumes/...).
# The glibc suffix (.2.31) pins the target ABI; 2.31 covers Pi OS bullseye/bookworm.
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31
# Binary at: target/aarch64-unknown-linux-gnu/release/trans_proxy
```

## Test

```bash
# Unit tests
cargo test

# Lint
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# E2E tests (require root + nftables on Linux / pf on macOS)
sudo ./target/release/e2e

# Docker build + test (Linux)
docker build -t trans_proxy_test .
docker run --rm --privileged trans_proxy_test /app/target/release/e2e
```

## Deploy to remote Linux host

```bash
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31
scp target/aarch64-unknown-linux-gnu/release/trans_proxy user@host:/tmp/trans_proxy
ssh user@host "sudo systemctl stop trans_proxy && sudo cp /tmp/trans_proxy /usr/local/bin/trans_proxy && sudo chmod 755 /usr/local/bin/trans_proxy && sudo systemctl start trans_proxy"
```

## Architecture

- `src/config.rs` — CLI parsing (clap derive)
- `src/firewall/` — Native firewall setup/teardown (nftables on Linux, pf on macOS)
- `src/dns.rs` — DNS forwarder (UDP/DoH upstream) with IP→domain mapping
- `src/proxy.rs` — TCP accept loop and per-connection handler
- `src/tunnel.rs` — HTTP CONNECT / SOCKS5 handshakes
- `src/sni.rs` — TLS ClientHello SNI extraction
- `src/orig_dest/` — Original destination recovery (SO_ORIGINAL_DST / DIOCNATLOOK)
- `src/service/` — System service installation (systemd / launchd)
- `src/gateway.rs` — ARP/RA gateway advertisement
- `src/daemon.rs` — Double-fork daemonization

## Key conventions

- Platform-specific code uses `#[cfg(target_os = "...")]` with separate submodules (e.g., `firewall/nftables.rs`, `firewall/pf.rs`)
- Linux service module is compiled on macOS for test coverage via `#[cfg(any(target_os = "linux", test))]`
- `--upstream-proxy` is required by clap; firewall/service subcommands must also include it
