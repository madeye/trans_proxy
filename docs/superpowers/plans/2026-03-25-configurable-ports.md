# Configurable Port Redirection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change trans_proxy from hardcoded port 80/443 to all-TCP-by-default, with an optional `--ports` flag to restrict which ports are redirected.

**Architecture:** Add a `PortList` wrapper type with `FromStr` parser in `config.rs`. Update both firewall scripts (`pf_setup.sh`, `nftables_setup.sh`) to accept an optional ports argument. Update `generate_unit` in `service/linux.rs` to pass the ports argument to the setup script.

**Tech Stack:** Rust (clap derive), Bash (pf/nftables)

**Spec:** `docs/superpowers/specs/2026-03-25-configurable-ports-design.md`

---

### Task 1: Add `PortList` type and `--ports` flag to Config

**Files:**
- Modify: `src/config.rs:159-232` (Config struct and tests)

- [ ] **Step 1: Write the failing test for PortList parsing**

Add to the `#[cfg(test)] mod tests` block in `src/config.rs`:

```rust
#[test]
fn test_port_list_parse_valid() {
    let pl: PortList = "22,80,443".parse().unwrap();
    assert_eq!(pl.0, vec![22, 80, 443]);
}

#[test]
fn test_port_list_parse_single() {
    let pl: PortList = "8080".parse().unwrap();
    assert_eq!(pl.0, vec![8080]);
}

#[test]
fn test_port_list_parse_deduplicates() {
    let pl: PortList = "80,443,80".parse().unwrap();
    assert_eq!(pl.0, vec![80, 443]);
}

#[test]
fn test_port_list_parse_rejects_zero() {
    let result: Result<PortList, _> = "0,80".parse();
    assert!(result.is_err());
}

#[test]
fn test_port_list_parse_rejects_invalid() {
    let result: Result<PortList, _> = "abc".parse();
    assert!(result.is_err());
}

#[test]
fn test_port_list_parse_rejects_empty() {
    let result: Result<PortList, _> = "".parse();
    assert!(result.is_err());
}

#[test]
fn test_port_list_parse_with_spaces() {
    let pl: PortList = "22, 80, 443".parse().unwrap();
    assert_eq!(pl.0, vec![22, 80, 443]);
}

#[test]
fn test_port_list_display() {
    let pl: PortList = "22,80,443".parse().unwrap();
    assert_eq!(format!("{}", pl), "22,80,443");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::tests::test_port_list`
Expected: FAIL — `PortList` type does not exist

- [ ] **Step 3: Implement PortList type**

Add above the `Config` struct in `src/config.rs`:

```rust
/// Comma-separated list of TCP ports for firewall redirection.
///
/// Used with the `--ports` flag to restrict which ports are redirected.
/// When not specified, all TCP traffic is redirected.
#[derive(Debug, Clone)]
pub struct PortList(pub Vec<u16>);

impl fmt::Display for PortList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.0.iter().map(|p| p.to_string()).collect();
        write!(f, "{}", s.join(","))
    }
}

impl std::str::FromStr for PortList {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ports = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for part in s.split(',') {
            let part = part.trim();
            let port: u16 = part
                .parse()
                .map_err(|_| format!("invalid port '{}': expected 1-65535", part))?;
            if port == 0 {
                return Err("port 0 is not valid".to_string());
            }
            if seen.insert(port) {
                ports.push(port);
            }
        }
        if ports.is_empty() {
            return Err("port list cannot be empty".to_string());
        }
        Ok(PortList(ports))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config::tests::test_port_list`
Expected: All 8 tests PASS

- [ ] **Step 5: Add `--ports` field to Config struct and test**

Add the field to the `Config` struct after `proxy_user`:

```rust
    /// Comma-separated list of TCP ports to redirect.
    /// When omitted, all TCP traffic is redirected.
    #[arg(long)]
    pub ports: Option<PortList>,
```

Add test:

```rust
#[test]
fn test_ports_flag() {
    let config = Config::parse_from([
        "trans_proxy",
        "--upstream-proxy",
        "127.0.0.1:1082",
        "--ports",
        "22,80,443",
    ]);
    let ports = config.ports.unwrap();
    assert_eq!(ports.0, vec![22, 80, 443]);
}

#[test]
fn test_ports_flag_default_none() {
    let config = Config::parse_from(["trans_proxy", "--upstream-proxy", "127.0.0.1:1082"]);
    assert!(config.ports.is_none());
}
```

- [ ] **Step 6: Run all config tests**

Run: `cargo test --lib config::tests`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/config.rs
git commit -m "feat: add --ports flag with PortList type for configurable port redirection"
```

---

### Task 2: Update `pf_setup.sh` for configurable ports

**Files:**
- Modify: `scripts/pf_setup.sh`

- [ ] **Step 1: Update script to accept optional ports argument**

Change the usage, argument parsing, and rule generation in `scripts/pf_setup.sh`:

Update `usage()`:
```bash
usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user] [ports]

Set up macOS pf (packet filter) rules to redirect TCP traffic
through trans_proxy.

Arguments:
  interface    Network interface for redirection (e.g., en0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic with UID-based
               exclusion to prevent loops (pass "" to skip)
  ports        Comma-separated ports to redirect (default: all TCP)

Examples:
  $0 en0                        # redirect all TCP on en0 to port 8443
  $0 en0 8443 "" 80,443         # redirect only ports 80,443
  $0 en0 8443 _proxy            # all TCP + local traffic (exclude user _proxy)
  $0 en0 8443 _proxy 22,80,443  # ports 22,80,443 + local traffic

Requires root privileges (uses sudo internally).
EOF
    exit 0
}
```

Add after `PROXY_USER`:
```bash
PORTS="${4:-}"
```

Build the port filter clause:
```bash
# Build port filter clause
if [ -n "$PORTS" ]; then
    # Convert comma-separated to pf syntax: {22, 80, 443}
    PORT_LIST=$(echo "$PORTS" | sed 's/,/, /g')
    PORT_FILTER=" port {${PORT_LIST}}"
else
    PORT_FILTER=""
fi
```

Update rule generation — replace the existing `if [ -n "$PROXY_USER" ]` block:
```bash
if [ -n "$PROXY_USER" ]; then
    RULES="rdr on ${IFACE} proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
rdr on lo0 proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}
pass out on ${IFACE} route-to (lo0 127.0.0.1) proto tcp from any to any${PORT_FILTER} user != ${PROXY_USER}"
else
    RULES="rdr on ${IFACE} proto tcp from any to any${PORT_FILTER} -> 127.0.0.1 port ${PROXY_PORT}"
fi
```

Update the summary echo at the bottom:
```bash
if [ -n "$PORTS" ]; then
    echo "  Ports:       ${PORTS} -> 127.0.0.1:${PROXY_PORT}"
else
    echo "  Ports:       all TCP -> 127.0.0.1:${PROXY_PORT}"
fi
```

- [ ] **Step 2: Verify script syntax**

Run: `bash -n scripts/pf_setup.sh`
Expected: No output (syntax OK)

- [ ] **Step 3: Commit**

```bash
git add scripts/pf_setup.sh
git commit -m "feat: pf_setup.sh accepts optional ports argument, defaults to all TCP"
```

---

### Task 3: Update `nftables_setup.sh` for configurable ports

**Files:**
- Modify: `scripts/nftables_setup.sh`

- [ ] **Step 1: Update script to accept optional ports argument**

Update `usage()`:
```bash
usage() {
    cat <<EOF
Usage: $0 <interface> [proxy_port] [proxy_user] [ports]

Set up nftables NAT redirect rules for trans_proxy on Linux.

Arguments:
  interface    Network interface for prerouting rules (e.g., eth0)
  proxy_port   trans_proxy listen port (default: 8443)
  proxy_user   When set, also intercept local traffic (OUTPUT chain)
               with UID-based exclusion for loop prevention (pass "" to skip)
  ports        Comma-separated ports to redirect (default: all TCP)

Examples:
  sudo $0 eth0                        # redirect all TCP on eth0 to port 8443
  sudo $0 eth0 8443 "" 80,443         # redirect only ports 80,443
  sudo $0 eth0 8443 proxy             # all TCP + local traffic (exclude user proxy)
  sudo $0 eth0 8443 proxy 22,80,443   # ports 22,80,443 + local traffic

Must be run as root.
EOF
    exit 0
}
```

Add after `PROXY_USER`:
```bash
PORTS="${4:-}"
```

Add port validation (after the existing proxy port validation block):
```bash
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
```

Replace the prerouting rule section (after `nft add chain`):
```bash
if [ -n "$PORTS" ]; then
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    for p in "${PORT_ARRAY[@]}"; do
        nft add rule ip trans_proxy prerouting iifname "$IFACE" tcp dport "$p" redirect to :"$PORT"
    done
else
    nft add rule ip trans_proxy prerouting iifname "$IFACE" meta l4proto tcp redirect to :"$PORT"
fi
```

Replace the local-traffic OUTPUT chain section:
```bash
if [ -n "$PROXY_USER" ]; then
    echo "Adding OUTPUT chain for local traffic (excluding user '$PROXY_USER')..."
    nft add chain ip trans_proxy output { type nat hook output priority -100 \; }
    nft add rule ip trans_proxy output meta skuid "$PROXY_USER" return
    if [ -n "$PORTS" ]; then
        IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
        for p in "${PORT_ARRAY[@]}"; do
            nft add rule ip trans_proxy output tcp dport "$p" redirect to :"$PORT"
        done
    else
        nft add rule ip trans_proxy output meta l4proto tcp redirect to :"$PORT"
    fi
fi
```

- [ ] **Step 2: Verify script syntax**

Run: `bash -n scripts/nftables_setup.sh`
Expected: No output (syntax OK)

- [ ] **Step 3: Commit**

```bash
git add scripts/nftables_setup.sh
git commit -m "feat: nftables_setup.sh accepts optional ports argument, defaults to all TCP"
```

---

### Task 4: Update `generate_unit` in `service/linux.rs` to pass ports

**Files:**
- Modify: `src/service/linux.rs:166-219` (generate_unit function and tests)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/service/linux.rs`:

```rust
#[test]
fn test_generate_unit_with_ports() {
    let args: Vec<String> = vec![
        "--upstream-proxy".into(),
        "127.0.0.1:1082".into(),
        "--ports".into(),
        "22,80,443".into(),
        "--interface".into(),
        "eth0".into(),
    ];
    let unit = generate_unit(&args);

    assert!(unit.contains("nftables_setup.sh eth0 8443 \"\" 22,80,443"));
}

#[test]
fn test_generate_unit_with_ports_and_local_traffic() {
    let args: Vec<String> = vec![
        "--upstream-proxy".into(),
        "127.0.0.1:1082".into(),
        "--ports".into(),
        "22,80,443".into(),
        "--local-traffic".into(),
        "--proxy-user".into(),
        "myproxy".into(),
    ];
    let unit = generate_unit(&args);

    assert!(unit.contains("nftables_setup.sh eth0 8443 myproxy 22,80,443"));
}

#[test]
fn test_generate_unit_without_ports_all_tcp() {
    let args: Vec<String> = vec!["--upstream-proxy".into(), "127.0.0.1:1082".into()];
    let unit = generate_unit(&args);

    // Without ports, no 4th argument — script defaults to all TCP
    assert!(unit.contains("nftables_setup.sh eth0 8443\n"));
}

#[test]
fn test_generate_unit_local_traffic_without_ports() {
    let args: Vec<String> = vec![
        "--upstream-proxy".into(),
        "127.0.0.1:1082".into(),
        "--local-traffic".into(),
    ];
    let unit = generate_unit(&args);

    // local-traffic + no ports: 3 args only, no trailing port list
    assert!(unit.contains("nftables_setup.sh eth0 8443 trans_proxy\n"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib service::linux::tests::test_generate_unit_with_ports`
Expected: FAIL — current code doesn't pass ports argument

- [ ] **Step 3: Update `generate_unit` to extract and pass `--ports`**

In `src/service/linux.rs`, update the `generate_unit` function. After the `proxy_user` extraction (line 182), add:

```rust
let ports = extract_arg(&filtered_args, "--ports");
```

Replace the `setup_cmd` construction:

```rust
let setup_cmd = match (local_traffic, ports) {
    (true, Some(p)) => format!("{SETUP_SCRIPT} {interface} {port} {proxy_user} {p}"),
    (true, None) => format!("{SETUP_SCRIPT} {interface} {port} {proxy_user}"),
    (false, Some(p)) => format!("{SETUP_SCRIPT} {interface} {port} \"\" {p}"),
    (false, None) => format!("{SETUP_SCRIPT} {interface} {port}"),
};
```

- [ ] **Step 4: Fix existing tests that assert exact line content**

The test `test_generate_unit_without_local_traffic_no_user` asserts:
```rust
assert!(unit.contains("nftables_setup.sh eth0 8443\n"));
```
This still passes because the `(false, None)` branch produces the same output as before.

Run: `cargo test --lib service::linux::tests`
Expected: All PASS (new and existing)

- [ ] **Step 5: Commit**

```bash
git add src/service/linux.rs
git commit -m "feat: pass --ports to nftables_setup.sh in systemd unit generation"
```

---

### Task 5: Update README documentation

**Files:**
- Modify: `README.md`
- Modify: `README_zh.md`

- [ ] **Step 1: Add `--ports` to the CLI Options table in README.md**

In the CLI Options table (around line 169), add a row after `--proxy-user`:

```markdown
| `--ports` | *(all TCP)* | Comma-separated list of TCP ports to redirect (e.g., `22,80,443`). When omitted, all TCP traffic is redirected |
```

- [ ] **Step 2: Update firewall script usage examples in README.md**

Update the pf_setup.sh example (around line 193):
```markdown
```bash
sudo scripts/pf_setup.sh <interface> [proxy_port] [proxy_user] [ports]
sudo scripts/pf_setup.sh en0 8443                    # all TCP
sudo scripts/pf_setup.sh en0 8443 "" 80,443           # only ports 80,443
```

Update the nftables_setup.sh example (around line 205):
```markdown
```bash
sudo scripts/nftables_setup.sh <interface> [proxy_port] [proxy_user] [ports]
sudo scripts/nftables_setup.sh eth0 8443                    # all TCP
sudo scripts/nftables_setup.sh eth0 8443 "" 80,443           # only ports 80,443
```

- [ ] **Step 3: Add a usage example for `--ports` in the "Starting the proxy" section**

After the SOCKS5 examples (around line 164), add:

```markdown
# Redirect only specific ports (default: all TCP)
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --ports 22,80,443
```

- [ ] **Step 4: Update README_zh.md with equivalent changes**

Apply the same changes to `README_zh.md` (translated to Chinese where applicable).

- [ ] **Step 5: Commit**

```bash
git add README.md README_zh.md
git commit -m "docs: document --ports flag and updated firewall script usage"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests PASS

- [ ] **Step 2: Verify build**

Run: `cargo build --release`
Expected: Build succeeds

- [ ] **Step 3: Check help output**

Run: `./target/release/trans_proxy --help`
Expected: `--ports` flag appears with description

- [ ] **Step 4: Verify script syntax**

Run: `bash -n scripts/pf_setup.sh && bash -n scripts/nftables_setup.sh`
Expected: No errors
