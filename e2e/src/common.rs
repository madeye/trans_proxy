//! Shared utilities for e2e tests across platforms.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};

pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const EXPECTED_BODY: &str = "trans_proxy_e2e_ok\n";

#[derive(Deserialize)]
pub struct TestServerPorts {
    pub socks5_port: u16,
    pub http_connect_port: u16,
    pub http_dest_port: u16,
    pub http_dest_addr: String,
}

/// Guard that kills a child process on drop.
pub struct ProcessGuard {
    pub child: Child,
    pub name: String,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("  Stopped {}", self.name);
    }
}

pub fn find_project_root() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut dir = exe.parent().unwrap().to_path_buf();
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("scripts").exists() {
            return dir;
        }
        if !dir.pop() {
            return std::env::current_dir().unwrap();
        }
    }
}

pub fn start_test_servers(
    root: &Path,
    envs: &[(&str, &str)],
) -> Result<(ProcessGuard, TestServerPorts)> {
    let bin = root.join("target/release/test_servers");
    let mut cmd = Command::new(&bin);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start test_servers at {}", bin.display()))?;

    let stdout = child.stdout.take().context("no stdout")?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let ports: TestServerPorts =
        serde_json::from_str(line.trim()).context("failed to parse test_servers port JSON")?;

    eprintln!(
        "  test_servers: socks5={}, http_connect={}, http_dest={}@{}",
        ports.socks5_port, ports.http_connect_port, ports.http_dest_port, ports.http_dest_addr
    );

    let guard = ProcessGuard {
        child,
        name: "test_servers".into(),
    };
    Ok((guard, ports))
}

pub fn start_trans_proxy(
    root: &Path,
    listen_port: u16,
    upstream: &str,
    extra_args: &[&str],
) -> Result<ProcessGuard> {
    let bin = root.join("target/release/trans_proxy");
    let mut cmd = Command::new(&bin);
    cmd.arg("--listen-addr")
        .arg(format!("127.0.0.1:{listen_port}"))
        .arg("--upstream-proxy")
        .arg(upstream)
        .arg("--local-traffic")
        .arg("--log-level")
        .arg("debug");

    for arg in extra_args {
        cmd.arg(arg);
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to start trans_proxy at {}", bin.display()))?;

    let guard = ProcessGuard {
        child,
        name: "trans_proxy".into(),
    };
    Ok(guard)
}

pub async fn wait_for_port(addr: SocketAddr) -> Result<()> {
    timeout(STARTUP_TIMEOUT, async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context(format!("timeout waiting for {addr}"))?;
    Ok(())
}

/// Send an HTTP GET and return the response body.
/// Optionally bind to a specific local address (needed on macOS for pf source matching).
pub async fn http_get(addr: SocketAddr, bind_from: Option<SocketAddr>) -> Result<String> {
    let stream = if let Some(local) = bind_from {
        let socket = TcpSocket::new_v4()?;
        socket.bind(local)?;
        timeout(REQUEST_TIMEOUT, socket.connect(addr)).await
    } else {
        timeout(REQUEST_TIMEOUT, TcpStream::connect(addr)).await
    }
    .context("timeout connecting")?
    .context("failed to connect")?;

    let mut stream = stream;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .context("timeout reading response")?
        .context("failed to read")?;

    let text = String::from_utf8(response)?;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok(body)
}

// ===== DNS helpers =====

const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;

pub fn build_dns_query(domain: &str, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pkt
}

pub fn build_dns_response(domain: &str, ip: Ipv4Addr, tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x81, 0x80]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&[0xC0, 0x0C]);
    pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    pkt.extend_from_slice(&60u32.to_be_bytes());
    pkt.extend_from_slice(&4u16.to_be_bytes());
    pkt.extend_from_slice(&ip.octets());
    pkt
}

/// Run a list of named test cases and report results.
pub fn report_results(results: Vec<(&str, Result<()>)>) -> Result<()> {
    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, result) in results {
        match result {
            Ok(()) => passed += 1,
            Err(e) => {
                eprintln!("  FAIL: {name}: {e:#}");
                failed += 1;
            }
        }
    }

    eprintln!("\n=== Results: {passed} passed, {failed} failed ===");
    if failed > 0 {
        bail!("{failed} test(s) failed");
    }
    Ok(())
}
