mod fwmark;
mod http_connect;
mod http_dest;
mod socks5;
mod udp_echo;

use serde::Serialize;

#[derive(Serialize)]
struct ServerInfo {
    socks5_port: u16,
    http_connect_port: u16,
    http_dest_port: u16,
    http_dest_addr: String,
    udp_echo_port: u16,
}

/// Read an optional fixed port from `key`; `0` (the default) means "pick a free
/// port". Fixed ports let the multi-container docker e2e address each server
/// deterministically; the loopback e2e leaves them unset and reads the JSON.
fn env_port(key: &str) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    // Proxies (SOCKS5 / HTTP CONNECT) default to loopback to preserve the
    // existing loopback e2e; the docker e2e sets PROXY_BIND_ADDR=0.0.0.0.
    let proxy_bind = std::env::var("PROXY_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    // Destinations (HTTP dest / UDP echo) use BIND_ADDR (an aliased IP on
    // macOS, 0.0.0.0 in docker).
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());

    let socks5 = socks5::Socks5Server::bind(&proxy_bind, env_port("SOCKS5_PORT")).await?;
    let http_connect =
        http_connect::HttpConnectServer::bind(&proxy_bind, env_port("HTTP_CONNECT_PORT")).await?;
    let http_dest = http_dest::HttpDestServer::bind(&bind_addr, env_port("HTTP_DEST_PORT")).await?;
    let udp_echo = udp_echo::UdpEchoServer::bind(&bind_addr, env_port("UDP_ECHO_PORT")).await?;

    let info = ServerInfo {
        socks5_port: socks5.port(),
        http_connect_port: http_connect.port(),
        http_dest_port: http_dest.port(),
        http_dest_addr: http_dest.listener_addr().ip().to_string(),
        udp_echo_port: udp_echo.port(),
    };

    // Print JSON port info for the e2e runner to parse
    println!("{}", serde_json::to_string(&info)?);

    // Run all servers concurrently
    tokio::select! {
        r = socks5.run() => r?,
        r = http_connect.run() => r?,
        r = http_dest.run() => r?,
        r = udp_echo.run() => r?,
    }

    Ok(())
}
