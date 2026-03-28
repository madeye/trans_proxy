mod fwmark;
mod http_connect;
mod http_dest;
mod socks5;

use serde::Serialize;

#[derive(Serialize)]
struct ServerInfo {
    socks5_port: u16,
    http_connect_port: u16,
    http_dest_port: u16,
    http_dest_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());

    let socks5 = socks5::Socks5Server::bind().await?;
    let http_connect = http_connect::HttpConnectServer::bind().await?;
    let http_dest = http_dest::HttpDestServer::bind(&bind_addr).await?;

    let info = ServerInfo {
        socks5_port: socks5.port(),
        http_connect_port: http_connect.port(),
        http_dest_port: http_dest.port(),
        http_dest_addr: http_dest.listener_addr().ip().to_string(),
    };

    // Print JSON port info for the e2e runner to parse
    println!("{}", serde_json::to_string(&info)?);

    // Run all servers concurrently
    tokio::select! {
        r = socks5.run() => r?,
        r = http_connect.run() => r?,
        r = http_dest.run() => r?,
    }

    Ok(())
}
