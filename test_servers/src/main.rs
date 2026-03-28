mod http_connect;
mod http_dest;
mod socks5;

use serde::Serialize;

#[derive(Serialize)]
struct Ports {
    socks5_port: u16,
    http_connect_port: u16,
    http_dest_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let socks5 = socks5::Socks5Server::bind().await?;
    let http_connect = http_connect::HttpConnectServer::bind().await?;
    let http_dest = http_dest::HttpDestServer::bind().await?;

    let ports = Ports {
        socks5_port: socks5.port(),
        http_connect_port: http_connect.port(),
        http_dest_port: http_dest.port(),
    };

    // Print JSON port info for the e2e runner to parse
    println!("{}", serde_json::to_string(&ports)?);

    // Run all servers concurrently
    tokio::select! {
        r = socks5.run() => r?,
        r = http_connect.run() => r?,
        r = http_dest.run() => r?,
    }

    Ok(())
}
