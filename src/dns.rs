//! Local DNS forwarder with IP→domain mapping capture.
//!
//! Listens directly on the gateway interface (port 53) for DNS queries from
//! LAN clients, forwards them to a configured upstream server (via UDP or
//! DNS-over-HTTPS), and parses A records from responses to build an IP→domain
//! lookup table shared with the proxy.
//!
//! # Purpose
//!
//! When a client resolves `example.com` → `93.184.216.34`, the DNS forwarder
//! records this mapping. Later, when the proxy intercepts a connection to
//! `93.184.216.34:80`, it can look up the hostname and send
//! `CONNECT example.com:80` instead of `CONNECT 93.184.216.34:80`.
//!
//! This is particularly useful for:
//! - Plain HTTP (port 80) where there is no TLS SNI to extract
//! - TLS clients that don't send SNI (rare but possible)
//! - Upstream proxies that require hostnames for routing or access control
//!
//! # Upstream modes
//!
//! - **DoH** (default: `https://cloudflare-dns.com/dns-query`): DNS-over-HTTPS
//!   (RFC 8484), sends the raw DNS wire format via HTTP POST with
//!   `application/dns-message`
//! - **UDP** (e.g., `8.8.8.8:53`): Traditional DNS over UDP
//!
//! # Cache
//!
//! The lookup table is capped at [`MAX_CACHE_ENTRIES`] (10,000). When full,
//! half the entries are evicted. Entries are not TTL-aware — they persist
//! until evicted or overwritten by a newer response.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::{DnsUpstream, ProxyAuth, ProxyProtocol, UpstreamProxy};

const MAX_DNS_PACKET: usize = 1500;
const MAX_CACHE_ENTRIES: usize = 10_000;
const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 3600;

// DNS header flags / record types
const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;

/// Shared IP→domain lookup table.
#[derive(Clone)]
pub struct DnsTable {
    inner: Arc<RwLock<HashMap<Ipv4Addr, String>>>,
}

impl DnsTable {
    /// Create an empty DNS lookup table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up a domain name for the given IP address.
    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<String> {
        self.inner.read().ok()?.get(ip).cloned()
    }

    /// Insert an IP→domain mapping.
    fn insert(&self, ip: Ipv4Addr, domain: String) {
        if let Ok(mut map) = self.inner.write() {
            // Evict oldest entries if cache is too large
            if map.len() >= MAX_CACHE_ENTRIES {
                // Simple eviction: clear half the cache
                let keys: Vec<_> = map.keys().take(MAX_CACHE_ENTRIES / 2).copied().collect();
                for k in keys {
                    map.remove(&k);
                }
            }
            map.insert(ip, domain);
        }
    }
}

/// Cached DNS response with expiration.
struct DnsCacheEntry {
    response: Vec<u8>,
    expires: Instant,
}

/// TTL-aware DNS response cache for DoH.
struct DnsCache {
    entries: RwLock<HashMap<String, DnsCacheEntry>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a cached response, returning it with the transaction ID rewritten.
    fn get(&self, name: &str, tx_id: u16) -> Option<Vec<u8>> {
        let map = self.entries.read().ok()?;
        let entry = map.get(name)?;
        if entry.expires <= Instant::now() {
            return None;
        }
        let mut resp = entry.response.clone();
        // Rewrite transaction ID to match the current query
        if resp.len() >= 2 {
            let id_bytes = tx_id.to_be_bytes();
            resp[0] = id_bytes[0];
            resp[1] = id_bytes[1];
        }
        Some(resp)
    }

    /// Cache a response, extracting the minimum TTL from answer records.
    fn put(&self, name: &str, response: &[u8]) {
        let ttl = extract_min_ttl(response)
            .unwrap_or(MIN_TTL)
            .clamp(MIN_TTL, MAX_TTL);
        let entry = DnsCacheEntry {
            response: response.to_vec(),
            expires: Instant::now() + Duration::from_secs(ttl as u64),
        };
        if let Ok(mut map) = self.entries.write() {
            // Simple eviction when cache is full
            if map.len() >= MAX_CACHE_ENTRIES {
                let stale: Vec<String> = map
                    .iter()
                    .filter(|(_, v)| v.expires <= Instant::now())
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in stale {
                    map.remove(&k);
                }
                // If still full, drop half
                if map.len() >= MAX_CACHE_ENTRIES {
                    let keys: Vec<String> =
                        map.keys().take(MAX_CACHE_ENTRIES / 2).cloned().collect();
                    for k in keys {
                        map.remove(&k);
                    }
                }
            }
            map.insert(name.to_string(), entry);
        }
    }
}

/// Extract the minimum TTL from answer records in a DNS response.
fn extract_min_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        pos += 4;
        if pos > packet.len() {
            return None;
        }
    }
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            break;
        }
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if ttl < min_ttl {
            min_ttl = ttl;
        }
    }
    if min_ttl == u32::MAX {
        None
    } else {
        Some(min_ttl)
    }
}

/// In-flight query coalescer: deduplicates concurrent DoH queries for the same domain.
struct QueryCoalescer {
    in_flight: RwLock<HashMap<String, broadcast::Sender<Vec<u8>>>>,
}

impl QueryCoalescer {
    fn new() -> Self {
        Self {
            in_flight: RwLock::new(HashMap::new()),
        }
    }

    /// Try to join an existing in-flight query. Returns a receiver if one exists.
    fn try_join(&self, name: &str) -> Option<broadcast::Receiver<Vec<u8>>> {
        let map = self.in_flight.read().ok()?;
        map.get(name).map(|tx| tx.subscribe())
    }

    /// Register a new in-flight query. Returns the sender to broadcast the result.
    fn register(&self, name: &str) -> broadcast::Sender<Vec<u8>> {
        let (tx, _) = broadcast::channel(1);
        if let Ok(mut map) = self.in_flight.write() {
            map.insert(name.to_string(), tx.clone());
        }
        tx
    }

    /// Remove a completed in-flight query.
    fn complete(&self, name: &str) {
        if let Ok(mut map) = self.in_flight.write() {
            map.remove(name);
        }
    }
}

/// Run the DNS forwarder, dispatching to UDP or DoH based on upstream config.
pub async fn run(
    listen_addr: SocketAddr,
    upstream: DnsUpstream,
    table: DnsTable,
    upstream_proxy: &UpstreamProxy,
) -> Result<()> {
    match upstream {
        DnsUpstream::Udp(addr) => run_udp(listen_addr, addr, table).await,
        DnsUpstream::Https(url) => run_doh(listen_addr, url, table, upstream_proxy).await,
    }
}

/// Run the DNS forwarder with a traditional UDP upstream.
async fn run_udp(listen_addr: SocketAddr, upstream_dns: SocketAddr, table: DnsTable) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .context("Failed to bind DNS listener")?;
    info!(
        "DNS forwarder listening on {}, upstream UDP {}",
        listen_addr, upstream_dns
    );

    let upstream_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind upstream DNS socket")?;
    upstream_socket.connect(upstream_dns).await?;

    // Track pending queries: (transaction_id, client_addr) → query_name
    let pending: Arc<RwLock<HashMap<(u16, SocketAddr), String>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let socket = Arc::new(socket);
    let upstream_socket = Arc::new(upstream_socket);

    // Spawn reader for upstream responses
    let resp_socket = Arc::clone(&socket);
    let resp_upstream = Arc::clone(&upstream_socket);
    let resp_pending = Arc::clone(&pending);
    let resp_table = table.clone();

    let _upstream_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DNS_PACKET];
        loop {
            let n = match resp_upstream.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!("DNS upstream recv error: {}", e);
                    continue;
                }
            };

            let packet = &buf[..n];

            // Extract transaction ID
            if packet.len() < 12 {
                continue;
            }
            let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

            // Look up the original client(s) for this transaction ID
            let clients: Vec<(SocketAddr, String)> = {
                let mut map = match resp_pending.write() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                // Collect all entries matching this tx_id (multiple clients may share the same ID)
                let matching_keys: Vec<(u16, SocketAddr)> =
                    map.keys().filter(|(id, _)| *id == tx_id).copied().collect();
                matching_keys
                    .into_iter()
                    .filter_map(|key| map.remove(&key).map(|name| (key.1, name)))
                    .collect()
            };

            if clients.is_empty() {
                continue;
            }

            // Use the query name from the first client (they all queried the same name for this tx_id response)
            let query_name = &clients[0].1;

            // Parse A records from the response and populate the table
            let resolved_ips = parse_a_records(packet);
            if let Some(ref ips) = resolved_ips {
                for ip in ips {
                    debug!("DNS resolved: {} -> {}", query_name, ip);
                    resp_table.insert(*ip, query_name.clone());
                }
            }

            let client_addrs: Vec<_> = clients.iter().map(|(addr, _)| addr.to_string()).collect();
            info!(
                "DNS response: {} -> {} (tx_id=0x{:04x}, clients={})",
                query_name,
                resolved_ips
                    .as_ref()
                    .map(|ips| ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_else(|| "no A records".into()),
                tx_id,
                client_addrs.join(",")
            );

            // Forward response back to all matching clients
            for (client_addr, _) in &clients {
                if let Err(e) = resp_socket.send_to(packet, client_addr).await {
                    warn!("DNS: failed to send response to {}: {}", client_addr, e);
                }
            }
        }
    });

    // Main loop: read queries from clients, forward to upstream
    let mut buf = vec![0u8; MAX_DNS_PACKET];
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let packet = &buf[..n];

        if packet.len() < 12 {
            continue;
        }

        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Extract the query name for later use
        let query_name = parse_query_name(packet).unwrap_or_default();

        debug!(
            "DNS query from {}: {} (tx_id=0x{:04x})",
            client_addr, query_name, tx_id
        );

        // Store pending query keyed by (tx_id, client_addr) to avoid collisions
        if let Ok(mut map) = pending.write() {
            map.insert((tx_id, client_addr), query_name);
        }

        // Forward to upstream
        if let Err(e) = upstream_socket.send(packet).await {
            warn!("DNS: failed to forward query to upstream: {}", e);
        }
    }
}

/// Run the DNS forwarder with a DNS-over-HTTPS upstream (RFC 8484).
///
/// Uses HTTP/2 connection pooling, a TTL-aware response cache, and query
/// coalescing to minimize DoH round-trips.
async fn run_doh(
    listen_addr: SocketAddr,
    doh_url: String,
    table: DnsTable,
    upstream_proxy: &UpstreamProxy,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind DNS listener")?,
    );
    info!(
        "DNS forwarder listening on {}, upstream DoH {}",
        listen_addr, doh_url
    );

    // Build an HTTP/2-capable client that routes through the upstream proxy
    let proxy_url = match &upstream_proxy.protocol {
        ProxyProtocol::HttpConnect => format!("http://{}", upstream_proxy.addr),
        ProxyProtocol::Socks5(ProxyAuth::None) => {
            format!("socks5://{}", upstream_proxy.addr)
        }
        ProxyProtocol::Socks5(ProxyAuth::UsernamePassword { username, password }) => {
            format!("socks5://{}:{}@{}", username, password, upstream_proxy.addr)
        }
    };
    let proxy = reqwest::Proxy::all(&proxy_url).context("Invalid upstream proxy URL for DoH")?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(300))
        .build()
        .context("Failed to build HTTP client for DoH")?;
    info!(
        "DoH requests routed through upstream proxy {}",
        upstream_proxy
    );

    let cache = Arc::new(DnsCache::new());
    let coalescer = Arc::new(QueryCoalescer::new());

    let mut buf = vec![0u8; MAX_DNS_PACKET];
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();

        if packet.len() < 12 {
            continue;
        }

        let query_name = parse_query_name(&packet).unwrap_or_default();
        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

        debug!("DNS query from {}: {} (DoH)", client_addr, query_name);

        // Fast path: serve from cache
        if let Some(cached) = cache.get(&query_name, tx_id) {
            // Still populate the DNS table from cached response
            let resolved_ips = parse_a_records(&cached);
            if let Some(ref ips) = resolved_ips {
                for ip in ips {
                    table.insert(*ip, query_name.clone());
                }
            }
            info!(
                "DNS response (DoH/cached): {} -> {} (client={})",
                query_name,
                resolved_ips
                    .as_ref()
                    .map(|ips| ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_else(|| "no A records".into()),
                client_addr
            );
            if let Err(e) = socket.send_to(&cached, client_addr).await {
                warn!(
                    "DNS: failed to send cached response to {}: {}",
                    client_addr, e
                );
            }
            continue;
        }

        // Coalesce: if another task is already querying this domain, wait for its result
        if let Some(mut rx) = coalescer.try_join(&query_name) {
            let socket = Arc::clone(&socket);
            let table = table.clone();
            let query_name = query_name.clone();
            tokio::spawn(async move {
                match rx.recv().await {
                    Ok(response) => {
                        // Rewrite tx_id for this client
                        let mut resp = response;
                        if resp.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            resp[0] = id_bytes[0];
                            resp[1] = id_bytes[1];
                        }
                        let resolved_ips = parse_a_records(&resp);
                        if let Some(ref ips) = resolved_ips {
                            for ip in ips {
                                table.insert(*ip, query_name.clone());
                            }
                        }
                        if let Err(e) = socket.send_to(&resp, client_addr).await {
                            warn!(
                                "DNS: failed to send coalesced response to {}: {}",
                                client_addr, e
                            );
                        }
                    }
                    Err(_) => {
                        warn!("DNS: coalesced query for {} dropped", query_name);
                    }
                }
            });
            continue;
        }

        // Register this query as in-flight
        let tx = coalescer.register(&query_name);

        let socket = Arc::clone(&socket);
        let client = client.clone();
        let doh_url = doh_url.clone();
        let table = table.clone();
        let cache = Arc::clone(&cache);
        let coalescer = Arc::clone(&coalescer);
        let query_name_owned = query_name.clone();

        tokio::spawn(async move {
            match doh_query(&client, &doh_url, &packet).await {
                Ok(response) => {
                    // Cache the response
                    cache.put(&query_name_owned, &response);

                    // Broadcast to coalesced waiters
                    let _ = tx.send(response.clone());
                    coalescer.complete(&query_name_owned);

                    // Parse A records and populate the table
                    let resolved_ips = parse_a_records(&response);
                    if let Some(ref ips) = resolved_ips {
                        for ip in ips {
                            debug!("DNS resolved: {} -> {} (DoH)", query_name_owned, ip);
                            table.insert(*ip, query_name_owned.clone());
                        }
                    }

                    info!(
                        "DNS response (DoH): {} -> {} (client={})",
                        query_name_owned,
                        resolved_ips
                            .as_ref()
                            .map(|ips| ips
                                .iter()
                                .map(|ip| ip.to_string())
                                .collect::<Vec<_>>()
                                .join(","))
                            .unwrap_or_else(|| "no A records".into()),
                        client_addr
                    );

                    // Send response back to the original client
                    if let Err(e) = socket.send_to(&response, client_addr).await {
                        warn!("DNS: failed to send DoH response to {}: {}", client_addr, e);
                    }
                }
                Err(e) => {
                    coalescer.complete(&query_name_owned);
                    warn!("DoH query for {} failed: {:#}", query_name_owned, e);
                }
            }
        });
    }
}

/// Send a DNS wire-format query to a DoH server and return the wire-format response.
async fn doh_query(client: &reqwest::Client, url: &str, query: &[u8]) -> Result<Vec<u8>> {
    let response = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .context("DoH request failed")?;

    if !response.status().is_success() {
        anyhow::bail!("DoH server returned status {}", response.status());
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read DoH response body")?;
    Ok(bytes.to_vec())
}

/// Parse the query name (QNAME) from a DNS packet.
fn parse_query_name(packet: &[u8]) -> Option<String> {
    // Skip header (12 bytes), then parse the name
    let mut pos = 12;
    let mut parts = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }
        // Compression pointer — shouldn't appear in QNAME but handle gracefully
        if len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        parts.push(std::str::from_utf8(&packet[pos..pos + len]).ok()?);
        pos += len;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

/// Parse A records from a DNS response packet. Returns the IPv4 addresses found.
fn parse_a_records(packet: &[u8]) -> Option<Vec<Ipv4Addr>> {
    if packet.len() < 12 {
        return None;
    }

    // Header: ID(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;

    // Skip question section
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        pos += 4; // QTYPE(2) + QCLASS(2)
        if pos > packet.len() {
            return None;
        }
    }

    // Parse answer section
    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            break;
        }

        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        // skip TTL (4 bytes)
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            break;
        }

        if rtype == DNS_TYPE_A && rclass == DNS_CLASS_IN && rdlength == 4 {
            let ip = Ipv4Addr::new(
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            );
            ips.push(ip);
        }

        pos += rdlength;
    }

    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// Skip a DNS name (handles compression pointers). Returns the position after the name.
fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= packet.len() {
            return None;
        }
        let b = packet[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total
            return Some(pos + 2);
        }
        pos += 1 + b as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS response with one A record for "example.com" → 93.184.216.34
    fn build_dns_response(domain: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // TX ID
        pkt.extend_from_slice(&[0x81, 0x80]); // flags: response, no error
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        pkt.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question section
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // end of name
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        // Answer section — use compression pointer to QNAME at offset 12
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        pkt.extend_from_slice(&ip.octets());

        pkt
    }

    #[test]
    fn test_parse_query_name() {
        let mut pkt = vec![0u8; 12]; // dummy header
                                     // "example.com"
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);

        assert_eq!(parse_query_name(&pkt), Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_a_records() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", ip);
        let ips = parse_a_records(&pkt).unwrap();
        assert_eq!(ips, vec![ip]);
    }

    #[test]
    fn test_parse_a_records_no_answer() {
        // Response with ANCOUNT=0
        let mut pkt = vec![0u8; 12];
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        assert_eq!(parse_a_records(&pkt), None);
    }

    /// Build a minimal DNS query for a domain name.
    fn build_dns_query(domain: &str, tx_id: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&tx_id.to_be_bytes()); // TX ID
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt
    }

    #[test]
    fn test_dns_cache_hit_and_miss() {
        let cache = DnsCache::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", ip);

        // Miss
        assert!(cache.get("example.com", 0x1234).is_none());

        // Put and hit
        cache.put("example.com", &pkt);
        let cached = cache.get("example.com", 0x1234).unwrap();
        assert!(cached.len() >= 12);
        // Verify tx_id was rewritten
        assert_eq!(cached[0], 0x12);
        assert_eq!(cached[1], 0x34);
        // Verify A record is still parseable
        let ips = parse_a_records(&cached).unwrap();
        assert_eq!(ips, vec![ip]);
    }

    #[test]
    fn test_extract_min_ttl() {
        let pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        // Our test builder uses TTL=60
        assert_eq!(extract_min_ttl(&pkt), Some(60));
    }

    /// Integration test: runs the UDP DNS forwarder with a fake upstream,
    /// sends a query, and verifies the full code path executes (including log statements).
    #[tokio::test]
    async fn test_dns_udp_query_response_logging() {
        // Set up tracing so debug! calls execute
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();

        // Bind a fake upstream DNS server
        let fake_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fake_upstream_addr = fake_upstream.local_addr().unwrap();

        // Create DNS table and start forwarder
        let table = DnsTable::new();
        let forwarder_table = table.clone();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind the forwarder listener manually to get the port
        let forwarder_socket = UdpSocket::bind(listen_addr).await.unwrap();
        let forwarder_addr = forwarder_socket.local_addr().unwrap();
        drop(forwarder_socket);

        // Start the DNS forwarder
        let forwarder = tokio::spawn(async move {
            let _ = run_udp(forwarder_addr, fake_upstream_addr, forwarder_table).await;
        });

        // Give the forwarder time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send a DNS query from a "client"
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query("example.com", 0xABCD);
        client_socket.send_to(&query, forwarder_addr).await.unwrap();

        // Fake upstream receives the forwarded query
        let mut buf = vec![0u8; MAX_DNS_PACKET];
        let (n, from_addr) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fake_upstream.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        // Verify the query was forwarded
        assert!(n >= 12);
        assert_eq!(parse_query_name(&buf[..n]), Some("example.com".to_string()));

        // Send a fake response back
        let response = build_dns_response("example.com", Ipv4Addr::new(93, 184, 216, 34));
        fake_upstream.send_to(&response, from_addr).await.unwrap();

        // Client should receive the response
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(n >= 12);

        // Verify the DNS table was populated (proves the info!/debug! code paths ran)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let resolved = table.lookup(&Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(resolved, Some("example.com".to_string()));

        forwarder.abort();
    }
}
