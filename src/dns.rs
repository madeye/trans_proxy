//! Local DNS forwarder with IP→domain mapping capture.
//!
//! Listens directly on the gateway interface (port 53, both UDP and TCP) for
//! DNS queries from LAN clients, forwards them to a configured upstream
//! server (via UDP or DNS-over-HTTPS), and parses A records from responses to
//! build an IP→domain lookup table shared with the proxy.
//!
//! The TCP listener implements RFC 7766 framing (2-byte big-endian length
//! prefix per message) so clients retrying truncated UDP responses over TCP
//! keep working when the firewall intercepts TCP port 53.
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
//! # AAAA stripping
//!
//! With `--dns-strip-aaaa`, AAAA queries are answered locally with an empty
//! NOERROR (NODATA) response on all listeners (UDP, TCP, DoH upstream alike)
//! and never forwarded. This keeps dual-stack clients on IPv4 — the only
//! address family the transparent proxy intercepts — so IPv6-capable
//! destinations cannot bypass the proxy and leak the real client address.
//!
//! # UDP hardening
//!
//! In UDP mode, each upstream query is sent with a fresh random transaction
//! ID (rewritten back to the client's original ID before replying), and an
//! upstream packet is only accepted if its QR bit is set and its question
//! name/type match the pending query for that ID. This mitigates off-path
//! response spoofing and prevents the IP→domain table from being poisoned
//! with mismatched names. Pending queries expire after
//! [`PENDING_QUERY_TTL`] and the map is capped at [`MAX_PENDING_QUERIES`].
//!
//! # Cache
//!
//! The lookup table is capped at [`MAX_CACHE_ENTRIES`] (10,000). Each entry
//! expires after the response's minimum TTL, clamped to
//! [`TABLE_TTL_FLOOR`]..[`TABLE_TTL_CEIL`]; expired entries are skipped on
//! lookup. When the table is full, expired entries are evicted first, then
//! half the remaining entries as a fallback.
//!
//! The DoH response cache is TTL-aware as well: cached responses are replayed
//! with the record TTLs decremented by the time spent in the cache.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::{DnsUpstream, ProxyAuth, ProxyProtocol, UpstreamProxy};

/// Maximum DNS message size over UDP (EDNS0 responses can far exceed 1500
/// bytes; recv() silently truncates anything larger than the buffer).
const MAX_UDP_DNS_PACKET: usize = 65_535;
/// Per-query timeout for TCP DNS forwarding (read body + upstream round-trip).
const TCP_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle timeout for a TCP DNS connection waiting for the next query.
const TCP_DNS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CACHE_ENTRIES: usize = 10_000;
/// How long an unanswered upstream query stays in the pending map.
const PENDING_QUERY_TTL: Duration = Duration::from_secs(5);
/// Hard cap on outstanding upstream queries (oldest evicted when full).
const MAX_PENDING_QUERIES: usize = 4096;
const MIN_TTL: u32 = 30;
const MAX_TTL: u32 = 3600;

/// Floor for IP→domain table entry lifetimes. The proxy benefits from
/// generous retention: clients often reuse a resolved IP well past short
/// CDN TTLs (e.g. 30s), and a stale-but-recent mapping is still the best
/// hostname guess for an intercepted connection.
const TABLE_TTL_FLOOR: u32 = 300;
/// Ceiling for IP→domain table entry lifetimes (one day), bounding how long
/// a mapping can outlive an IP reassignment.
const TABLE_TTL_CEIL: u32 = 86_400;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_OPT: u16 = 41;
const DNS_CLASS_IN: u16 = 1;

/// Shared IP→domain lookup table (supports both IPv4 and IPv6).
#[derive(Clone)]
pub struct DnsTable {
    inner: Arc<RwLock<HashMap<IpAddr, (String, Instant)>>>,
}

impl DnsTable {
    /// Create an empty DNS lookup table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up a domain name for the given IP address. Expired entries
    /// return `None`.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let map = self.inner.read().ok()?;
        let (domain, expires) = map.get(ip)?;
        if *expires <= Instant::now() {
            return None;
        }
        Some(domain.clone())
    }

    /// Insert an IP→domain mapping that expires after `ttl_secs`.
    fn insert(&self, ip: IpAddr, domain: String, ttl_secs: u32) {
        let expires = Instant::now() + Duration::from_secs(ttl_secs as u64);
        if let Ok(mut map) = self.inner.write() {
            if map.len() >= MAX_CACHE_ENTRIES {
                // Evict expired entries first
                let now = Instant::now();
                map.retain(|_, (_, exp)| *exp > now);
                // If still full, fall back to dropping half
                if map.len() >= MAX_CACHE_ENTRIES {
                    let keys: Vec<_> = map.keys().take(MAX_CACHE_ENTRIES / 2).copied().collect();
                    for k in keys {
                        map.remove(&k);
                    }
                }
            }
            map.insert(ip, (domain, expires));
        }
    }
}

/// Derive the table entry TTL from a DNS response: the minimum answer TTL,
/// clamped to [`TABLE_TTL_FLOOR`]..[`TABLE_TTL_CEIL`], defaulting to the
/// floor when no TTL can be extracted.
fn table_ttl(response: &[u8]) -> u32 {
    extract_min_ttl(response)
        .unwrap_or(TABLE_TTL_FLOOR)
        .clamp(TABLE_TTL_FLOOR, TABLE_TTL_CEIL)
}

/// Cached DNS response with expiration.
struct DnsCacheEntry {
    response: Vec<u8>,
    inserted: Instant,
    expires: Instant,
}

/// TTL-aware DNS response cache for DoH.
struct DnsCache {
    entries: RwLock<HashMap<Vec<u8>, DnsCacheEntry>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a cached response, returning it with the transaction ID
    /// rewritten and record TTLs decremented by the time spent in the cache.
    fn get(&self, key: &[u8], tx_id: u16) -> Option<Vec<u8>> {
        let map = self.entries.read().ok()?;
        let entry = map.get(key)?;
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
        // Decrement TTLs by the entry's age so clients don't over-cache
        let elapsed = entry.inserted.elapsed().as_secs().min(u32::MAX as u64) as u32;
        if elapsed > 0 {
            let _ = rewrite_ttls(&mut resp, elapsed);
        }
        Some(resp)
    }

    /// Cache a response, extracting the minimum TTL from answer records.
    fn put(&self, key: Vec<u8>, response: &[u8]) {
        let ttl = extract_min_ttl(response)
            .unwrap_or(MIN_TTL)
            .clamp(MIN_TTL, MAX_TTL);
        let now = Instant::now();
        let entry = DnsCacheEntry {
            response: response.to_vec(),
            inserted: now,
            expires: now + Duration::from_secs(ttl as u64),
        };
        if let Ok(mut map) = self.entries.write() {
            // Simple eviction when cache is full
            if map.len() >= MAX_CACHE_ENTRIES {
                let stale: Vec<Vec<u8>> = map
                    .iter()
                    .filter(|(_, v)| v.expires <= Instant::now())
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in stale {
                    map.remove(&k);
                }
                // If still full, drop half
                if map.len() >= MAX_CACHE_ENTRIES {
                    let keys: Vec<Vec<u8>> =
                        map.keys().take(MAX_CACHE_ENTRIES / 2).cloned().collect();
                    for k in keys {
                        map.remove(&k);
                    }
                }
            }
            map.insert(key, entry);
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

/// Rewrite the TTL of every resource record (answer, authority, additional)
/// in a DNS response to `original_ttl - elapsed_secs`, floored at 1. OPT
/// pseudo-records (EDNS) are skipped since their TTL field carries flags.
fn rewrite_ttls(packet: &mut [u8], elapsed_secs: u32) -> Option<()> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(packet, pos)?;
        pos += 4;
        if pos > packet.len() {
            return None;
        }
    }
    for _ in 0..(ancount + nscount + arcount) {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        if rtype != DNS_TYPE_OPT {
            let ttl = u32::from_be_bytes([
                packet[pos + 4],
                packet[pos + 5],
                packet[pos + 6],
                packet[pos + 7],
            ]);
            let new_ttl = ttl.saturating_sub(elapsed_secs).max(1);
            packet[pos + 4..pos + 8].copy_from_slice(&new_ttl.to_be_bytes());
        }
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if pos > packet.len() {
            return None;
        }
    }
    Some(())
}

/// Synthesize a minimal answerless response from a DNS query: same
/// transaction ID, QR=1, RA=1, the given RCODE, question section echoed,
/// all other sections empty.
fn build_empty_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(query, pos)?;
        pos += 4;
        if pos > query.len() {
            return None;
        }
    }
    let mut resp = Vec::with_capacity(pos);
    resp.extend_from_slice(&query[..12]);
    // QR=1; preserve opcode and RD; clear AA/TC
    resp[2] = 0x80 | (query[2] & 0x79);
    // RA=1 plus the response code
    resp[3] = 0x80 | (rcode & 0x0F);
    // ANCOUNT = NSCOUNT = ARCOUNT = 0 (question count preserved)
    resp[6..12].fill(0);
    resp.extend_from_slice(&query[12..pos]);
    Some(resp)
}

/// Synthesize a SERVFAIL (RCODE=2) response for a failed query.
fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    build_empty_response(query, 2)
}

/// Synthesize an empty NOERROR (NODATA) response, used to suppress AAAA
/// answers when `--dns-strip-aaaa` is enabled.
fn build_nodata(query: &[u8]) -> Option<Vec<u8>> {
    build_empty_response(query, 0)
}

/// In-flight query coalescer: deduplicates concurrent DoH queries for the same domain.
struct QueryCoalescer {
    in_flight: RwLock<HashMap<Vec<u8>, broadcast::Sender<Vec<u8>>>>,
}

impl QueryCoalescer {
    fn new() -> Self {
        Self {
            in_flight: RwLock::new(HashMap::new()),
        }
    }

    /// Try to join an existing in-flight query. Returns a receiver if one exists.
    fn try_join(&self, key: &[u8]) -> Option<broadcast::Receiver<Vec<u8>>> {
        let map = self.in_flight.read().ok()?;
        map.get(key).map(|tx| tx.subscribe())
    }

    /// Register a new in-flight query. Returns the sender to broadcast the result.
    fn register(&self, key: Vec<u8>) -> broadcast::Sender<Vec<u8>> {
        let (tx, _) = broadcast::channel(1);
        if let Ok(mut map) = self.in_flight.write() {
            map.insert(key, tx.clone());
        }
        tx
    }

    /// Remove a completed in-flight query.
    fn complete(&self, key: &[u8]) {
        if let Ok(mut map) = self.in_flight.write() {
            map.remove(key);
        }
    }
}

/// Run the DNS forwarder, dispatching to UDP or DoH based on upstream config.
///
/// Runs a UDP listener and an RFC 7766 TCP listener concurrently on the same
/// address; if either fails, the error propagates to the caller.
pub async fn run(
    listen_addr: SocketAddr,
    upstream: DnsUpstream,
    table: DnsTable,
    upstream_proxy: &UpstreamProxy,
    strip_aaaa: bool,
) -> Result<()> {
    let tcp_upstream = match &upstream {
        DnsUpstream::Udp(addr) => TcpDnsUpstream::Tcp(*addr),
        DnsUpstream::Https(url) => TcpDnsUpstream::Doh {
            client: build_doh_client(upstream_proxy)?,
            url: url.clone(),
        },
    };
    if strip_aaaa {
        info!("DNS forwarder answering AAAA queries with empty NOERROR (--dns-strip-aaaa)");
    }

    let udp = async {
        match upstream {
            DnsUpstream::Udp(addr) => run_udp(listen_addr, addr, table.clone(), strip_aaaa).await,
            DnsUpstream::Https(url) => {
                run_doh(listen_addr, url, table.clone(), upstream_proxy, strip_aaaa).await
            }
        }
    };
    let tcp = run_tcp(listen_addr, tcp_upstream, table.clone(), strip_aaaa);

    tokio::try_join!(udp, tcp)?;
    Ok(())
}

/// Upstream target for the TCP DNS listener.
#[derive(Clone)]
enum TcpDnsUpstream {
    /// Forward over a TCP connection to the same address as the UDP upstream.
    Tcp(SocketAddr),
    /// Forward via DNS-over-HTTPS (no message size constraints).
    Doh {
        client: reqwest::Client,
        url: String,
    },
}

impl std::fmt::Display for TcpDnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpDnsUpstream::Tcp(addr) => write!(f, "TCP {}", addr),
            TcpDnsUpstream::Doh { url, .. } => write!(f, "DoH {}", url),
        }
    }
}

/// Build an HTTP/2-capable DoH client that routes through the upstream proxy.
///
/// Mirrors the client construction in [`run_doh`]; kept as a separate,
/// dedicated client so the TCP listener does not share state with the UDP
/// DoH path.
fn build_doh_client(upstream_proxy: &UpstreamProxy) -> Result<reqwest::Client> {
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
    reqwest::Client::builder()
        .proxy(proxy)
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(300))
        .build()
        .context("Failed to build HTTP client for DoH")
}

/// Run the TCP DNS listener (RFC 7766).
///
/// Accepts length-prefixed DNS queries, forwards them upstream (over TCP for
/// a UDP upstream address, or via DoH), populates the shared [`DnsTable`],
/// and writes length-prefixed responses back.
async fn run_tcp(
    listen_addr: SocketAddr,
    upstream: TcpDnsUpstream,
    table: DnsTable,
    strip_aaaa: bool,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "Failed to bind TCP DNS listener on {}: port already in use by another process",
                listen_addr
            )
        } else {
            anyhow::anyhow!("Failed to bind TCP DNS listener on {}: {}", listen_addr, e)
        }
    })?;
    info!(
        "DNS forwarder listening on {} (TCP), upstream {}",
        listen_addr, upstream
    );

    loop {
        let (stream, client_addr) = listener.accept().await.context("TCP DNS accept failed")?;
        let upstream = upstream.clone();
        let table = table.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_dns_client(stream, client_addr, upstream, table, strip_aaaa).await
            {
                debug!("TCP DNS connection from {} closed: {:#}", client_addr, e);
            }
        });
    }
}

/// Handle one TCP DNS client connection: read length-prefixed queries in a
/// loop, forward each upstream, and write back length-prefixed responses.
async fn handle_tcp_dns_client(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    upstream: TcpDnsUpstream,
    table: DnsTable,
    strip_aaaa: bool,
) -> Result<()> {
    loop {
        // Wait for the next query's 2-byte length prefix (idle timeout).
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(TCP_DNS_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Err(_) => {
                debug!("TCP DNS: idle timeout for {}", client_addr);
                return Ok(());
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e).context("failed to read query length"),
            Ok(Ok(_)) => {}
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len < 12 {
            anyhow::bail!("query too short ({len} bytes)");
        }

        let mut query = vec![0u8; len];
        tokio::time::timeout(TCP_DNS_QUERY_TIMEOUT, stream.read_exact(&mut query))
            .await
            .context("timed out reading query body")?
            .context("failed to read query body")?;

        let query_name = parse_query_name(&query).unwrap_or_default();
        debug!("DNS query from {} (TCP): {}", client_addr, query_name);

        // Suppress AAAA resolution so dual-stack clients stay on IPv4
        if strip_aaaa && parse_query_type(&query) == Some(DNS_TYPE_AAAA) {
            if let Some(resp) = build_nodata(&query) {
                debug!(
                    "DNS: stripped AAAA query for {} from {} (TCP)",
                    query_name, client_addr
                );
                stream
                    .write_all(&(resp.len() as u16).to_be_bytes())
                    .await
                    .context("failed to write NODATA length")?;
                stream
                    .write_all(&resp)
                    .await
                    .context("failed to write NODATA body")?;
            }
            continue;
        }

        let response = match tokio::time::timeout(
            TCP_DNS_QUERY_TIMEOUT,
            forward_tcp_dns_query(&upstream, &query),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                warn!("TCP DNS query for {} failed: {:#}", query_name, e);
                return Ok(());
            }
            Err(_) => {
                warn!("TCP DNS query for {} timed out", query_name);
                return Ok(());
            }
        };
        if response.len() < 12 || response.len() > u16::MAX as usize {
            anyhow::bail!("invalid upstream response length {}", response.len());
        }

        // Parse A/AAAA records and populate the shared table
        let resolved_ips = parse_ip_records(&response);
        if let Some(ref ips) = resolved_ips {
            let ttl = table_ttl(&response);
            for ip in ips {
                debug!("DNS resolved: {} -> {} (TCP)", query_name, ip);
                table.insert(*ip, query_name.clone(), ttl);
            }
        }

        info!(
            "DNS response (TCP): {} -> {} (client={})",
            query_name,
            resolved_ips
                .as_ref()
                .map(|ips| ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_else(|| "no A/AAAA records".into()),
            client_addr
        );

        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .context("failed to write response length")?;
        stream
            .write_all(&response)
            .await
            .context("failed to write response body")?;
    }
}

/// Forward a single DNS query upstream for the TCP listener.
async fn forward_tcp_dns_query(upstream: &TcpDnsUpstream, query: &[u8]) -> Result<Vec<u8>> {
    match upstream {
        TcpDnsUpstream::Tcp(addr) => {
            let mut conn = TcpStream::connect(addr)
                .await
                .with_context(|| format!("failed to connect to upstream DNS {addr} over TCP"))?;
            conn.write_all(&(query.len() as u16).to_be_bytes())
                .await
                .context("failed to send query length upstream")?;
            conn.write_all(query)
                .await
                .context("failed to send query upstream")?;

            let mut len_buf = [0u8; 2];
            conn.read_exact(&mut len_buf)
                .await
                .context("failed to read upstream response length")?;
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut response = vec![0u8; len];
            conn.read_exact(&mut response)
                .await
                .context("failed to read upstream response body")?;
            Ok(response)
        }
        TcpDnsUpstream::Doh { client, url } => doh_query(client, url, query).await,
    }
}

/// A client query awaiting its upstream response, keyed by the random
/// transaction ID we assigned to the upstream query.
struct PendingQuery {
    client_addr: SocketAddr,
    /// The client's original transaction ID, restored before replying.
    client_tx_id: u16,
    /// Query name, used to validate the response's question section.
    name: String,
    /// Query type (QTYPE), used to validate the response's question section.
    qtype: u16,
    created: Instant,
}

/// Insert a pending query under a fresh random upstream transaction ID.
///
/// Expired entries are swept opportunistically on every insert, and the map
/// is capped at [`MAX_PENDING_QUERIES`] (evicting the oldest entries when
/// full). Returns the assigned upstream transaction ID, or `None` if a free
/// ID could not be found.
fn pending_insert(
    map: &mut HashMap<u16, PendingQuery>,
    entry: PendingQuery,
    now: Instant,
) -> Option<u16> {
    // Sweep entries whose upstream response never arrived
    map.retain(|_, p| now.duration_since(p.created) < PENDING_QUERY_TTL);

    // Enforce the hard cap: evict the oldest entries to make room
    while map.len() >= MAX_PENDING_QUERIES {
        let oldest = map.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| *k)?;
        map.remove(&oldest);
    }

    // Pick a random unused transaction ID — the map holds at most 4096 of
    // 65536 possible IDs, so a free one is found almost immediately
    for _ in 0..64 {
        let id: u16 = rand::random();
        if let std::collections::hash_map::Entry::Vacant(slot) = map.entry(id) {
            slot.insert(entry);
            return Some(id);
        }
    }
    None
}

/// Remove and return the pending query for `tx_id`, but only if the
/// response's question name (case-insensitive) and type match the stored
/// query. A mismatch leaves the entry in place so the genuine response can
/// still be matched later.
fn pending_take_match(
    map: &mut HashMap<u16, PendingQuery>,
    tx_id: u16,
    resp_name: &str,
    resp_qtype: u16,
) -> Option<PendingQuery> {
    let entry = map.get(&tx_id)?;
    if !entry.name.eq_ignore_ascii_case(resp_name) || entry.qtype != resp_qtype {
        return None;
    }
    map.remove(&tx_id)
}

/// Run the DNS forwarder with a traditional UDP upstream.
async fn run_udp(
    listen_addr: SocketAddr,
    upstream_dns: SocketAddr,
    table: DnsTable,
    strip_aaaa: bool,
) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "Failed to bind DNS listener on {}: port already in use by another process",
                listen_addr
            )
        } else {
            anyhow::anyhow!("Failed to bind DNS listener on {}: {}", listen_addr, e)
        }
    })?;
    info!(
        "DNS forwarder listening on {}, upstream UDP {}",
        listen_addr, upstream_dns
    );

    let upstream_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind upstream DNS socket")?;
    upstream_socket.connect(upstream_dns).await?;

    // Track pending queries: random upstream transaction ID → original query
    let pending: Arc<RwLock<HashMap<u16, PendingQuery>>> = Arc::new(RwLock::new(HashMap::new()));

    let socket = Arc::new(socket);
    let upstream_socket = Arc::new(upstream_socket);

    // Spawn reader for upstream responses
    let resp_socket = Arc::clone(&socket);
    let resp_upstream = Arc::clone(&upstream_socket);
    let resp_pending = Arc::clone(&pending);
    let resp_table = table.clone();

    let _upstream_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
        loop {
            let n = match resp_upstream.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!("DNS upstream recv error: {}", e);
                    continue;
                }
            };

            if n < 12 {
                continue;
            }

            // Only accept actual responses (QR bit set)
            if buf[2] & 0x80 == 0 {
                continue;
            }

            let tx_id = u16::from_be_bytes([buf[0], buf[1]]);

            // Parse the question section from the response itself; it must
            // match the pending query before we trust the packet
            let resp_name = match parse_query_name(&buf[..n]) {
                Some(name) => name,
                None => continue,
            };
            let resp_qtype = parse_query_type(&buf[..n]).unwrap_or(0);

            // Look up the original client for this transaction ID
            let entry = {
                let mut map = match resp_pending.write() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                pending_take_match(&mut map, tx_id, &resp_name, resp_qtype)
            };
            let Some(entry) = entry else {
                debug!(
                    "DNS: dropping unmatched response for {} (tx_id=0x{:04x})",
                    resp_name, tx_id
                );
                continue;
            };

            // Parse A records from the response and populate the table,
            // using the name parsed from the response itself
            let resolved_ips = parse_ip_records(&buf[..n]);
            if let Some(ref ips) = resolved_ips {
                let ttl = table_ttl(&buf[..n]);
                for ip in ips {
                    debug!("DNS resolved: {} -> {}", resp_name, ip);
                    resp_table.insert(*ip, resp_name.clone(), ttl);
                }
            }

            info!(
                "DNS response: {} -> {} (tx_id=0x{:04x}, client={})",
                resp_name,
                resolved_ips
                    .as_ref()
                    .map(|ips| ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_else(|| "no A/AAAA records".into()),
                tx_id,
                entry.client_addr
            );

            // Restore the client's original transaction ID and reply
            buf[..2].copy_from_slice(&entry.client_tx_id.to_be_bytes());
            if let Err(e) = resp_socket.send_to(&buf[..n], entry.client_addr).await {
                warn!(
                    "DNS: failed to send response to {}: {}",
                    entry.client_addr, e
                );
            }
        }
    });

    // Main loop: read queries from clients, forward to upstream
    let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;

        if n < 12 {
            continue;
        }

        let client_tx_id = u16::from_be_bytes([buf[0], buf[1]]);

        // Extract the query name and type for response validation
        let query_name = parse_query_name(&buf[..n]).unwrap_or_default();
        let qtype = parse_query_type(&buf[..n]).unwrap_or(0);

        debug!(
            "DNS query from {}: {} (tx_id=0x{:04x})",
            client_addr, query_name, client_tx_id
        );

        // Suppress AAAA resolution so dual-stack clients stay on IPv4
        if strip_aaaa && qtype == DNS_TYPE_AAAA {
            if let Some(resp) = build_nodata(&buf[..n]) {
                debug!(
                    "DNS: stripped AAAA query for {} from {}",
                    query_name, client_addr
                );
                if let Err(e) = socket.send_to(&resp, client_addr).await {
                    warn!("DNS: failed to send NODATA to {}: {}", client_addr, e);
                }
            }
            continue;
        }

        // Store the pending query under a fresh random upstream transaction
        // ID so off-path attackers can't predict it from the client's ID
        let upstream_tx_id = {
            let entry = PendingQuery {
                client_addr,
                client_tx_id,
                name: query_name,
                qtype,
                created: Instant::now(),
            };
            match pending.write() {
                Ok(mut map) => pending_insert(&mut map, entry, Instant::now()),
                Err(_) => continue,
            }
        };
        let Some(upstream_tx_id) = upstream_tx_id else {
            warn!(
                "DNS: pending query map full, dropping query from {}",
                client_addr
            );
            continue;
        };

        // Rewrite the transaction ID and forward to upstream
        buf[..2].copy_from_slice(&upstream_tx_id.to_be_bytes());
        if let Err(e) = upstream_socket.send(&buf[..n]).await {
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
    strip_aaaa: bool,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen_addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "Failed to bind DNS listener on {}: port already in use by another process",
                listen_addr
            )
        } else {
            anyhow::anyhow!("Failed to bind DNS listener on {}: {}", listen_addr, e)
        }
    })?);
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
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .context("Failed to build HTTP client for DoH")?;
    info!(
        "DoH requests routed through upstream proxy {}",
        upstream_proxy
    );

    let cache = Arc::new(DnsCache::new());
    let coalescer = Arc::new(QueryCoalescer::new());

    let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
    loop {
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();

        if packet.len() < 12 {
            continue;
        }

        let query_name = parse_query_name(&packet).unwrap_or_default();
        let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
        let ckey = cache_key(&packet);

        debug!("DNS query from {}: {} (DoH)", client_addr, query_name);

        // Suppress AAAA resolution so dual-stack clients stay on IPv4
        if strip_aaaa && parse_query_type(&packet) == Some(DNS_TYPE_AAAA) {
            if let Some(resp) = build_nodata(&packet) {
                debug!(
                    "DNS: stripped AAAA query for {} from {}",
                    query_name, client_addr
                );
                if let Err(e) = socket.send_to(&resp, client_addr).await {
                    warn!("DNS: failed to send NODATA to {}: {}", client_addr, e);
                }
            }
            continue;
        }

        // Fast path: serve from cache
        if let Some(cached) = cache.get(&ckey, tx_id) {
            // Still populate the DNS table from cached response
            let resolved_ips = parse_ip_records(&cached);
            if let Some(ref ips) = resolved_ips {
                let ttl = table_ttl(&cached);
                for ip in ips {
                    table.insert(*ip, query_name.clone(), ttl);
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
                    .unwrap_or_else(|| "no A/AAAA records".into()),
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

        if let Some(mut rx) = coalescer.try_join(&ckey) {
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
                        let resolved_ips = parse_ip_records(&resp);
                        if let Some(ref ips) = resolved_ips {
                            let ttl = table_ttl(&resp);
                            for ip in ips {
                                table.insert(*ip, query_name.clone(), ttl);
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

        let tx = coalescer.register(ckey.clone());

        let socket = Arc::clone(&socket);
        let client = client.clone();
        let doh_url = doh_url.clone();
        let table = table.clone();
        let cache = Arc::clone(&cache);
        let coalescer = Arc::clone(&coalescer);
        let query_name_owned = query_name.clone();
        let ckey_owned = ckey.clone();

        tokio::spawn(async move {
            match doh_query(&client, &doh_url, &packet).await {
                Ok(response) => {
                    // Parse A records and populate the table
                    let resolved_ips = parse_ip_records(&response);

                    if resolved_ips.is_some() {
                        cache.put(ckey_owned.clone(), &response);
                    }

                    // Remove the in-flight entry BEFORE broadcasting: a
                    // tokio broadcast receiver only sees messages sent after
                    // subscribe(), so a subscriber joining after send() but
                    // before complete() would wait on a spent sender forever.
                    // After removal, late queries fall through to the cache
                    // or issue their own DoH request.
                    coalescer.complete(&ckey_owned);
                    let _ = tx.send(response.clone());
                    if let Some(ref ips) = resolved_ips {
                        let ttl = table_ttl(&response);
                        for ip in ips {
                            debug!("DNS resolved: {} -> {} (DoH)", query_name_owned, ip);
                            table.insert(*ip, query_name_owned.clone(), ttl);
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
                            .unwrap_or_else(|| "no A/AAAA records".into()),
                        client_addr
                    );

                    // Send response back to the original client
                    if let Err(e) = socket.send_to(&response, client_addr).await {
                        warn!("DNS: failed to send DoH response to {}: {}", client_addr, e);
                    }
                }
                Err(e) => {
                    coalescer.complete(&ckey_owned);
                    warn!("DoH query for {} failed: {:#}", query_name_owned, e);
                    // Synthesize a SERVFAIL so the client fails fast instead
                    // of blocking for its full stub timeout and retrying.
                    if let Some(servfail) = build_servfail(&packet) {
                        let _ = tx.send(servfail.clone());
                        if let Err(e) = socket.send_to(&servfail, client_addr).await {
                            warn!("DNS: failed to send SERVFAIL to {}: {}", client_addr, e);
                        }
                    }
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

/// Build a cache/coalescing key from the full DNS query with only the
/// transaction ID normalized.
///
/// The DNS response echoes the question section and can depend on header flags
/// and EDNS options, so keying only by QNAME/QTYPE can replay a response for a
/// different QCLASS or otherwise distinct query. The transaction ID is the one
/// field intentionally rewritten before serving a cached/coalesced response.
fn cache_key(packet: &[u8]) -> Vec<u8> {
    let mut key = packet.to_vec();
    if key.len() >= 2 {
        key[0] = 0;
        key[1] = 0;
    }
    key
}

/// Parse the query type (QTYPE) from a DNS packet. Returns the raw u16 value.
fn parse_query_type(packet: &[u8]) -> Option<u16> {
    let mut pos = 12;
    if pos >= packet.len() {
        return None;
    }
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    if pos + 2 > packet.len() {
        return None;
    }
    Some(u16::from_be_bytes([packet[pos], packet[pos + 1]]))
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

/// Parse A and AAAA records from a DNS response packet.
fn parse_ip_records(packet: &[u8]) -> Option<Vec<IpAddr>> {
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

    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_dns_name(packet, pos)?;
        if pos + 10 > packet.len() {
            break;
        }

        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            break;
        }

        if rclass == DNS_CLASS_IN {
            if rtype == DNS_TYPE_A && rdlength == 4 {
                let ip = Ipv4Addr::new(
                    packet[pos],
                    packet[pos + 1],
                    packet[pos + 2],
                    packet[pos + 3],
                );
                ips.push(IpAddr::V4(ip));
            } else if rtype == DNS_TYPE_AAAA && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
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

    fn build_dns_response_aaaa(domain: &str, ip: Ipv6Addr) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAB, 0xCD]);
        pkt.extend_from_slice(&[0x81, 0x80]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00);
        pkt.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        pkt.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
        pkt.extend_from_slice(&ip.octets());
        pkt
    }

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
    fn test_parse_ip_records_a() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", ip);
        let ips = parse_ip_records(&pkt).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(ip)]);
    }

    #[test]
    fn test_parse_ip_records_aaaa() {
        let ip = Ipv6Addr::new(
            0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
        );
        let pkt = build_dns_response_aaaa("example.com", ip);
        let ips = parse_ip_records(&pkt).unwrap();
        assert_eq!(ips, vec![IpAddr::V6(ip)]);
    }

    #[test]
    fn test_parse_ip_records_no_answer() {
        let mut pkt = vec![0u8; 12];
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        assert_eq!(parse_ip_records(&pkt), None);
    }

    /// Build a minimal DNS query for a domain name with the given QTYPE.
    fn build_dns_query_typed(domain: &str, tx_id: u16, qtype: u16) -> Vec<u8> {
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
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt
    }

    /// Build a minimal DNS A query for a domain name.
    fn build_dns_query(domain: &str, tx_id: u16) -> Vec<u8> {
        build_dns_query_typed(domain, tx_id, DNS_TYPE_A)
    }

    fn set_query_class(packet: &mut [u8], qclass: u16) {
        let qtype_pos = skip_dns_name(packet, 12).unwrap();
        packet[qtype_pos + 2..qtype_pos + 4].copy_from_slice(&qclass.to_be_bytes());
    }

    fn build_dns_query_with_edns_padding(domain: &str, tx_id: u16, padding_len: usize) -> Vec<u8> {
        let mut pkt = build_dns_query(domain, tx_id);
        pkt[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
        pkt.push(0); // root owner name
        pkt.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        pkt.extend_from_slice(&4096u16.to_be_bytes()); // UDP payload size
        pkt.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE / flags
        let option_len = padding_len.min(u16::MAX as usize);
        let rdlen = 4 + option_len;
        pkt.extend_from_slice(&(rdlen as u16).to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes()); // EDNS Padding option
        pkt.extend_from_slice(&(option_len as u16).to_be_bytes());
        pkt.extend(std::iter::repeat_n(0, option_len));
        pkt
    }

    async fn run_one_shot_http_proxy_for_doh(
        body_len_tx: tokio::sync::oneshot::Sender<usize>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed before HTTP headers");
                header.extend_from_slice(&buf[..n]);
                if header.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let header_end = header.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let header_text = String::from_utf8_lossy(&header[..header_end]);
            let content_len = header_text
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .or_else(|| line.strip_prefix("Content-Length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap();

            let mut body = header[header_end..].to_vec();
            while body.len() < content_len {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed before HTTP body");
                body.extend_from_slice(&buf[..n]);
            }
            body.truncate(content_len);
            let _ = body_len_tx.send(body.len());

            let response = build_servfail(&body).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                response.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        addr
    }

    #[test]
    fn test_build_nodata() {
        let query = build_dns_query_typed("example.com", 0xBEEF, DNS_TYPE_AAAA);
        let resp = build_nodata(&query).unwrap();
        // Same transaction ID
        assert_eq!(&resp[..2], &[0xBE, 0xEF]);
        // QR=1, RD preserved
        assert_eq!(resp[2], 0x81);
        // RA=1, RCODE=0 (NOERROR)
        assert_eq!(resp[3], 0x80);
        // QDCOUNT=1, no answers/authority/additional
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0);
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0);
        // Question echoed
        assert_eq!(parse_query_name(&resp), Some("example.com".to_string()));
        assert_eq!(parse_query_type(&resp), Some(DNS_TYPE_AAAA));
        assert_eq!(parse_ip_records(&resp), None);
    }

    /// With strip_aaaa enabled, AAAA queries get an immediate empty NOERROR
    /// and are never forwarded upstream; A queries still pass through.
    #[tokio::test]
    async fn test_dns_udp_strip_aaaa() {
        let fake_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fake_upstream_addr = fake_upstream.local_addr().unwrap();

        let table = DnsTable::new();
        let forwarder_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder_socket.local_addr().unwrap();
        drop(forwarder_socket);

        let forwarder = tokio::spawn(async move {
            let _ = run_udp(forwarder_addr, fake_upstream_addr, table, true).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // AAAA query: answered locally with empty NOERROR
        let query = build_dns_query_typed("example.com", 0x4444, DNS_TYPE_AAAA);
        client.send_to(&query, forwarder_addr).await.unwrap();
        let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let resp = &buf[..n];
        assert_eq!(&resp[..2], &[0x44, 0x44]);
        assert_eq!(resp[2] & 0x80, 0x80); // QR
        assert_eq!(resp[3] & 0x0F, 0); // NOERROR
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // no answers

        // The AAAA query must not have reached the upstream
        let mut upstream_buf = vec![0u8; MAX_UDP_DNS_PACKET];
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(200),
            fake_upstream.recv_from(&mut upstream_buf),
        )
        .await
        .is_err());

        // A query: still forwarded upstream
        let query = build_dns_query("example.com", 0x5555);
        client.send_to(&query, forwarder_addr).await.unwrap();
        let (_n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fake_upstream.recv_from(&mut upstream_buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            parse_query_name(&upstream_buf[..n]),
            Some("example.com".to_string())
        );

        forwarder.abort();
    }

    #[tokio::test]
    async fn test_doh_udp_preserves_large_edns_query() {
        let (body_len_tx, body_len_rx) = tokio::sync::oneshot::channel();
        let proxy_addr = run_one_shot_http_proxy_for_doh(body_len_tx).await;
        let upstream_proxy: UpstreamProxy = proxy_addr.to_string().parse().unwrap();

        let forwarder_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder_socket.local_addr().unwrap();
        drop(forwarder_socket);

        let forwarder = tokio::spawn(async move {
            let _ = run_doh(
                forwarder_addr,
                "http://dns.example/dns-query".to_string(),
                DnsTable::new(),
                &upstream_proxy,
                false,
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let query = build_dns_query_with_edns_padding("example.com", 0xABCD, 2000);
        assert!(query.len() > 1500);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, forwarder_addr).await.unwrap();

        let observed_len = tokio::time::timeout(std::time::Duration::from_secs(2), body_len_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed_len, query.len());

        let mut resp_buf = vec![0u8; MAX_UDP_DNS_PACKET];
        let (_n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut resp_buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&resp_buf[..2], &0xABCDu16.to_be_bytes());
        assert_eq!(resp_buf[3] & 0x0F, 2); // SERVFAIL from fake DoH server

        forwarder.abort();
    }

    #[test]
    fn test_dns_cache_hit_and_miss() {
        let cache = DnsCache::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", ip);
        let query = build_dns_query("example.com", 0xABCD);
        let key = cache_key(&query);

        // Miss
        assert!(cache.get(&key, 0x1234).is_none());

        // Put and hit
        cache.put(key.clone(), &pkt);
        let cached = cache.get(&key, 0x1234).unwrap();
        assert!(cached.len() >= 12);
        // Verify tx_id was rewritten
        assert_eq!(cached[0], 0x12);
        assert_eq!(cached[1], 0x34);
        let ips = parse_ip_records(&cached).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(ip)]);
    }

    #[test]
    fn test_cache_key_ignores_transaction_id_only() {
        let mut query_a = build_dns_query("example.com", 0x1111);
        let query_b = build_dns_query("example.com", 0x2222);
        assert_eq!(cache_key(&query_a), cache_key(&query_b));

        let class_in_key = cache_key(&query_a);
        set_query_class(&mut query_a, 3);
        assert_ne!(cache_key(&query_a), class_in_key);
    }

    #[test]
    fn test_extract_min_ttl() {
        let pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        // Our test builder uses TTL=60
        assert_eq!(extract_min_ttl(&pkt), Some(60));
    }

    #[test]
    fn test_rewrite_ttls_decrements() {
        let mut pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        rewrite_ttls(&mut pkt, 10).unwrap();
        assert_eq!(extract_min_ttl(&pkt), Some(50));
        // Records must still parse after the rewrite
        assert!(parse_ip_records(&pkt).is_some());
    }

    #[test]
    fn test_rewrite_ttls_floors_at_one() {
        let mut pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        rewrite_ttls(&mut pkt, 9999).unwrap();
        assert_eq!(extract_min_ttl(&pkt), Some(1));
    }

    #[test]
    fn test_dns_cache_get_rewrites_ttl_by_age() {
        let cache = DnsCache::new();
        let pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        // Insert an entry backdated by 20 seconds
        let now = Instant::now();
        let query = build_dns_query("example.com", 0xABCD);
        let key = cache_key(&query);
        cache.entries.write().unwrap().insert(
            key.clone(),
            DnsCacheEntry {
                response: pkt,
                inserted: now - Duration::from_secs(20),
                expires: now + Duration::from_secs(40),
            },
        );
        let cached = cache.get(&key, 0x1234).unwrap();
        // Original TTL=60, 20s elapsed → 40 (allow 1s of test slack)
        let ttl = extract_min_ttl(&cached).unwrap();
        assert!((39..=40).contains(&ttl), "ttl was {}", ttl);
    }

    #[test]
    fn test_build_servfail() {
        let query = build_dns_query("example.com", 0xBEEF);
        let resp = build_servfail(&query).unwrap();
        // Same transaction ID
        assert_eq!(&resp[0..2], &0xBEEFu16.to_be_bytes());
        // QR=1, RD preserved
        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(resp[2] & 0x01, query[2] & 0x01);
        // RA=1, RCODE=2 (SERVFAIL)
        assert_eq!(resp[3], 0x82);
        // Question echoed, no answers
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        assert_eq!(&resp[6..12], &[0u8; 6]);
        assert_eq!(parse_query_name(&resp), Some("example.com".to_string()));
        assert_eq!(resp.len(), query.len());
    }

    #[test]
    fn test_build_servfail_rejects_short_packet() {
        assert!(build_servfail(&[0u8; 11]).is_none());
    }

    #[test]
    fn test_dns_table_entry_expiry() {
        let table = DnsTable::new();
        let fresh = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let expired = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        table.insert(fresh, "fresh.example".to_string(), 300);
        // TTL of 0 expires immediately
        table.insert(expired, "expired.example".to_string(), 0);

        assert_eq!(table.lookup(&fresh), Some("fresh.example".to_string()));
        assert_eq!(table.lookup(&expired), None);
    }

    #[test]
    fn test_table_ttl_clamping() {
        // TTL=60 in the test response is below the floor → clamped up
        let pkt = build_dns_response("example.com", Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(table_ttl(&pkt), TABLE_TTL_FLOOR);
        // No answers → default to the floor
        assert_eq!(table_ttl(&[0u8; 12]), TABLE_TTL_FLOOR);
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
            let _ = run_udp(forwarder_addr, fake_upstream_addr, forwarder_table, false).await;
        });

        // Give the forwarder time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send a DNS query from a "client"
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query("example.com", 0xABCD);
        client_socket.send_to(&query, forwarder_addr).await.unwrap();

        // Fake upstream receives the forwarded query
        let mut buf = vec![0u8; MAX_UDP_DNS_PACKET];
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

        // Send a fake response back, echoing the (randomized) upstream tx_id
        let mut response = build_dns_response("example.com", Ipv4Addr::new(93, 184, 216, 34));
        response[..2].copy_from_slice(&buf[..2]);
        fake_upstream.send_to(&response, from_addr).await.unwrap();

        // Client should receive the response with its original tx_id restored
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(n >= 12);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xABCD);

        // Verify the DNS table was populated (proves the info!/debug! code paths ran)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let resolved = table.lookup(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(resolved, Some("example.com".to_string()));

        forwarder.abort();
    }

    /// Integration test: runs the TCP DNS listener with a fake TCP upstream,
    /// sends a length-prefixed query, and verifies RFC 7766 framing round-trips
    /// and the DNS table is populated.
    #[tokio::test]
    async fn test_dns_tcp_query_response_framing() {
        // Fake upstream DNS server speaking TCP with 2-byte length prefixes
        let fake_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake_upstream_addr = fake_upstream.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = fake_upstream.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).await.unwrap();
            assert_eq!(parse_query_name(&query), Some("example.com".to_string()));

            let mut response = build_dns_response("example.com", Ipv4Addr::new(93, 184, 216, 34));
            // Preserve the client's transaction ID
            response[0] = query[0];
            response[1] = query[1];
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });

        // Pick an ephemeral port for the forwarder's TCP listener
        let table = DnsTable::new();
        let forwarder_table = table.clone();
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let forwarder = tokio::spawn(async move {
            let _ = run_tcp(
                forwarder_addr,
                TcpDnsUpstream::Tcp(fake_upstream_addr),
                forwarder_table,
                false,
            )
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client sends a length-prefixed query over TCP
        let mut client = TcpStream::connect(forwarder_addr).await.unwrap();
        let query = build_dns_query("example.com", 0x1234);
        client
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&query).await.unwrap();

        // Read the length-prefixed response
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut len_buf),
        )
        .await
        .unwrap()
        .unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut response = vec![0u8; len];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();

        // Transaction ID preserved, answer parses
        assert_eq!(response[0], 0x12);
        assert_eq!(response[1], 0x34);
        let ips = parse_ip_records(&response).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);

        // The forwarder populated the shared table
        let resolved = table.lookup(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(resolved, Some("example.com".to_string()));

        upstream_task.await.unwrap();
        forwarder.abort();
    }

    fn make_pending(name: &str, qtype: u16, created: Instant) -> PendingQuery {
        PendingQuery {
            client_addr: "127.0.0.1:5353".parse().unwrap(),
            client_tx_id: 0xABCD,
            name: name.to_string(),
            qtype,
            created,
        }
    }

    #[test]
    fn test_pending_take_match_rejects_wrong_name_and_qtype() {
        let mut map = HashMap::new();
        let now = Instant::now();
        let tx_id =
            pending_insert(&mut map, make_pending("example.com", DNS_TYPE_A, now), now).unwrap();

        // Wrong name: rejected, entry stays pending for the real response
        assert!(pending_take_match(&mut map, tx_id, "evil.com", DNS_TYPE_A).is_none());
        assert_eq!(map.len(), 1);

        // Wrong qtype: rejected
        assert!(pending_take_match(&mut map, tx_id, "example.com", DNS_TYPE_AAAA).is_none());
        assert_eq!(map.len(), 1);

        // Unknown tx_id: rejected
        assert!(
            pending_take_match(&mut map, tx_id.wrapping_add(1), "example.com", DNS_TYPE_A)
                .is_none()
        );
        assert_eq!(map.len(), 1);

        // Matching name (case-insensitive) and qtype: accepted and removed
        let entry = pending_take_match(&mut map, tx_id, "EXAMPLE.Com", DNS_TYPE_A).unwrap();
        assert_eq!(entry.client_tx_id, 0xABCD);
        assert!(map.is_empty());
    }

    #[test]
    fn test_pending_insert_expires_stale_entries() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let later = t0 + PENDING_QUERY_TTL + Duration::from_secs(1);

        pending_insert(&mut map, make_pending("a.com", DNS_TYPE_A, t0), t0).unwrap();
        assert_eq!(map.len(), 1);

        // After the TTL, the stale entry is swept when a new query arrives
        pending_insert(&mut map, make_pending("b.com", DNS_TYPE_A, later), later).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.values().all(|p| p.name == "b.com"));
    }

    #[test]
    fn test_pending_insert_enforces_cap() {
        let mut map = HashMap::new();
        let base = Instant::now();

        // Fill the map with fresh entries up to the cap; "0.com" is oldest
        for i in 0..MAX_PENDING_QUERIES {
            let created = base + Duration::from_millis(i as u64);
            pending_insert(
                &mut map,
                make_pending(&format!("{}.com", i), DNS_TYPE_A, created),
                base,
            )
            .unwrap();
        }
        assert_eq!(map.len(), MAX_PENDING_QUERIES);

        // The next insert evicts the oldest entry instead of growing the map
        pending_insert(&mut map, make_pending("new.com", DNS_TYPE_A, base), base).unwrap();
        assert_eq!(map.len(), MAX_PENDING_QUERIES);
        assert!(map.values().all(|p| p.name != "0.com"));
        assert!(map.values().any(|p| p.name == "new.com"));
    }
}
