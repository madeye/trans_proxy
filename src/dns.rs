//! Local DNS forwarder with IP→domain mapping capture.
//!
//! Listens on a UDP port, forwards all DNS queries to a configured upstream
//! server, and parses A records from responses to build an IP→domain lookup
//! table shared with the proxy.
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
//! # Cache
//!
//! The lookup table is capped at [`MAX_CACHE_ENTRIES`] (10,000). When full,
//! half the entries are evicted. Entries are not TTL-aware — they persist
//! until evicted or overwritten by a newer response.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const MAX_DNS_PACKET: usize = 1500;
const MAX_CACHE_ENTRIES: usize = 10_000;

// DNS header flags / record types
const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;

/// Shared IP→domain lookup table.
#[derive(Clone)]
pub struct DnsTable {
    inner: Arc<RwLock<HashMap<Ipv4Addr, String>>>,
}

impl DnsTable {
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

/// Run the DNS forwarder.
///
/// Binds to `listen_addr`, forwards all queries to `upstream_dns`,
/// and records A record responses in the shared `table`.
pub async fn run(listen_addr: SocketAddr, upstream_dns: SocketAddr, table: DnsTable) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .context("Failed to bind DNS listener")?;
    info!("DNS forwarder listening on {}, upstream {}", listen_addr, upstream_dns);

    // We use a single upstream socket for forwarding.
    // Map transaction IDs to client addresses for routing replies back.
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind upstream DNS socket")?;
    upstream_socket.connect(upstream_dns).await?;

    // Track pending queries: transaction_id → (client_addr, query_name)
    let pending: Arc<RwLock<HashMap<u16, (SocketAddr, String)>>> =
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

            // Look up the original client
            let (client_addr, query_name) = {
                let mut map = match resp_pending.write() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match map.remove(&tx_id) {
                    Some(v) => v,
                    None => continue,
                }
            };

            // Parse A records from the response and populate the table
            if let Some(ips) = parse_a_records(packet) {
                for ip in ips {
                    debug!("DNS: {} -> {}", ip, query_name);
                    resp_table.insert(ip, query_name.clone());
                }
            }

            // Forward response back to the original client
            if let Err(e) = resp_socket.send_to(packet, client_addr).await {
                debug!("DNS: failed to send response to {}: {}", client_addr, e);
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

        // Store pending query
        if let Ok(mut map) = pending.write() {
            map.insert(tx_id, (client_addr, query_name));
        }

        // Forward to upstream
        if let Err(e) = upstream_socket.send(packet).await {
            debug!("DNS: failed to forward query to upstream: {}", e);
        }
    }
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
            let ip = Ipv4Addr::new(packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]);
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
}
