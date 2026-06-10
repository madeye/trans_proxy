//! TLS ClientHello SNI (Server Name Indication) extraction.
//!
//! Peeks at the first bytes of a TCP stream to parse the TLS handshake
//! and extract the hostname from the SNI extension, without consuming the
//! data so it can still be forwarded to the upstream proxy.
//!
//! # TLS Record Format
//!
//! ```text
//! TLS Record: type(1) | version(2) | length(2)
//!   └─ Handshake: type(1) | length(3)
//!       └─ ClientHello: version(2) | random(32) | session_id(var)
//!           | cipher_suites(var) | compression(var) | extensions(var)
//!           └─ Extension 0x0000 (server_name):
//!               └─ ServerNameList: length(2)
//!                   └─ HostName: type(1)=0x00 | length(2) | name(var)
//! ```
//!
//! # Non-destructive
//!
//! Uses [`TcpStream::peek`](tokio::net::TcpStream::peek) so the ClientHello
//! bytes remain in the socket buffer for the subsequent relay.
//!
//! # Partial records
//!
//! `peek` resolves as soon as *any* bytes are buffered, so a ClientHello
//! split across TCP segments (common with large post-quantum hellos) may be
//! observed truncated. [`extract_sni`] re-peeks on a short interval until the
//! full TLS record is buffered, the size cap is reached, or the retry budget
//! is exhausted.

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::time::Duration;

const MAX_CLIENT_HELLO: usize = 4096;

/// Delay between re-peeks while waiting for the rest of a partial ClientHello.
const PEEK_RETRY_INTERVAL: Duration = Duration::from_millis(50);
/// Maximum number of re-peeks before parsing whatever is buffered (~1s total).
const MAX_PEEK_ATTEMPTS: usize = 20;

// TLS record types and handshake constants
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const SNI_HOST_NAME_TYPE: u8 = 0x00;

/// Peek at the TLS ClientHello on the stream and extract the SNI hostname.
/// Returns `None` if this isn't TLS or no SNI extension is present.
/// The data remains in the socket buffer (uses `peek`).
///
/// A single `peek` may observe only part of the ClientHello, so this loops:
/// once the 5-byte record header is buffered it computes the full record
/// length and re-peeks until that many bytes are available (capped at
/// [`MAX_CLIENT_HELLO`]) or the retry budget runs out. Non-TLS streams are
/// detected from the first byte and returned immediately without waiting.
pub async fn extract_sni(stream: &TcpStream) -> Result<Option<String>> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let mut n = stream.peek(&mut buf).await?;
    let mut attempts = 0;
    loop {
        if n == 0 {
            return Ok(None); // EOF before any handshake data
        }
        if buf[0] != TLS_RECORD_HANDSHAKE {
            return Ok(None); // Not a TLS handshake record — no point waiting
        }
        if n >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = (5 + record_len).min(MAX_CLIENT_HELLO);
            if n >= needed {
                break; // Full record buffered (or as much as we'll inspect)
            }
        }
        attempts += 1;
        if attempts >= MAX_PEEK_ATTEMPTS {
            break; // Retry budget exhausted; parse what we have (best effort)
        }
        // `peek` resolves as soon as *any* data is buffered, so re-peeking
        // immediately would just return the same bytes. Sleep briefly to let
        // the rest of the ClientHello arrive.
        tokio::time::sleep(PEEK_RETRY_INTERVAL).await;
        n = stream.peek(&mut buf).await?;
    }
    parse_sni_from_client_hello(&buf[..n])
}

/// Parse SNI from a raw TLS record containing a ClientHello.
fn parse_sni_from_client_hello(data: &[u8]) -> Result<Option<String>> {
    let mut pos = 0;

    // TLS record header: type(1) + version(2) + length(2)
    if data.len() < 5 {
        return Ok(None);
    }
    if data[pos] != TLS_RECORD_HANDSHAKE {
        return Ok(None); // Not a TLS handshake record
    }
    pos += 1;

    // version (2 bytes) - skip
    pos += 2;

    // record length
    let record_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let record_end = pos + record_len.min(data.len() - pos);

    // Handshake header: type(1) + length(3)
    if pos + 4 > record_end {
        return Ok(None);
    }
    if data[pos] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Ok(None);
    }
    pos += 1;

    // handshake length (3 bytes) - skip, we use record_end
    pos += 3;

    // ClientHello: version(2) + random(32)
    if pos + 34 > record_end {
        return Ok(None);
    }
    pos += 34;

    // Session ID: length(1) + data
    if pos + 1 > record_end {
        return Ok(None);
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    if pos + 2 > record_end {
        return Ok(None);
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods: length(1) + data
    if pos + 1 > record_end {
        return Ok(None);
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions: length(2) + data
    if pos + 2 > record_end {
        return Ok(None);
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len.min(record_end - pos);

    // Walk extensions looking for SNI
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_sni_extension(&data[pos..pos + ext_len.min(extensions_end - pos)]);
        }

        pos += ext_len;
    }

    Ok(None)
}

/// Parse the SNI extension payload to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Result<Option<String>> {
    if data.len() < 2 {
        return Ok(None);
    }

    // Server name list length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = pos + list_len.min(data.len() - pos);

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == SNI_HOST_NAME_TYPE && pos + name_len <= end {
            let name = std::str::from_utf8(&data[pos..pos + name_len])
                .map(|s| s.to_string())
                .ok();
            return Ok(name);
        }

        pos += name_len;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni_no_tls() {
        // HTTP request, not TLS
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_sni_from_client_hello(data).unwrap(), None);
    }

    /// Build a minimal synthetic ClientHello record with an SNI extension.
    fn build_client_hello(hostname: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();

        // -- TLS record header --
        hello.push(TLS_RECORD_HANDSHAKE); // content type
        hello.extend_from_slice(&[0x03, 0x01]); // TLS 1.0

        // placeholder for record length (fill later)
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        let record_start = hello.len();

        // -- Handshake header --
        hello.push(TLS_HANDSHAKE_CLIENT_HELLO);
        // placeholder for handshake length (3 bytes, fill later)
        let hs_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        let hs_start = hello.len();

        // ClientHello body
        hello.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random

        hello.push(0x00); // session ID length = 0

        hello.extend_from_slice(&[0x00, 0x02]); // cipher suites length = 2
        hello.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA

        hello.push(0x01); // compression methods length = 1
        hello.push(0x00); // null compression

        // -- Extensions --
        // Build SNI extension
        let mut sni_ext = Vec::new();
        // server name list length
        let name_entry_len = 1 + 2 + hostname.len(); // type + len + name
        sni_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        sni_ext.push(SNI_HOST_NAME_TYPE);
        sni_ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname);

        // extensions total length
        let ext_total = 2 + 2 + sni_ext.len(); // ext_type + ext_len + ext_data
        hello.extend_from_slice(&(ext_total as u16).to_be_bytes());

        // SNI extension header
        hello.extend_from_slice(&TLS_EXT_SERVER_NAME.to_be_bytes());
        hello.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        // Fill in lengths
        let hs_len = hello.len() - hs_start;
        hello[hs_len_pos] = ((hs_len >> 16) & 0xFF) as u8;
        hello[hs_len_pos + 1] = ((hs_len >> 8) & 0xFF) as u8;
        hello[hs_len_pos + 2] = (hs_len & 0xFF) as u8;

        let record_len = hello.len() - record_start;
        hello[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
        hello[record_len_pos + 1] = (record_len & 0xFF) as u8;

        hello
    }

    #[test]
    fn test_parse_sni_real_client_hello() {
        let hello = build_client_hello(b"example.com");
        let result = parse_sni_from_client_hello(&hello).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }

    /// Connect a local TCP pair and return (client, accepted server) streams.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_extract_sni_complete_hello() {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tcp_pair().await;
        client
            .write_all(&build_client_hello(b"example.com"))
            .await
            .unwrap();

        let result = extract_sni(&server).await.unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[tokio::test]
    async fn test_extract_sni_split_across_writes() {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tcp_pair().await;
        let hello = build_client_hello(b"example.com");

        // Deliver the ClientHello in three delayed chunks so a single peek
        // observes a truncated record; extract_sni must wait and re-peek.
        let (first, rest) = hello.split_at(10);
        let (second, third) = rest.split_at(rest.len() / 2);
        client.write_all(first).await.unwrap();
        let (second, third) = (second.to_vec(), third.to_vec());
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            client.write_all(&second).await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            client.write_all(&third).await.unwrap();
            client
        });

        let result = extract_sni(&server).await.unwrap();
        assert_eq!(result, Some("example.com".to_string()));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_extract_sni_non_tls_returns_immediately() {
        use tokio::io::AsyncWriteExt;

        let (mut client, server) = tcp_pair().await;
        // Partial HTTP request: not TLS, so extract_sni must not wait for more
        client.write_all(b"GET / HT").await.unwrap();

        let start = tokio::time::Instant::now();
        let result = extract_sni(&server).await.unwrap();
        assert_eq!(result, None);
        // Early-exit path: well under a single retry interval
        assert!(start.elapsed() < PEEK_RETRY_INTERVAL);
    }

    #[tokio::test]
    async fn test_extract_sni_eof_returns_none() {
        let (client, server) = tcp_pair().await;
        drop(client);

        let result = extract_sni(&server).await.unwrap();
        assert_eq!(result, None);
    }
}
