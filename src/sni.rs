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

use anyhow::Result;
use tokio::net::TcpStream;

const MAX_CLIENT_HELLO: usize = 4096;

// TLS record types and handshake constants
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const SNI_HOST_NAME_TYPE: u8 = 0x00;

/// Peek at the TLS ClientHello on the stream and extract the SNI hostname.
/// Returns `None` if this isn't TLS or no SNI extension is present.
/// The data remains in the socket buffer (uses `peek`).
pub async fn extract_sni(stream: &TcpStream) -> Result<Option<String>> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = stream.peek(&mut buf).await?;
    if n < 5 {
        return Ok(None);
    }
    let buf = &buf[..n];
    parse_sni_from_client_hello(buf)
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

    #[test]
    fn test_parse_sni_real_client_hello() {
        // Minimal synthetic ClientHello with SNI for "example.com"
        let hostname = b"example.com";
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

        let result = parse_sni_from_client_hello(&hello).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }
}
