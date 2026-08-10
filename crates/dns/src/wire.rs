//! DNS wire format: minimal query builder and response parser.
//!
//! Hand-rolled to avoid a DNS-crate dependency; supports exactly what the
//! resolver needs — single-question queries and A/AAAA answer extraction.

use std::net::IpAddr;

use anyhow::Result;

/// Next DNS transaction ID for outgoing queries. Randomized rather than
/// sequential so an off-path spoofer can't predict it; `RandomState` keys
/// are seeded with per-thread entropy (no rand dependency needed).
pub(crate) fn next_tx_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

/// Max DNS label length per RFC 1035.
const MAX_LABEL_LEN: usize = 63;

/// DNS query/record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QType {
    A = 1,
    // Query/parse support exists but no AAAA query is sent yet (dns.ipv6
    // behaves as false); exercised by wire tests.
    #[allow(dead_code)]
    Aaaa = 28,
}

impl QType {
    fn code(self) -> u16 {
        self as u16
    }

    /// Expected RDATA length for this record type.
    fn rdlength(self) -> usize {
        match self {
            QType::A => 4,
            QType::Aaaa => 16,
        }
    }
}

/// Result of a DNS lookup including TTL for caching.
#[derive(Debug)]
pub(crate) struct DnsResult {
    pub ip: IpAddr,
    pub ttl: u32,
}

/// Build a minimal single-question DNS query packet for `qtype`.
pub(crate) fn build_dns_query(host: &str, tx_id: u16, qtype: QType) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);

    buf.extend_from_slice(&tx_id.to_be_bytes()); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Encode domain name as DNS labels
    for label in host.split('.') {
        if label.is_empty() {
            continue; // skip empty labels (trailing dot)
        }
        if label.len() > MAX_LABEL_LEN {
            anyhow::bail!(
                "DNS label too long ({} > {MAX_LABEL_LEN}): {label}",
                label.len()
            );
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    buf.extend_from_slice(&qtype.code().to_be_bytes()); // QTYPE
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    Ok(buf)
}

/// Parse a DNS response and extract the first record matching `qtype`
/// with its TTL.
pub(crate) fn parse_dns_response(
    data: &[u8],
    host: &str,
    expected_id: u16,
    qtype: QType,
) -> Result<DnsResult> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short");
    }

    let resp_id = u16::from_be_bytes([data[0], data[1]]);
    if resp_id != expected_id {
        anyhow::bail!("DNS response ID mismatch: expected {expected_id}, got {resp_id}");
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);

    // Check TC (truncation) bit — response was too large for UDP
    if flags & 0x0200 != 0 {
        anyhow::bail!("DNS response truncated (TC bit set) for {host}");
    }

    let rcode = flags & 0x000F;
    if rcode != 0 {
        anyhow::bail!("DNS error rcode={rcode} for {host}");
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        anyhow::bail!("no answers in DNS response for {host}");
    }

    // Skip all question sections
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        if pos + 4 > data.len() {
            anyhow::bail!("DNS response truncated in question section");
        }
        pos += 4; // skip QTYPE + QCLASS
    }

    // Parse answer records, looking for records of the requested type.
    // CNAME records (type 5) are skipped — most recursive resolvers include
    // the full CNAME → address chain in the answer section.
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;

        if pos + 10 > data.len() {
            anyhow::bail!("DNS response truncated in answer record");
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            anyhow::bail!("DNS response truncated in RDATA");
        }

        if rtype == qtype.code() && rdlength == qtype.rdlength() {
            let ip = match qtype {
                QType::A => IpAddr::V4(std::net::Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                )),
                QType::Aaaa => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos..pos + 16]);
                    IpAddr::V6(std::net::Ipv6Addr::from(octets))
                }
            };
            return Ok(DnsResult { ip, ttl });
        }

        pos += rdlength;
    }

    anyhow::bail!("no {qtype:?} record found in DNS response for {host}")
}

/// Skip a DNS name (handles both label sequences and compressed pointers).
/// Limited to 128 iterations to prevent malformed packets from looping.
pub(crate) fn skip_dns_name(data: &[u8], mut pos: usize) -> Result<usize> {
    let mut iterations = 0;
    loop {
        if iterations > 128 {
            anyhow::bail!("DNS name too many labels (malformed packet)");
        }
        iterations += 1;

        if pos >= data.len() {
            anyhow::bail!("DNS name extends past end of packet");
        }
        let b = data[pos];
        if b == 0 {
            return Ok(pos + 1); // null terminator
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes)
            if pos + 2 > data.len() {
                anyhow::bail!("DNS compression pointer truncated");
            }
            return Ok(pos + 2);
        }
        let label_len = b as usize;
        if label_len > MAX_LABEL_LEN {
            anyhow::bail!("DNS label length {label_len} exceeds maximum {MAX_LABEL_LEN}");
        }
        if pos + 1 + label_len > data.len() {
            anyhow::bail!("DNS label extends past end of packet");
        }
        pos += 1 + label_len;
    }
}

/// Helpers for building synthetic DNS messages, shared by the crate's
/// test modules (wire parsing, upstream exchanges, bootstrap, resolver).
#[cfg(test)]
pub(crate) mod test_util {
    pub(crate) fn build_test_response(
        tx_id: u16,
        flags: u16,
        questions: &[&[u8]],
        answers: &[&[u8]],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tx_id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&(questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        for q in questions {
            buf.extend_from_slice(q);
        }
        for a in answers {
            buf.extend_from_slice(a);
        }
        buf
    }

    pub(crate) fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    pub(crate) fn make_question(name: &str) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        buf
    }

    pub(crate) fn make_a_record_with_ttl(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        buf.extend_from_slice(&ip);
        buf
    }

    pub(crate) fn make_a_record(name: &str, ip: [u8; 4]) -> Vec<u8> {
        make_a_record_with_ttl(name, ip, 60)
    }

    pub(crate) fn make_aaaa_record(name: &str, ip: [u8; 16]) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x1C]); // TYPE=AAAA
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        buf.extend_from_slice(&[0x00, 0x10]); // RDLENGTH=16
        buf.extend_from_slice(&ip);
        buf
    }

    pub(crate) fn make_cname_record(name: &str, target: &str) -> Vec<u8> {
        let mut buf = encode_name(name);
        buf.extend_from_slice(&[0x00, 0x05]); // TYPE=CNAME
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        let target_encoded = encode_name(target);
        buf.extend_from_slice(&(target_encoded.len() as u16).to_be_bytes());
        buf.extend_from_slice(&target_encoded);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;

    #[test]
    fn build_query_encodes_labels() {
        let query = build_dns_query("www.example.com", 0x1234, QType::A).unwrap();
        assert_eq!(query[12], 3);
        assert_eq!(&query[13..16], b"www");
        assert_eq!(query[16], 7);
        assert_eq!(&query[17..24], b"example");
        assert_eq!(query[24], 3);
        assert_eq!(&query[25..28], b"com");
        assert_eq!(query[28], 0);
    }

    #[test]
    fn build_query_with_tx_id() {
        let query = build_dns_query("test.com", 0xABCD, QType::A).unwrap();
        assert_eq!(query[0], 0xAB);
        assert_eq!(query[1], 0xCD);
    }

    #[test]
    fn build_query_trailing_dot() {
        let q1 = build_dns_query("example.com.", 1, QType::A).unwrap();
        let q2 = build_dns_query("example.com", 1, QType::A).unwrap();
        assert_eq!(q1, q2);
    }

    #[test]
    fn build_query_rejects_long_label() {
        let long_label = "a".repeat(64);
        let host = format!("{long_label}.com");
        assert!(build_dns_query(&host, 1, QType::A).is_err());
    }

    #[test]
    fn build_query_qtype_parameterized() {
        let q_a = build_dns_query("example.com", 1, QType::A).unwrap();
        let q_aaaa = build_dns_query("example.com", 1, QType::Aaaa).unwrap();
        let n = q_a.len();
        // QTYPE is the third-to-last u16: [QTYPE][QCLASS] at the tail.
        assert_eq!(&q_a[n - 4..n - 2], &1u16.to_be_bytes());
        assert_eq!(&q_aaaa[n - 4..n - 2], &28u16.to_be_bytes());
        // QCLASS=IN identical in both.
        assert_eq!(&q_a[n - 2..], &q_aaaa[n - 2..]);
    }

    #[test]
    fn skip_name_handles_pointer() {
        let data = [0xC0, 0x0C, 0x00];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 2);
    }

    #[test]
    fn skip_name_handles_labels() {
        let data = [3, b'w', b'w', b'w', 0];
        assert_eq!(skip_dns_name(&data, 0).unwrap(), 5);
    }

    #[test]
    fn skip_name_rejects_truncated() {
        let data = [10, b'a', b'b', b'c'];
        assert!(skip_dns_name(&data, 0).is_err());
    }

    #[test]
    fn skip_name_rejects_oversized_label() {
        let mut data = vec![64];
        data.extend(vec![b'a'; 64]);
        data.push(0);
        assert!(skip_dns_name(&data, 0).is_err());
    }

    // --- Response parsing tests ---

    #[test]
    fn parse_simple_a_response() {
        let q = make_question("example.com");
        let a = make_a_record("example.com", [93, 184, 216, 34]);
        let resp = build_test_response(0x1234, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x1234, QType::A).unwrap();
        assert_eq!(result.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(result.ttl, 60);
    }

    #[test]
    fn parse_response_preserves_ttl() {
        let q = make_question("example.com");
        let a = make_a_record_with_ttl("example.com", [1, 2, 3, 4], 300);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x0001, QType::A).unwrap();
        assert_eq!(result.ttl, 300);
    }

    #[test]
    fn parse_cname_then_a_response() {
        let q = make_question("www.example.com");
        let cname = make_cname_record("www.example.com", "cdn.example.net");
        let a = make_a_record("cdn.example.net", [180, 101, 51, 73]);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&cname, &a]);

        let result = parse_dns_response(&resp, "www.example.com", 0x0001, QType::A).unwrap();
        assert_eq!(result.ip, "180.101.51.73".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_response_with_pointer_names() {
        let q = make_question("example.com");
        let mut a = vec![0xC0, 0x0C]; // pointer to question name
        a.extend_from_slice(&[0x00, 0x01]); // TYPE=A
        a.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        a.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        a.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        a.extend_from_slice(&[1, 2, 3, 4]);
        let resp = build_test_response(0x0042, 0x8180, &[&q], &[&a]);

        let result = parse_dns_response(&resp, "example.com", 0x0042, QType::A).unwrap();
        assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_aaaa_response() {
        let q = make_question("example.com");
        let aaaa = make_aaaa_record(
            "example.com",
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        let resp = build_test_response(0x1234, 0x8180, &[&q], &[&aaaa]);

        let result = parse_dns_response(&resp, "example.com", 0x1234, QType::Aaaa).unwrap();
        assert_eq!(result.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(result.ttl, 60);
    }

    #[test]
    fn parse_a_query_ignores_aaaa_record() {
        let q = make_question("example.com");
        let aaaa = make_aaaa_record(
            "example.com",
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        let resp = build_test_response(0x1234, 0x8180, &[&q], &[&aaaa]);

        let err = parse_dns_response(&resp, "example.com", 0x1234, QType::A).unwrap_err();
        assert!(err.to_string().contains("no A record"));
    }

    #[test]
    fn parse_response_id_mismatch() {
        let q = make_question("example.com");
        let a = make_a_record("example.com", [1, 2, 3, 4]);
        let resp = build_test_response(0x9999, 0x8180, &[&q], &[&a]);

        let err = parse_dns_response(&resp, "example.com", 0x1111, QType::A).unwrap_err();
        assert!(err.to_string().contains("ID mismatch"));
    }

    #[test]
    fn parse_response_nxdomain() {
        let q = make_question("nonexistent.example.com");
        let resp = build_test_response(0x0001, 0x8183, &[&q], &[]);

        let err =
            parse_dns_response(&resp, "nonexistent.example.com", 0x0001, QType::A).unwrap_err();
        assert!(err.to_string().contains("rcode=3"));
    }

    #[test]
    fn parse_response_truncated_tc_bit() {
        let q = make_question("example.com");
        let resp = build_test_response(0x0001, 0x8380, &[&q], &[]);

        let err = parse_dns_response(&resp, "example.com", 0x0001, QType::A).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn parse_response_no_a_record_only_cname() {
        let q = make_question("alias.example.com");
        let cname = make_cname_record("alias.example.com", "real.example.com");
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&cname]);

        let err = parse_dns_response(&resp, "alias.example.com", 0x0001, QType::A).unwrap_err();
        assert!(err.to_string().contains("no A record"));
    }

    #[test]
    fn parse_response_multiple_a_records_returns_first() {
        let q = make_question("multi.example.com");
        let a1 = make_a_record("multi.example.com", [10, 0, 0, 1]);
        let a2 = make_a_record("multi.example.com", [10, 0, 0, 2]);
        let resp = build_test_response(0x0001, 0x8180, &[&q], &[&a1, &a2]);

        let result = parse_dns_response(&resp, "multi.example.com", 0x0001, QType::A).unwrap();
        assert_eq!(result.ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_response_too_short() {
        let err = parse_dns_response(&[0u8; 6], "x.com", 0, QType::A).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }
}
