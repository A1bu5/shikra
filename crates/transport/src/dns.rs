//! Minimal DNS wire codec used by the DNS beacon transport.
//!
//! The transport carries opaque payloads in DNS `TXT` queries/responses. Only
//! the subset required for a client and server that both speak the same
//! dialect is implemented: a single question, label compression pointers on
//! input, and TXT answers on output.

use anyhow::{anyhow, Result};
use base32::Alphabet;

/// DNS record type for TXT records.
pub const TYPE_TXT: u16 = 16;
/// DNS class IN.
pub const CLASS_IN: u16 = 1;

const HEADER_LEN: usize = 12;
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 253;

/// Encodes a DNS query with a single TXT question.
pub fn encode_query(id: u16, qname: &str) -> Result<Vec<u8>> {
    let labels = split_name(qname)?;
    let mut out = Vec::with_capacity(HEADER_LEN + 16 + qname.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, &labels);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parses a DNS query, returning the transaction id and the query name.
pub fn decode_query(bytes: &[u8]) -> Result<(u16, String)> {
    if bytes.len() < HEADER_LEN {
        return Err(anyhow!("dns: query too short"));
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qdcount != 1 {
        return Err(anyhow!("dns: expected exactly one question"));
    }
    let (labels, _) = read_name(bytes, HEADER_LEN)?;
    Ok((id, labels.join(".")))
}

/// Encodes a DNS response carrying `payload` as TXT answer strings.
///
/// An empty payload produces a response with no answers (used as an ACK for
/// intermediate request chunks).
pub fn encode_response(id: u16, qname: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let labels = split_name(qname)?;
    let mut out = Vec::with_capacity(HEADER_LEN + qname.len() + payload.len() * 2 + 16);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(u16::from(!payload.is_empty())).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, &labels);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());

    if !payload.is_empty() {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer to question
        out.extend_from_slice(&TYPE_TXT.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL

        let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, payload);
        let rdata_len: usize = encoded
            .as_bytes()
            .chunks(255)
            .map(|chunk| chunk.len() + 1)
            .sum();
        let rdata_len = u16::try_from(rdata_len).map_err(|_| anyhow!("dns: response too large"))?;
        out.extend_from_slice(&rdata_len.to_be_bytes());
        for chunk in encoded.as_bytes().chunks(255) {
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    Ok(out)
}

/// Parses a TXT response and returns the concatenated, base32-decoded payload.
pub fn decode_response(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < HEADER_LEN {
        return Err(anyhow!("dns: response too short"));
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut offset = HEADER_LEN;
    for _ in 0..qdcount {
        let (_, next) = read_name(bytes, offset)?;
        offset = next + 4;
    }

    let mut encoded = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(bytes, offset)?;
        offset = next;
        if offset + 10 > bytes.len() {
            return Err(anyhow!("dns: truncated answer"));
        }
        let rtype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
        offset += 2; // class
        offset += 4; // ttl
        let rdlen = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + rdlen > bytes.len() {
            return Err(anyhow!("dns: truncated rdata"));
        }
        if rtype == TYPE_TXT {
            let mut pos = offset;
            while pos < offset + rdlen {
                let len = bytes[pos] as usize;
                pos += 1;
                if pos + len > offset + rdlen {
                    return Err(anyhow!("dns: truncated txt string"));
                }
                encoded.extend_from_slice(&bytes[pos..pos + len]);
                pos += len;
            }
        }
        offset += rdlen;
    }

    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(encoded).map_err(|_| anyhow!("dns: non-utf8 txt data"))?;
    base32::decode(Alphabet::Rfc4648 { padding: false }, &text)
        .ok_or_else(|| anyhow!("dns: invalid base32 payload"))
}

/// Encodes `payload` as base32 labels suitable for a DNS query name.
pub fn payload_to_labels(payload: &[u8]) -> Vec<String> {
    let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, payload);
    encoded
        .as_bytes()
        .chunks(MAX_LABEL)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// Decodes the concatenation of base32 labels back into payload bytes.
pub fn labels_to_payload(labels: &[String]) -> Result<Vec<u8>> {
    let joined = labels.concat();
    base32::decode(Alphabet::Rfc4648 { padding: false }, &joined)
        .ok_or_else(|| anyhow!("dns: invalid base32 label payload"))
}

fn split_name(qname: &str) -> Result<Vec<String>> {
    let labels: Vec<String> = qname
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect();
    if labels.is_empty() {
        return Err(anyhow!("dns: empty name"));
    }
    if labels.iter().any(|label| label.len() > MAX_LABEL) {
        return Err(anyhow!("dns: label exceeds {MAX_LABEL} bytes"));
    }
    if qname.len() > MAX_NAME {
        return Err(anyhow!("dns: name exceeds {MAX_NAME} bytes"));
    }
    Ok(labels)
}

fn encode_name(out: &mut Vec<u8>, labels: &[String]) {
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Reads a (possibly compressed) name starting at `offset`.
///
/// Returns the labels and the offset immediately after the name at the
/// original position (not after any pointer target).
fn read_name(bytes: &[u8], offset: usize) -> Result<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut end: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        if pos >= bytes.len() {
            return Err(anyhow!("dns: name out of bounds"));
        }
        let len = bytes[pos] as usize;
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= bytes.len() {
                return Err(anyhow!("dns: truncated compression pointer"));
            }
            let target = ((len & 0x3F) << 8) | bytes[pos + 1] as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            hops += 1;
            if hops > 16 {
                return Err(anyhow!("dns: compression pointer loop"));
            }
            pos = target;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        if len > MAX_LABEL || pos + 1 + len > bytes.len() {
            return Err(anyhow!("dns: invalid label"));
        }
        labels.push(String::from_utf8_lossy(&bytes[pos + 1..pos + 1 + len]).into_owned());
        pos += 1 + len;
    }

    Ok((labels, end.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let encoded = encode_query(0x1234, "abc.def.example").unwrap();
        let (id, name) = decode_query(&encoded).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(name, "abc.def.example");
    }

    #[test]
    fn response_roundtrip() {
        let payload = b"envelope-bytes-\x00\x01\x02";
        let encoded = encode_response(7, "a.b.example", payload).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn response_roundtrip_large_payload() {
        let payload: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
        let encoded = encode_response(9, "abc.example", &payload).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn empty_response_decodes_to_empty() {
        let encoded = encode_response(3, "x.example", &[]).unwrap();
        assert!(decode_response(&encoded).unwrap().is_empty());
    }

    #[test]
    fn label_roundtrip() {
        let payload: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let labels = payload_to_labels(&payload);
        let decoded = labels_to_payload(&labels).unwrap();
        assert_eq!(decoded, payload);
    }
}
