use shikra_obf::{obf, obf_bytes};

#[test]
fn obfuscated_string_decodes() {
    let value = obf!("shikra-secret-string");
    assert_eq!(value, "shikra-secret-string");
}

#[test]
fn obfuscated_empty_string_decodes() {
    assert_eq!(obf!(""), "");
}

#[test]
fn obfuscated_unicode_decodes() {
    assert_eq!(obf!("héllo wörld"), "héllo wörld");
}

#[test]
fn obfuscated_bytes_decode() {
    let value = obf_bytes!(b"\x00\x01\x02shikra\xff");
    assert_eq!(value, b"\x00\x01\x02shikra\xff".to_vec());
}

#[test]
fn obfuscated_bytes_empty() {
    assert!(obf_bytes!(b"").is_empty());
}

#[test]
fn same_literal_is_stable() {
    let first = obf!("stable-value");
    let second = obf!("stable-value");
    assert_eq!(first, second);
    assert_eq!(first, "stable-value");
}
