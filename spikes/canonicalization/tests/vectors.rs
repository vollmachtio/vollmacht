use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::sha::sha256;
use serde_json::{Value, json};

// Hand-written canonical bytes, not output captured from the library under test.
const CANONICAL: &[u8] = br#"{"a":{"a":0,"b":"line\nquote\"\\"},"enabled":true,"z":4294967295}"#;
const DOMAIN: &[u8] = b"vollmacht:experimental:canonicalization-spike:v1\0";
const JWK_CANONICAL: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#;

fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("fixture serializes")
}

#[test]
fn reordered_nested_ascii_fixture_matches_literal_bytes() {
    let input: Value = serde_json::from_str(
        r#"{ "z":4294967295, "enabled":true, "a":{"b":"line\nquote\"\\","a":0} }"#,
    )
    .unwrap();
    assert_eq!(canonical(&input), CANONICAL);
    let reordered: Value = serde_json::from_slice(CANONICAL).unwrap();
    assert_eq!(canonical(&reordered), CANONICAL);
}

#[test]
fn serializer_orders_an_explicitly_reverse_ordered_map() {
    use std::{cmp::Reverse, collections::BTreeMap};
    let input = BTreeMap::from([(Reverse("z"), 3), (Reverse("a"), 2), (Reverse("A"), 1)]);
    assert_eq!(
        input.keys().map(|key| key.0).collect::<Vec<_>>(),
        ["z", "a", "A"]
    );
    assert_eq!(
        serde_jcs::to_vec(&input).unwrap(),
        br#"{"A":1,"a":2,"z":3}"#
    );
}

#[test]
fn escaping_and_ascii_key_order_match_literal_bytes() {
    assert_eq!(
        canonical(&json!({"z":"/", "a":"\u{000f}\u{0008}\t\n\u{000c}\r\"\\", "A":0})),
        br#"{"A":0,"a":"\u000f\b\t\n\f\r\"\\","z":"/"}"#
    );
}

#[test]
fn exact_integer_fixture_boundaries() {
    assert_eq!(
        canonical(&json!({"max":9007199254740991_u64,"zero":0,"u32":4294967295_u64})),
        br#"{"max":9007199254740991,"u32":4294967295,"zero":0}"#
    );
}

#[test]
fn domain_separated_hash_matches_independent_literal() {
    let digest = sha256(&[DOMAIN, CANONICAL].concat());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "31f269124304456ecda5c9e25beb7df82899f7727856d7f3589dce5836703258"
    );
    assert_ne!(digest, sha256(CANONICAL));
    assert_ne!(
        digest,
        sha256(&[&DOMAIN[..DOMAIN.len() - 1], CANONICAL].concat())
    );
    assert_ne!(
        digest,
        sha256(&[b"other-domain\0".as_slice(), CANONICAL].concat())
    );
}

#[test]
fn public_ec_thumbprint_uses_only_required_members() {
    // Standard P-256 generator point. This is a public fixture, not an enrolled key.
    let full = json!({"kid":"ignored","alg":"ES256","use":"sig", "kty":"EC","crv":"P-256",
        "x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"});
    let required = json!({"crv":full["crv"],"kty":full["kty"],"x":full["x"],"y":full["y"]});
    let bytes = canonical(&required);
    assert_eq!(bytes, JWK_CANONICAL);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(sha256(&bytes)),
        "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
    );
    assert_ne!(sha256(&bytes), sha256(&canonical(&full)));
    // Thumbprints have their own RFC construction, not our experimental domain.
    assert_ne!(sha256(&bytes), sha256(&[DOMAIN, &bytes].concat()));
}

#[test]
fn normal_json_map_loses_duplicate_evidence_before_serialization() {
    for input in [
        r#"{"action":1,"action":2}"#,
        r#"{"action":1,"\u0061ction":2}"#,
    ] {
        let collapsed: Value = serde_json::from_str(input).unwrap();
        assert_eq!(canonical(&collapsed), br#"{"action":2}"#);
    }
    // Demonstration of a dangerous pre-parser, NOT acceptance policy for mandates.
}

#[test]
fn normal_parser_loses_integer_lexical_distinctions() {
    for input in ["1", "1.0", "1e0"] {
        let value: Value = serde_json::from_str(input).unwrap();
        assert_eq!(canonical(&value), b"1");
    }
    let value: Value = serde_json::from_str("-0").unwrap();
    assert_eq!(canonical(&value), b"0");
}
