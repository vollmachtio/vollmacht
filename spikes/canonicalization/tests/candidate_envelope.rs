//! Provisional fixture linkage only; no production schema or evidence verifier.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::sha::sha256;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("../fixtures/candidate-envelope-vector.json")).unwrap()
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    sha256(&[domain, bytes].concat())
}

#[test]
fn envelope_payload_and_header_match_independent_literal_bytes() {
    let fixture = vector();
    assert_eq!(fixture["profile"], "candidate-envelope-v1");
    let payload: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-payload.json")).unwrap();
    assert_eq!(fixture["envelope"]["payload"], payload);
    for (value, expected) in [
        ("envelope", "canonical_envelope"),
        ("protected_header", "canonical_header"),
        ("rebound_envelope", "rebound_canonical_envelope"),
    ] {
        assert_eq!(
            canonical(&fixture[value]),
            fixture[expected].as_str().unwrap().as_bytes()
        );
    }
    assert_eq!(fixture["protected_header"].as_object().unwrap().len(), 3);
    assert_eq!(fixture["protected_header"]["alg"], "ES256");
    assert_eq!(fixture["protected_header"]["typ"], "vollmacht-mandate+jws");
}

#[test]
fn raw_assertion_challenge_matches_reviewed_payload_digest() {
    let fixture = vector();
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-expected.json")).unwrap();
    let evidence = &fixture["envelope"]["evidence"];
    let bytes = B64
        .decode(evidence["client_data_json"].as_str().unwrap())
        .unwrap();
    let client: Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = digest(
        b"vollmacht:mandate:v1\0",
        &canonical(&fixture["envelope"]["payload"]),
    );
    assert_eq!(B64.encode(challenge), expected["mandate_challenge"]);
    assert_eq!(client["challenge"], expected["mandate_challenge"]);
    assert_eq!(
        evidence["credential_id"],
        fixture["envelope"]["payload"]["credential_id"]
    );
    assert_eq!(
        evidence["credential_id"],
        fixture["trusted"]["credential"]["id"]
    );
    assert_eq!(client["origin"], fixture["trusted"]["origin"]);
    // Parsing trusted fixture bytes here is not duplicate-safe runtime validation
    // and does not verify the assertion signature or establish trusted enrollment.
}

#[test]
fn envelope_hash_covers_payload_evidence_and_domain() {
    let fixture = vector();
    let bytes = canonical(&fixture["envelope"]);
    let original = digest(b"vollmacht:envelope:v1\0", &bytes);
    let hex: String = original.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, fixture["envelope_digest_hex"]);
    for domain in [
        b"vollmacht:envelope:v1".as_slice(),
        b"vollmacht:mandate:v1\0",
        b"vollmacht:operation:v1\0",
    ] {
        assert_ne!(original, digest(domain, &bytes));
    }
    assert_ne!(original, sha256(&bytes));
    let mut changed = fixture["envelope"].clone();
    changed["payload"]["operation"]["resource"]["pull_request_number"] = Value::from(43);
    assert_ne!(
        original,
        digest(b"vollmacht:envelope:v1\0", &canonical(&changed))
    );
    let evidence = fixture["envelope"]["evidence"].as_object().unwrap();
    for field in evidence.keys() {
        let mut changed = fixture["envelope"].clone();
        let value = changed["evidence"][field].as_str().unwrap();
        changed["evidence"][field] = Value::from(format!("{value}x"));
        assert_ne!(
            original,
            digest(b"vollmacht:envelope:v1\0", &canonical(&changed)),
            "{field}"
        );
    }
    // Mutated evidence may be invalid schema: this checks binding, not acceptance.
}

#[test]
fn rebound_envelope_keeps_old_assertion_but_requires_a_different_challenge() {
    let fixture = vector();
    let mut expected_rebound = fixture["envelope"].clone();
    expected_rebound["payload"]["operation"]["resource"]["pull_request_number"] = Value::from(43);
    assert_eq!(fixture["rebound_envelope"], expected_rebound);
    assert_eq!(
        fixture["rebound_envelope"]["evidence"],
        fixture["envelope"]["evidence"]
    );
    assert_ne!(
        digest(
            b"vollmacht:mandate:v1\0",
            &canonical(&fixture["envelope"]["payload"])
        ),
        digest(
            b"vollmacht:mandate:v1\0",
            &canonical(&fixture["rebound_envelope"]["payload"])
        )
    );
}
