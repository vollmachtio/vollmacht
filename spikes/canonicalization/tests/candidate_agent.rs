//! Trusted synthetic fixtures only; no production proof/context validator.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::sha::sha256;
use serde_json::{Value, json};

fn vector() -> Value {
    serde_json::from_str(include_str!("../fixtures/candidate-agent-vector.json")).unwrap()
}
fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}
fn digest(domain: &[u8], bytes: &[u8]) -> String {
    B64.encode(sha256(&[domain, bytes].concat()))
}

#[test]
fn agent_proof_bytes_match_independent_oracle_and_exact_fixture_profile() {
    let fixture = vector();
    assert_eq!(fixture["profile"], "candidate-agent-proof-v1");
    assert_eq!(
        canonical(&fixture["payload"]),
        fixture["canonical_payload"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        canonical(&fixture["protected_header"]),
        fixture["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(fixture["protected_header"].as_object().unwrap().len(), 3);
    assert_eq!(fixture["protected_header"]["alg"], "ES256");
    assert_eq!(
        fixture["protected_header"]["typ"],
        "vollmacht-execution+jws"
    );
    let mut expected = fixture["trusted"]["pending"].clone();
    expected["version"] = Value::from(1);
    assert_eq!(fixture["payload"], expected);
    assert_eq!(expected.as_object().unwrap().len(), 8);
}

#[test]
fn public_agent_thumbprint_matches_existing_mandate_and_proof_kid() {
    let fixture = vector();
    let mandate: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-payload.json")).unwrap();
    let key = &fixture["trusted"]["agent_jwk"];
    assert!(key.get("d").is_none());
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    for field in ["x", "y"] {
        assert_eq!(B64.decode(key[field].as_str().unwrap()).unwrap().len(), 32);
    }
    let required = json!({"crv":key["crv"],"kty":key["kty"],"x":key["x"],"y":key["y"]});
    let thumbprint = B64.encode(sha256(&canonical(&required)));
    assert_eq!(thumbprint, mandate["agent_jkt"]);
    assert_eq!(thumbprint, fixture["protected_header"]["kid"]);
    let wrong = &fixture["trusted"]["wrong_agent_jwk"];
    assert!(wrong.get("d").is_none());
    let wrong_required =
        json!({"crv":wrong["crv"],"kty":wrong["kty"],"x":wrong["x"],"y":wrong["y"]});
    assert_ne!(thumbprint, B64.encode(sha256(&canonical(&wrong_required))));
}

#[test]
fn pending_context_binds_reviewed_payload_operation_envelope_and_time_window() {
    let fixture = vector();
    let mandate: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-payload.json")).unwrap();
    let envelope: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-envelope-vector.json")).unwrap();
    let pending = &fixture["trusted"]["pending"];
    for (name, domain, value) in [
        (
            "mandate_digest",
            b"vollmacht:mandate:v1\0".as_slice(),
            &mandate,
        ),
        (
            "operation_digest",
            b"vollmacht:operation:v1\0",
            &mandate["operation"],
        ),
        (
            "envelope_digest",
            b"vollmacht:envelope:v1\0",
            &envelope["envelope"],
        ),
    ] {
        assert_eq!(digest(domain, &canonical(value)), pending[name]);
    }
    assert_eq!(pending["audience"], mandate["audience"]);
    assert_eq!(
        B64.decode(pending["challenge"].as_str().unwrap()).unwrap(),
        [12; 32]
    );
    assert_eq!(
        fixture["trusted"]["mandate_expires_at"],
        mandate["expires_at"]
    );
    let issued = pending["issued_at"].as_u64().unwrap();
    let expires = pending["expires_at"].as_u64().unwrap();
    assert!(issued >= mandate["issued_at"].as_u64().unwrap());
    assert_eq!(expires.checked_sub(issued), Some(30));
    assert!(expires <= mandate["expires_at"].as_u64().unwrap());
    // These comparisons describe fixture data, not a runtime clock/expiry policy.
}

#[test]
fn context_variants_change_exactly_one_expected_field() {
    let fixture = vector();
    let variants = fixture["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 3);
    for (id, field) in [
        ("wrong-audience", "audience"),
        ("wrong-challenge", "challenge"),
        ("wrong-envelope-digest", "envelope_digest"),
    ] {
        let matches: Vec<_> = variants.iter().filter(|item| item["id"] == id).collect();
        assert_eq!(matches.len(), 1);
        let item = matches[0];
        assert_eq!(
            canonical(&item["payload"]),
            item["canonical_payload"].as_str().unwrap().as_bytes()
        );
        assert_ne!(item["payload"][field], fixture["trusted"]["pending"][field]);
        let mut restored = item["payload"].clone();
        restored[field] = fixture["payload"][field].clone();
        assert_eq!(restored, fixture["payload"]);
    }
}
