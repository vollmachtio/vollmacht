//! Fixed external fixtures only. Issuer cryptography does not validate WebAuthn.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    jwk::Jwk,
    jws::{self, ES256},
};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-envelope-vector.json"
    ))
    .unwrap()
}

fn trusted_key(fixture: &Value, field: &str) -> Jwk {
    let key = &fixture["trusted"][field];
    assert!(key.get("d").is_none(), "public fixture keys only");
    Jwk::from_bytes(serde_json::to_vec(key).unwrap()).unwrap()
}

fn parts(compact: &str) -> Vec<&str> {
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    for part in &parts {
        assert_eq!(B64.encode(B64.decode(part).unwrap()), *part);
    }
    assert_eq!(B64.decode(parts[2]).unwrap().len(), 64);
    parts
}

#[test]
fn external_issuer_signature_covers_exact_header_and_envelope_bytes() {
    let fixture = vector();
    let compact = fixture["issuer_jws"].as_str().unwrap();
    let segments = parts(compact);
    assert_eq!(
        B64.decode(segments[0]).unwrap(),
        fixture["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        B64.decode(segments[1]).unwrap(),
        fixture["canonical_envelope"].as_str().unwrap().as_bytes()
    );
    let mut verifier = ES256
        .verifier_from_jwk(&trusted_key(&fixture, "issuer_jwk"))
        .unwrap();
    verifier.set_key_id(fixture["protected_header"]["kid"].as_str().unwrap());
    let (payload, header) = jws::deserialize_compact(compact, &verifier).unwrap();
    assert_eq!(
        payload,
        fixture["canonical_envelope"].as_str().unwrap().as_bytes()
    );
    assert_eq!(header.algorithm(), Some("ES256"));
    assert_eq!(
        serde_json::from_slice::<Value>(&B64.decode(segments[0]).unwrap()).unwrap(),
        fixture["protected_header"]
    );
}

#[test]
fn wrong_issuer_key_and_unsigned_modifications_reject() {
    let fixture = vector();
    let compact = fixture["issuer_jws"].as_str().unwrap();
    let segments = parts(compact);
    let verifier = ES256
        .verifier_from_jwk(&trusted_key(&fixture, "issuer_jwk"))
        .unwrap();
    let wrong = ES256
        .verifier_from_jwk(&trusted_key(&fixture, "wrong_issuer_jwk"))
        .unwrap();
    assert!(jws::deserialize_compact(compact, &wrong).is_err());
    let replaced_payload = format!(
        "{}.{}.{}",
        segments[0],
        B64.encode(fixture["rebound_canonical_envelope"].as_str().unwrap()),
        segments[2]
    );
    assert!(jws::deserialize_compact(replaced_payload, &verifier).is_err());
    let mut header = fixture["protected_header"].clone();
    header["typ"] = Value::from("wrong-type");
    let replaced_header = format!(
        "{}.{}.{}",
        B64.encode(serde_json::to_vec(&header).unwrap()),
        segments[1],
        segments[2]
    );
    assert!(jws::deserialize_compact(replaced_header, &verifier).is_err());
    let signature = B64.decode(segments[2]).unwrap();
    for position in 0..signature.len() {
        let mut changed = signature.clone();
        changed[position] ^= 1;
        let mutated = format!("{}.{}.{}", segments[0], segments[1], B64.encode(changed));
        assert!(
            jws::deserialize_compact(mutated, &verifier).is_err(),
            "signature byte {position}"
        );
    }
}

#[test]
fn valid_rebound_issuer_signature_is_not_fresh_credential_approval() {
    let fixture = vector();
    let compact = fixture["rebound_issuer_jws"].as_str().unwrap();
    let segments = parts(compact);
    let verifier = ES256
        .verifier_from_jwk(&trusted_key(&fixture, "issuer_jwk"))
        .unwrap();
    let (payload, _) = jws::deserialize_compact(compact, &verifier).unwrap();
    assert_eq!(
        B64.decode(segments[0]).unwrap(),
        fixture["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        payload,
        fixture["rebound_canonical_envelope"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    let rebound: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(rebound, fixture["rebound_envelope"]);
    assert_eq!(rebound["evidence"], fixture["envelope"]["evidence"]);
    assert_ne!(rebound["payload"], fixture["envelope"]["payload"]);
    // The Node fixture test must separately reject this old assertion against the
    // new payload challenge. A valid issuer signature alone does not authorize it.
}
