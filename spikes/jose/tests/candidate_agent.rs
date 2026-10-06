//! Cryptographic compatibility only; trusted-context comparisons are test assertions.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    jwk::Jwk,
    jws::{self, ES256},
};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-agent-vector.json"
    ))
    .unwrap()
}
fn key(fixture: &Value, field: &str) -> Jwk {
    let value = &fixture["trusted"][field];
    assert!(value.get("d").is_none(), "public context only");
    Jwk::from_bytes(serde_json::to_vec(value).unwrap()).unwrap()
}
fn parts(compact: &str) -> Vec<&str> {
    let result: Vec<_> = compact.split('.').collect();
    assert_eq!(result.len(), 3);
    for part in &result {
        assert_eq!(B64.encode(B64.decode(part).unwrap()), *part);
    }
    assert_eq!(B64.decode(result[2]).unwrap().len(), 64);
    result
}

#[test]
fn externally_signed_agent_proof_matches_original_bytes() {
    let fixture = vector();
    let compact = fixture["proof_jws"].as_str().unwrap();
    let segments = parts(compact);
    let mut verifier = ES256
        .verifier_from_jwk(&key(&fixture, "agent_jwk"))
        .unwrap();
    verifier.set_key_id(fixture["protected_header"]["kid"].as_str().unwrap());
    let (payload, header) = jws::deserialize_compact(compact, &verifier).unwrap();
    assert_eq!(
        B64.decode(segments[0]).unwrap(),
        fixture["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        payload,
        fixture["canonical_payload"].as_str().unwrap().as_bytes()
    );
    assert_eq!(B64.decode(segments[1]).unwrap(), payload);
    assert_eq!(header.algorithm(), Some("ES256"));
    assert_eq!(header.token_type(), Some("vollmacht-execution+jws"));
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        fixture["payload"]
    );
}

#[test]
fn wrong_agent_key_and_unsigned_mutations_reject() {
    let fixture = vector();
    let compact = fixture["proof_jws"].as_str().unwrap();
    let segments = parts(compact);
    let verifier = ES256
        .verifier_from_jwk(&key(&fixture, "agent_jwk"))
        .unwrap();
    let wrong = ES256
        .verifier_from_jwk(&key(&fixture, "wrong_agent_jwk"))
        .unwrap();
    assert!(jws::deserialize_compact(compact, &wrong).is_err());
    let altered_payload = fixture["variants"][0]["canonical_payload"]
        .as_str()
        .unwrap();
    assert!(
        jws::deserialize_compact(
            format!(
                "{}.{}.{}",
                segments[0],
                B64.encode(altered_payload),
                segments[2]
            ),
            &verifier
        )
        .is_err()
    );
    let mut altered_header = fixture["protected_header"].clone();
    altered_header["typ"] = Value::from("vollmacht-mandate+jws");
    assert!(
        jws::deserialize_compact(
            format!(
                "{}.{}.{}",
                B64.encode(serde_json::to_vec(&altered_header).unwrap()),
                segments[1],
                segments[2]
            ),
            &verifier
        )
        .is_err()
    );
    let signature = B64.decode(segments[2]).unwrap();
    for position in 0..64 {
        let mut altered = signature.clone();
        altered[position] ^= 1;
        assert!(
            jws::deserialize_compact(
                format!("{}.{}.{}", segments[0], segments[1], B64.encode(altered)),
                &verifier
            )
            .is_err()
        );
    }
}

#[test]
fn correctly_signed_context_variants_are_not_authorized_by_cryptography_alone() {
    let fixture = vector();
    let verifier = ES256
        .verifier_from_jwk(&key(&fixture, "agent_jwk"))
        .unwrap();
    let variants = fixture["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 3);
    for item in variants {
        let compact = item["proof_jws"].as_str().unwrap();
        let segments = parts(compact);
        assert_eq!(
            B64.decode(segments[0]).unwrap(),
            fixture["canonical_header"].as_str().unwrap().as_bytes()
        );
        let (payload, _) = jws::deserialize_compact(compact, &verifier).unwrap();
        assert_eq!(
            payload,
            item["canonical_payload"].as_str().unwrap().as_bytes()
        );
        let decoded: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded, item["payload"]);
        let field = match item["id"].as_str().unwrap() {
            "wrong-audience" => "audience",
            "wrong-challenge" => "challenge",
            "wrong-envelope-digest" => "envelope_digest",
            _ => panic!("unknown fixture variant"),
        };
        assert_ne!(decoded[field], fixture["trusted"]["pending"][field]);
        // No real pending state, clock, challenge consumption or policy is enforced.
    }
}
