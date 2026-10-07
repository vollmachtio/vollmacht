//! Signature compatibility and explicit fixture comparisons, not an admin endpoint.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    jwk::Jwk,
    jws::{self, ES256},
};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-enrollment-vector.json"
    ))
    .unwrap()
}
fn key(v: &Value, field: &str) -> Jwk {
    let value = &v["trusted"][field];
    assert!(value.get("d").is_none());
    Jwk::from_bytes(serde_json::to_vec(value).unwrap()).unwrap()
}
fn parts(compact: &str) -> Vec<&str> {
    assert!(compact.is_ascii() && compact.len() <= 8192);
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    for (part, limit) in parts.iter().zip([512, 2048, 64]) {
        assert!(!part.is_empty());
        let bytes = B64.decode(part).unwrap();
        assert!(bytes.len() <= limit);
        assert_eq!(B64.encode(bytes), *part);
    }
    assert_eq!(B64.decode(parts[2]).unwrap().len(), 64);
    parts
}

#[test]
fn independent_verifier_accepts_exact_node_signed_bytes() {
    let v = vector();
    let verifier = ES256.verifier_from_jwk(&key(&v, "candidate_jwk")).unwrap();
    let compact = v["proof_jws"].as_str().unwrap();
    let segments = parts(compact);
    let (payload, header) = jws::deserialize_compact(compact, &verifier).unwrap();
    assert_eq!(
        B64.decode(segments[0]).unwrap(),
        v["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(payload, v["canonical_payload"].as_str().unwrap().as_bytes());
    assert_eq!(payload, B64.decode(segments[1]).unwrap());
    assert_eq!(header.algorithm(), Some("ES256"));
    assert_eq!(header.token_type(), Some("vollmacht-agent-enrollment+jws"));
    assert_eq!(header.key_id(), v["proposal"]["agent_jkt"].as_str());
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        v["trusted"]["pending"]
    );
}

#[test]
fn wrong_candidate_and_unsigned_changes_fail_cryptographic_verification() {
    let v = vector();
    let compact = v["proof_jws"].as_str().unwrap();
    let segments = parts(compact);
    let verifier = ES256.verifier_from_jwk(&key(&v, "candidate_jwk")).unwrap();
    let wrong = ES256
        .verifier_from_jwk(&key(&v, "wrong_candidate_jwk"))
        .unwrap();
    assert!(jws::deserialize_compact(compact, &wrong).is_err());
    for item in v["variants"].as_array().unwrap() {
        let altered = format!(
            "{}.{}.{}",
            B64.encode(item["canonical_header"].as_str().unwrap()),
            B64.encode(item["canonical_payload"].as_str().unwrap()),
            segments[2]
        );
        assert!(
            jws::deserialize_compact(altered, &verifier).is_err(),
            "{}",
            item["id"]
        );
    }
    let signature = B64.decode(segments[2]).unwrap();
    for index in 0..64 {
        let mut changed = signature.clone();
        changed[index] ^= 1;
        assert!(
            jws::deserialize_compact(
                format!("{}.{}.{}", segments[0], segments[1], B64.encode(changed)),
                &verifier
            )
            .is_err()
        );
    }
}

#[test]
fn valid_signatures_do_not_establish_enrollment_context_or_admin_authority() {
    let v = vector();
    let verifier = ES256.verifier_from_jwk(&key(&v, "candidate_jwk")).unwrap();
    let variants = v["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 5);
    for item in variants {
        let compact = item["proof_jws"].as_str().unwrap();
        let segments = parts(compact);
        let (payload, header) = jws::deserialize_compact(compact, &verifier).unwrap();
        assert_eq!(
            B64.decode(segments[0]).unwrap(),
            item["canonical_header"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            payload,
            item["canonical_payload"].as_str().unwrap().as_bytes()
        );
        let decoded: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded, item["payload"]);
        let field = match item["id"].as_str().unwrap() {
            "wrong-audience" => "audience",
            "wrong-stage" => "ceremony_id",
            "wrong-authorization-digest" => "authorization_digest",
            "wrong-candidate" => "agent_jkt",
            "execution-type" => {
                assert_eq!(header.token_type(), Some("vollmacht-execution+jws"));
                assert_ne!(header.token_type(), Some("vollmacht-agent-enrollment+jws"));
                assert_eq!(decoded, v["trusted"]["pending"]);
                continue;
            }
            _ => panic!("unknown fixture variant"),
        };
        assert_ne!(decoded[field], v["trusted"]["pending"][field]);
    }
    // Existing execution proof is also cryptographically valid under this public key.
    // Its actual payload/type cannot serve as an administrative possession proof.
    let execution: Value = serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-agent-vector.json"
    ))
    .unwrap();
    let (payload, header) =
        jws::deserialize_compact(execution["proof_jws"].as_str().unwrap(), &verifier).unwrap();
    assert_eq!(header.token_type(), Some("vollmacht-execution+jws"));
    assert_ne!(header.token_type(), Some("vollmacht-agent-enrollment+jws"));
    assert_ne!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        v["trusted"]["pending"]
    );
    // These assertions are not a production type/context validator or passkey check.
}
