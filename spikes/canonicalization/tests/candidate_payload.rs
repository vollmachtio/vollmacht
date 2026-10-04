//! Provisional fixture binding tests, not a parser or authorization policy.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::sha::sha256;
use serde_json::Value;

const PAYLOAD: &str = include_str!("../fixtures/candidate-payload.json");
const EXPECTED: &str = include_str!("../fixtures/candidate-expected.json");
const MANDATE_DOMAIN: &[u8] = b"vollmacht:mandate:v1\0";
const OPERATION_DOMAIN: &[u8] = b"vollmacht:operation:v1\0";

fn fixture() -> Value {
    serde_json::from_str(PAYLOAD).unwrap()
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    sha256(&[domain, bytes].concat())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn scalar_paths(value: &Value, path: &str, result: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            assert!(!fields.is_empty(), "unexpected empty fixture object");
            for (key, child) in fields {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                scalar_paths(child, &format!("{path}/{escaped}"), result);
            }
        }
        Value::String(_) | Value::Number(_) => result.push(path.to_owned()),
        _ => panic!("unexpected fixture value at {path}"),
    }
}

#[test]
fn complete_candidate_matches_independent_bytes_and_hashes() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let payload = fixture();
    let bytes = canonical(&payload);
    let operation = canonical(&payload["operation"]);
    assert_eq!(
        bytes,
        expected["canonical_payload"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        operation,
        expected["canonical_operation"].as_str().unwrap().as_bytes()
    );
    let mandate = digest(MANDATE_DOMAIN, &bytes);
    assert_eq!(hex(&mandate), expected["mandate_digest_hex"]);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(mandate),
        expected["mandate_challenge"]
    );
    assert_eq!(
        hex(&digest(OPERATION_DOMAIN, &operation)),
        expected["operation_digest_hex"]
    );
    assert_eq!(
        payload["expires_at"].as_u64().unwrap() - payload["issued_at"].as_u64().unwrap(),
        120
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(payload["nonce"].as_str().unwrap())
            .unwrap(),
        [0; 32]
    );
}

#[test]
fn original_input_order_and_whitespace_do_not_change_canonical_bytes() {
    let payload = fixture();
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    let ordered = expected["canonical_payload"].as_str().unwrap();
    assert_ne!(PAYLOAD.trim(), ordered);
    assert_eq!(payload, serde_json::from_str::<Value>(ordered).unwrap());
    assert_eq!(canonical(&payload), ordered.as_bytes());
    assert_eq!(
        canonical(
            &serde_json::from_str::<Value>(&serde_json::to_string_pretty(&payload).unwrap())
                .unwrap()
        ),
        ordered.as_bytes()
    );
    // Value parsing already sorts ASCII map keys; direct serializer sorting is
    // separately exercised by the reverse-ordered-map test in vectors.rs.
}

#[test]
fn every_candidate_leaf_is_covered_by_mandate_digest() {
    let payload = fixture();
    let baseline = digest(MANDATE_DOMAIN, &canonical(&payload));
    let paths = [
        "/version",
        "/mandate_id",
        "/nonce",
        "/issuer_id",
        "/audience",
        "/principal_id",
        "/credential_id",
        "/agent_jkt",
        "/policy_revision",
        "/issued_at",
        "/expires_at",
        "/operation/action",
        "/operation/resource/host",
        "/operation/resource/repository_id",
        "/operation/resource/pull_request_number",
        "/operation/constraints/expected_head_sha",
        "/operation/constraints/base_ref",
        "/operation/constraints/merge_method",
        "/display/version",
        "/display/repository",
    ];
    let mut observed = Vec::new();
    scalar_paths(&payload, "", &mut observed);
    observed.sort();
    let mut listed = paths.to_vec();
    listed.sort();
    assert_eq!(
        observed, listed,
        "every fixture scalar must have a mutation"
    );
    for path in paths {
        let mut changed = payload.clone();
        let value = changed.pointer_mut(path).expect("listed leaf exists");
        *value = match value {
            Value::String(text) => Value::String(format!("{text}x")),
            Value::Number(number) => Value::from(number.as_u64().unwrap() + 1),
            _ => panic!("fixture leaf type changed"),
        };
        assert_ne!(
            digest(MANDATE_DOMAIN, &canonical(&changed)),
            baseline,
            "{path}"
        );
    }
    // Several mutations violate the proposed schema. This proves byte binding,
    // not schema rejection, policy acceptance, or resistance to hash collisions.
}

#[test]
fn operation_hash_excludes_authority_but_mandate_hash_covers_it() {
    let original = fixture();
    let mut changed = original.clone();
    changed["principal_id"] = Value::from("44444444444444444444444444444444");
    assert_eq!(
        digest(OPERATION_DOMAIN, &canonical(&original["operation"])),
        digest(OPERATION_DOMAIN, &canonical(&changed["operation"]))
    );
    assert_ne!(
        digest(MANDATE_DOMAIN, &canonical(&original)),
        digest(MANDATE_DOMAIN, &canonical(&changed))
    );
    // An operation digest alone therefore never represents delegated authority.
}

#[test]
fn candidate_domains_and_terminal_nul_are_not_interchangeable() {
    let bytes = canonical(&fixture());
    let mandate = digest(MANDATE_DOMAIN, &bytes);
    for domain in [
        OPERATION_DOMAIN,
        b"vollmacht:envelope:v1\0",
        b"vollmacht:experimental:canonicalization-spike:v1\0",
        b"vollmacht:mandate:v1",
        b"vollmacht:mandate:v1\\0",
    ] {
        assert_ne!(mandate, digest(domain, &bytes));
    }
    assert_ne!(mandate, sha256(&bytes));
}
