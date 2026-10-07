//! Candidate bytes and context relationships only, not enrollment authorization.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::sha::sha256;
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn vector() -> Value {
    serde_json::from_str(include_str!("../fixtures/candidate-enrollment-vector.json")).unwrap()
}
fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}
fn digest(domain: &[u8], value: &Value) -> [u8; 32] {
    sha256(&[domain, &canonical(value)].concat())
}
const DOMAIN: &[u8] = b"vollmacht:admin:enroll-agent:v1\0";

#[test]
fn literal_bytes_domains_and_public_key_match_independent_node_oracle() {
    let v = vector();
    assert_eq!(v["profile"], "candidate-agent-enrollment-v1");
    for (object, bytes, limit) in [
        ("proposal", "canonical_proposal", 4096),
        ("payload", "canonical_payload", 2048),
        ("protected_header", "canonical_header", 512),
    ] {
        let encoded = canonical(&v[object]);
        assert_eq!(encoded, v[bytes].as_str().unwrap().as_bytes());
        assert!(encoded.len() <= limit);
    }
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(hex(DOMAIN), v["domain_hex"]);
    let hash = digest(DOMAIN, &v["proposal"]);
    assert_eq!(hex(&hash), v["authorization_digest_hex"]);
    assert_eq!(B64.encode(hash), v["authorization_digest"]);
    for domain in [
        b"vollmacht:admin:enroll-agent:v1".as_slice(),
        b"vollmacht:admin:enroll-agent:v1\0\0",
        b"vollmacht:mandate:v1\0",
        b"vollmacht:operation:v1\0",
    ] {
        assert_ne!(digest(domain, &v["proposal"]), hash);
    }
    let key = &v["trusted"]["candidate_jwk"];
    assert_eq!(key.as_object().unwrap().len(), 4);
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert!(key.get("d").is_none());
    for field in ["x", "y"] {
        let encoded = key[field].as_str().unwrap();
        assert_eq!(B64.decode(encoded).unwrap().len(), 32);
        assert_eq!(B64.encode(B64.decode(encoded).unwrap()), encoded);
    }
    let jkt = B64.encode(sha256(&canonical(key)));
    assert_eq!(v["proposal"]["agent_key"], *key);
    assert_eq!(v["proposal"]["agent_jkt"], jkt);
    assert_eq!(v["payload"]["agent_jkt"], jkt);
    assert_eq!(
        v["protected_header"],
        json!({"alg":"ES256", "typ":"vollmacht-agent-enrollment+jws", "kid":jkt})
    );
    let previous: Value =
        serde_json::from_str(include_str!("../fixtures/candidate-agent-vector.json")).unwrap();
    assert_eq!(*key, previous["trusted"]["agent_jwk"]);
}

#[test]
fn exact_proposal_and_pending_bindings_include_separate_stages_and_nested_intervals() {
    let v = vector();
    let a = &v["proposal"];
    let b = &v["payload"];
    let fields: BTreeSet<_> = a.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        fields,
        BTreeSet::from([
            "version",
            "operation",
            "operation_id",
            "installation_id",
            "audience",
            "principal_id",
            "credential_id",
            "registry_revision",
            "credential_revision",
            "policy_revision",
            "agent_key",
            "agent_jkt",
            "ceremony_id",
            "nonce",
            "issued_at",
            "expires_at"
        ])
    );
    assert_eq!(a["version"], 1);
    assert_eq!(a["operation"], "enroll_agent");
    for field in [
        "registry_revision",
        "credential_revision",
        "policy_revision",
    ] {
        assert!(a[field].as_u64().unwrap() > 0);
    }
    assert_eq!(b, &v["trusted"]["pending"]);
    let mut expected = json!({});
    for field in [
        "version",
        "operation",
        "operation_id",
        "installation_id",
        "audience",
        "principal_id",
        "agent_jkt",
    ] {
        expected[field] = a[field].clone();
    }
    expected["authorization_digest"] = v["authorization_digest"].clone();
    expected["ceremony_id"] = Value::from("99999999999999999999999999999999");
    expected["challenge"] = Value::from(B64.encode([22; 32]));
    expected["issued_at"] = Value::from(1_800_000_060);
    expected["expires_at"] = Value::from(1_800_000_090);
    assert_eq!(*b, expected);
    assert_ne!(a["ceremony_id"], b["ceremony_id"]);
    assert_eq!(a["nonce"], B64.encode([21; 32]));
    let time = |object: &Value, field: &str| object[field].as_u64().unwrap();
    assert_eq!(time(a, "expires_at") - time(a, "issued_at"), 120);
    assert_eq!(time(b, "expires_at") - time(b, "issued_at"), 30);
    assert!(time(b, "issued_at") >= time(a, "issued_at"));
    assert!(time(b, "expires_at") <= time(a, "expires_at"));
    // These are fixed fixture relationships, not a runtime clock or capability.
}

fn leaves(value: &Value, prefix: &str, output: &mut BTreeSet<String>) {
    if let Some(map) = value.as_object() {
        for (name, child) in map {
            leaves(child, &format!("{prefix}/{name}"), output);
        }
    } else {
        assert!(value.is_string() || value.is_u64());
        output.insert(prefix.to_owned());
    }
}

#[test]
fn every_proposal_leaf_is_bound_including_identity_candidate_and_revisions() {
    let v = vector();
    let a = &v["proposal"];
    let mut paths = BTreeSet::new();
    leaves(a, "", &mut paths);
    let expected = [
        "version",
        "operation",
        "operation_id",
        "installation_id",
        "audience",
        "principal_id",
        "credential_id",
        "registry_revision",
        "credential_revision",
        "policy_revision",
        "agent_key/kty",
        "agent_key/crv",
        "agent_key/x",
        "agent_key/y",
        "agent_jkt",
        "ceremony_id",
        "nonce",
        "issued_at",
        "expires_at",
    ];
    assert_eq!(
        paths,
        expected.map(|s| format!("/{s}")).into_iter().collect()
    );
    for path in paths {
        let mut altered = a.clone();
        let field = altered.pointer_mut(&path).unwrap();
        *field = if let Some(n) = field.as_u64() {
            Value::from(n + 1)
        } else {
            Value::from(format!("{}x", field.as_str().unwrap()))
        };
        assert_ne!(digest(DOMAIN, &altered), digest(DOMAIN, a), "{path}");
    }
    // Some mutations intentionally violate the profile: no parser is tested here.
}

#[test]
fn signed_variants_change_exactly_the_declared_context_or_type() {
    let v = vector();
    let variants = v["variants"].as_array().unwrap();
    let cases = [
        ("wrong-audience", "audience"),
        ("wrong-stage", "ceremony_id"),
        ("wrong-authorization-digest", "authorization_digest"),
        ("wrong-candidate", "agent_jkt"),
        ("execution-type", "typ"),
    ];
    assert_eq!(variants.len(), cases.len());
    for (id, field) in cases {
        let matches: Vec<_> = variants.iter().filter(|item| item["id"] == id).collect();
        assert_eq!(matches.len(), 1);
        let item = matches[0];
        for (object, encoded) in [
            ("payload", "canonical_payload"),
            ("protected_header", "canonical_header"),
        ] {
            assert_eq!(
                canonical(&item[object]),
                item[encoded].as_str().unwrap().as_bytes()
            );
        }
        let (changed, unchanged) = if field == "typ" {
            ("protected_header", "payload")
        } else {
            ("payload", "protected_header")
        };
        assert_eq!(item[unchanged], v[unchanged]);
        assert_ne!(item[changed][field], v[changed][field]);
        let mut restored = item[changed].clone();
        restored[field] = v[changed][field].clone();
        assert_eq!(restored, v[changed]);
    }
}
