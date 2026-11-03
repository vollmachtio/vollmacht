use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use vollmacht_core::{
    ApprovalPayload, EnvelopeError, MandateEnvelope, envelope_digest, mandate_digest,
    operation_digest,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}

fn original() -> String {
    fixture()["issuer"]["canonical_payload"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn value() -> Value {
    serde_json::from_str(&original()).unwrap()
}

// Used only to arrange mutated fixtures, never to generate expected oracle bytes.
fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn parse(value: &Value) -> MandateEnvelope {
    MandateEnvelope::parse_canonical(&canonical(value)).unwrap()
}

fn reject(value: &Value) {
    assert_eq!(
        MandateEnvelope::parse_canonical(&canonical(value)).unwrap_err(),
        EnvelopeError::InvalidEnvelope
    );
}

#[test]
fn independent_envelope_and_all_three_digest_oracles_match() {
    let f = fixture();
    let original = original();
    let envelope = MandateEnvelope::parse_canonical(original.as_bytes()).unwrap();
    assert_eq!(envelope.canonical_bytes(), original.as_bytes());
    assert_eq!(
        envelope.approval().canonical_bytes(),
        f["canonical_approval"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        envelope.evidence(),
        value()["evidence"].as_object().unwrap()
    );
    // Independently generated literal digests cover the exact named domain and
    // its terminal NUL. Expected values do not call production digest functions.
    let expected = [
        "cPADub8ZYk9k4lytHWn0RCCKrzTZhTnW0oAeVlhGmjg",
        "m52GQUq-f3bYHyg28thpea1vIdPud7HtMex-NFBSoU8",
        "5SfYT2j0480tDJX_1e912WPIUr0XV5Mxo8UhjPiF1jY",
    ];
    for (name, literal) in ["mandate_digest", "operation_digest", "envelope_digest"]
        .into_iter()
        .zip(expected)
    {
        assert_eq!(f["execution"]["payload"][name], literal);
    }
    let digests = [
        mandate_digest(envelope.approval()).unwrap(),
        operation_digest(envelope.approval()).unwrap(),
        envelope_digest(&envelope).unwrap(),
    ];
    for (actual, literal) in digests.into_iter().zip(expected) {
        assert_eq!(B64.encode(actual), literal);
    }
}

#[test]
fn envelope_and_evidence_require_exact_fields_and_types() {
    for path in ["", "/evidence"] {
        let source = value();
        for (name, expected) in source.pointer(path).unwrap().as_object().unwrap() {
            let mut missing = source.clone();
            missing
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(name);
            reject(&missing);
            for wrong in [
                Value::Null,
                json!(true),
                json!([]),
                json!({}),
                json!("1"),
                json!(1),
            ] {
                if (expected.is_object() && wrong.is_object())
                    || (expected.is_string() && wrong.is_string())
                    || (expected.is_number() && wrong.is_number())
                {
                    continue;
                }
                let mut changed = source.clone();
                changed.pointer_mut(path).unwrap()[name] = wrong;
                reject(&changed);
            }
        }
        for name in ["unknown", "crypto_profile", "exp"] {
            let mut changed = source.clone();
            changed.pointer_mut(path).unwrap()[name] = json!(1);
            reject(&changed);
        }
    }
    for version in [0, 2] {
        let mut changed = value();
        changed["version"] = json!(version);
        reject(&changed);
    }
    for kind in ["webauthn.create", "WEBAUTHN.GET", ""] {
        let mut changed = value();
        changed["evidence"]["kind"] = json!(kind);
        reject(&changed);
    }
}

#[test]
fn evidence_binary_fields_enforce_exact_decoded_bounds_and_canonical_encoding() {
    for (field, min, max) in [
        ("client_data_json", 1, 12_288),
        ("authenticator_data", 37, 8_192),
        ("signature", 1, 1_024),
        ("user_handle", 0, 64),
    ] {
        for length in [min, max] {
            let mut changed = value();
            changed["evidence"][field] = json!(B64.encode(vec![0; length]));
            parse(&changed);
        }
        let mut lengths = vec![max + 1];
        if min > 0 {
            lengths.push(min - 1);
        }
        for length in lengths {
            let mut changed = value();
            changed["evidence"][field] = json!(B64.encode(vec![0; length]));
            reject(&changed);
        }
        // 37 bytes meets every nonempty minimum and ends with four unused bits.
        let correct = B64.encode(vec![0; 37]);
        for invalid in [
            format!("{correct}="),
            format!("{correct} "),
            format!("{}B", &correct[..correct.len() - 1]),
            format!("{}+", &correct[..correct.len() - 1]),
            "A".into(),
        ] {
            let mut changed = value();
            changed["evidence"][field] = json!(invalid);
            reject(&changed);
        }
    }
}

#[test]
fn evidence_credential_must_be_canonical_and_equal_to_approval() {
    for length in [1, 1_024] {
        let id = B64.encode(vec![0; length]);
        let mut changed = value();
        changed["payload"]["credential_id"] = json!(id);
        changed["evidence"]["credential_id"] = changed["payload"]["credential_id"].clone();
        parse(&changed);
    }
    for id in [
        "".into(),
        "AB".into(),
        "AA=".into(),
        B64.encode(vec![0; 1_025]),
        "AQIDBQ".into(),
    ] {
        let mut changed = value();
        changed["evidence"]["credential_id"] = json!(id);
        reject(&changed);
    }
}

#[test]
fn signed_bytes_are_opaque_preserved_and_not_claimed_verified() {
    for bytes in [b" \n{\"x\":1,\"x\":2}\t".as_slice(), &[0xff, 0x00, 0xfe]] {
        let mut changed = value();
        changed["evidence"]["client_data_json"] = json!(B64.encode(bytes));
        let parsed = parse(&changed);
        assert_eq!(
            B64.decode(parsed.evidence()["client_data_json"].as_str().unwrap())
                .unwrap(),
            bytes
        );
        assert_eq!(parsed.canonical_bytes(), canonical(&changed));
    }
    // Syntactic evidence limits permit these bytes; no UP/UV/signature claim.
    let mut largest = value();
    for (field, count) in [
        ("client_data_json", 12_288),
        ("authenticator_data", 8_192),
        ("signature", 1_024),
        ("user_handle", 64),
    ] {
        largest["evidence"][field] = json!(B64.encode(vec![0; count]));
    }
    let parsed = parse(&largest);
    assert!(parsed.canonical_bytes().len() < 65_536);
}

#[test]
fn embedded_payload_schema_and_original_nested_whitespace_are_not_bypassed() {
    for (path, wrong) in [
        ("/payload/crypto_profile", json!("unknown")),
        ("/payload/version", json!(2)),
        (
            "/payload/operation/constraints/base_ref",
            json!("bad..branch"),
        ),
        ("/payload/policy_revision", json!(0)),
    ] {
        let mut changed = value();
        *changed.pointer_mut(path).unwrap() = wrong;
        reject(&changed);
    }
    let mut missing = value();
    missing["payload"]
        .as_object_mut()
        .unwrap()
        .remove("crypto_profile");
    reject(&missing);
    let original = original();
    let padded = original.replace(
        "\"payload\":{",
        &format!("\"payload\":{{{}", " ".repeat(8_193)),
    );
    assert_ne!(padded, original);
    assert!(padded.len() < 65_536);
    assert!(MandateEnvelope::parse_canonical(padded.as_bytes()).is_err());
    let duplicate = original.replace("\"kind\":", "\"\\u006bind\":\"webauthn.get\",\"kind\":");
    assert!(MandateEnvelope::parse_canonical(duplicate.as_bytes()).is_err());
}

#[test]
fn canonical_only_envelope_rejects_original_whitespace_order_and_escape_variants() {
    let original = original();
    let source = value();
    let reversed = format!(
        "{{\"version\":1,\"payload\":{},\"evidence\":{}}}",
        source["payload"], source["evidence"]
    );
    for variant in [
        format!(" {original}"),
        serde_json::to_string_pretty(&source).unwrap(),
        reversed,
        original.replace("\"version\"", "\"\\u0076ersion\""),
    ] {
        assert_ne!(variant, original);
        assert_eq!(
            MandateEnvelope::parse_canonical(variant.as_bytes()).unwrap_err(),
            EnvelopeError::NonCanonical
        );
    }
    let at_limit = format!("{}{}", " ".repeat(65_536 - original.len()), original);
    assert_eq!(
        MandateEnvelope::parse_canonical(at_limit.as_bytes()).unwrap_err(),
        EnvelopeError::NonCanonical
    );
    assert_eq!(
        MandateEnvelope::parse_canonical(format!(" {at_limit}").as_bytes()).unwrap_err(),
        EnvelopeError::InvalidEnvelope
    );
}

#[test]
fn operation_digest_excludes_authority_and_display_but_mandate_binds_them() {
    let original = parse(&value());
    let operation = operation_digest(original.approval()).unwrap();
    let mandate = mandate_digest(original.approval()).unwrap();
    for (field, replacement) in [
        ("mandate_id", json!("0".repeat(32))),
        ("issuer_id", json!("0".repeat(32))),
        ("audience", json!("0".repeat(32))),
        ("principal_id", json!("0".repeat(32))),
        ("nonce", json!(B64.encode([1; 32]))),
        ("agent_jkt", json!(B64.encode([1; 32]))),
        ("credential_id", json!("AA")),
        ("policy_revision", json!(2)),
        ("issued_at", json!(1_800_000_001)),
        ("expires_at", json!(1_800_000_121)),
        ("display", json!({"version":1,"repository":"other/repo"})),
    ] {
        let mut changed = value()["payload"].clone();
        changed[field] = replacement;
        let approval = ApprovalPayload::parse(&canonical(&changed)).unwrap();
        assert_eq!(operation_digest(&approval).unwrap(), operation, "{field}");
        assert_ne!(mandate_digest(&approval).unwrap(), mandate, "{field}");
    }
    for (path, replacement) in [
        ("/constraints/base_ref", json!("other")),
        ("/constraints/expected_head_sha", json!("b".repeat(40))),
        ("/constraints/merge_method", json!("merge")),
        ("/resource/repository_id", json!("23456")),
        ("/resource/pull_request_number", json!(43)),
    ] {
        let mut changed = value()["payload"].clone();
        *changed["operation"].pointer_mut(path).unwrap() = replacement;
        let approval = ApprovalPayload::parse(&canonical(&changed)).unwrap();
        assert_ne!(operation_digest(&approval).unwrap(), operation);
        assert_ne!(mandate_digest(&approval).unwrap(), mandate);
    }
}

#[test]
fn evidence_mutations_change_only_envelope_digest_not_approval_digests() {
    let original = parse(&value());
    for (field, bytes) in [
        ("client_data_json", vec![1]),
        ("authenticator_data", vec![1; 37]),
        ("signature", vec![1]),
        ("user_handle", vec![1]),
    ] {
        let mut changed = value();
        changed["evidence"][field] = json!(B64.encode(bytes));
        let parsed = parse(&changed);
        assert_ne!(
            envelope_digest(&parsed).unwrap(),
            envelope_digest(&original).unwrap()
        );
        assert_eq!(
            mandate_digest(parsed.approval()).unwrap(),
            mandate_digest(original.approval()).unwrap()
        );
        assert_eq!(
            operation_digest(parsed.approval()).unwrap(),
            operation_digest(original.approval()).unwrap()
        );
    }
    let mut invalid = value();
    invalid["evidence"]["kind"] = json!("DO_NOT_ECHO_THIS_SECRET");
    let error = MandateEnvelope::parse_canonical(&canonical(&invalid)).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
}
