use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use vollmacht_core::{EnrollmentPossessionPayload, ExecutionProofPayload, ProofPayloadError};

#[derive(Clone, Copy, Debug)]
enum Role {
    Execution,
    Possession,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Possession => "possession",
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Execution => 8_192,
            Self::Possession => 2_048,
        }
    }
    fn parse(self, bytes: &[u8]) -> Result<(Value, Vec<u8>), ProofPayloadError> {
        match self {
            Self::Execution => {
                let parsed = ExecutionProofPayload::parse_canonical(bytes)?;
                Ok((
                    Value::Object(parsed.fields().clone()),
                    parsed.canonical_bytes().to_vec(),
                ))
            }
            Self::Possession => {
                let parsed = EnrollmentPossessionPayload::parse_canonical(bytes)?;
                Ok((
                    Value::Object(parsed.fields().clone()),
                    parsed.canonical_bytes().to_vec(),
                ))
            }
        }
    }
    fn oracle(self) -> String {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
        ))
        .unwrap();
        fixture[self.name()]["canonical_payload"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn value(self) -> Value {
        serde_json::from_str(&self.oracle()).unwrap()
    }
    fn ids(self) -> &'static [&'static str] {
        match self {
            Self::Execution => &["audience"],
            Self::Possession => &[
                "operation_id",
                "installation_id",
                "audience",
                "principal_id",
                "ceremony_id",
            ],
        }
    }
    fn binary(self) -> &'static [&'static str] {
        match self {
            Self::Execution => &[
                "mandate_digest",
                "operation_digest",
                "envelope_digest",
                "challenge",
            ],
            Self::Possession => &["agent_jkt", "authorization_digest", "challenge"],
        }
    }
}

const ROLES: [Role; 2] = [Role::Execution, Role::Possession];

// JCS arranges mutated test cases only; positive expected bytes come directly
// from independently generated accepted fixtures, never this serializer.
fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn changed(role: Role, field: &str, replacement: Value) -> Value {
    let mut value = role.value();
    value[field] = replacement;
    value
}

fn rejects(role: Role, value: &Value) {
    assert_eq!(
        role.parse(&canonical(value)).unwrap_err(),
        ProofPayloadError::InvalidPayload,
        "{role:?}: {value}"
    );
}

#[test]
fn current_independent_oracles_match_both_exact_types() {
    for role in ROLES {
        let oracle = role.oracle();
        let (fields, bytes) = role.parse(oracle.as_bytes()).unwrap();
        assert_eq!(bytes, oracle.as_bytes());
        assert_eq!(fields, role.value());
        assert_eq!(
            fields.as_object().unwrap().len(),
            match role {
                Role::Execution => 9,
                Role::Possession => 13,
            }
        );
        let (_, reparsed) = role.parse(&bytes).unwrap();
        assert_eq!(reparsed, bytes);
    }
}

#[test]
fn every_field_is_required_and_unknown_fields_and_wrong_types_fail() {
    for role in ROLES {
        let source = role.value();
        for (field, expected) in source.as_object().unwrap() {
            let mut missing = source.clone();
            missing.as_object_mut().unwrap().remove(field);
            rejects(role, &missing);
            for wrong in [
                Value::Null,
                json!(true),
                json!([]),
                json!({}),
                json!(1),
                json!("1"),
            ] {
                if (expected.is_number() && wrong.is_number())
                    || (expected.is_string() && wrong.is_string())
                {
                    continue;
                }
                rejects(role, &changed(role, field, wrong));
            }
        }
        for field in ["unexpected", "exp", "kid", "signature", "payload"] {
            rejects(role, &changed(role, field, json!(1)));
        }
    }
}

#[test]
fn versions_profiles_and_possession_operation_are_exact() {
    for role in ROLES {
        for version in [0, 2, 9_007_199_254_740_991_u64] {
            rejects(role, &changed(role, "version", json!(version)));
        }
        for profile in [
            "",
            "vollmacht-local-es256-v0",
            "unknown",
            "VOLLMACHT-local-es256-v1",
            "vollmacht-local-es256-v1 ",
        ] {
            rejects(role, &changed(role, "crypto_profile", json!(profile)));
        }
        rejects(
            role,
            &changed(role, "crypto_profile", json!("x".repeat(65))),
        );
    }
    for operation in [
        "",
        "rotate_agent",
        "enroll_agent ",
        "github.pull_request.merge",
    ] {
        rejects(
            Role::Possession,
            &changed(Role::Possession, "operation", json!(operation)),
        );
    }
}

#[test]
fn identity_grammar_is_not_trust_or_pending_context_validation() {
    for role in ROLES {
        for field in role.ids() {
            let modified = changed(role, field, json!("0123456789abcdef0123456789abcdef"));
            let (parsed, _) = role.parse(&canonical(&modified)).unwrap();
            assert_eq!(parsed[*field], modified[*field]);
            for bad in [
                "".into(),
                "a".repeat(31),
                "a".repeat(33),
                "A".repeat(32),
                "g".repeat(32),
                "é".repeat(32),
            ] {
                rejects(role, &changed(role, field, json!(bad)));
            }
        }
    }
}

#[test]
fn every_binary_field_requires_canonical_base64url_of_exactly_32_bytes() {
    for role in ROLES {
        for field in role.binary() {
            for bytes in [[0; 32], [255; 32]] {
                assert!(
                    role.parse(&canonical(&changed(role, field, json!(B64.encode(bytes)))))
                        .is_ok()
                );
            }
            for bad in [
                "".into(),
                B64.encode([0; 31]),
                B64.encode([0; 33]),
                format!("{}=", B64.encode([0; 32])),
                format!("{}B", "A".repeat(42)),
                format!("{}+", "A".repeat(42)),
                format!("{}/", "A".repeat(42)),
                format!("{} ", B64.encode([0; 32])),
            ] {
                rejects(role, &changed(role, field, json!(bad)));
            }
        }
    }
}

#[test]
fn ttl_bounds_are_checked_without_unsigned_underflow_or_current_clock_assumptions() {
    const MAX: u64 = 9_007_199_254_740_991;
    for role in ROLES {
        for start in [0, 1, MAX - 30] {
            for ttl in [1, 29, 30] {
                let mut value = role.value();
                value["issued_at"] = json!(start);
                value["expires_at"] = json!(start + ttl);
                assert!(role.parse(&canonical(&value)).is_ok());
            }
        }
        for (start, end) in [(0, 0), (1, 1), (2, 1), (0, 31), (MAX, 0), (MAX, MAX)] {
            let mut value = role.value();
            value["issued_at"] = json!(start);
            value["expires_at"] = json!(end);
            rejects(role, &value);
        }
        for field in ["issued_at", "expires_at"] {
            for bad in [json!(-1), json!(MAX + 1), json!(u64::MAX)] {
                rejects(role, &changed(role, field, bad));
            }
        }
    }
}

#[test]
fn cross_role_substitution_and_wrapping_do_not_parse() {
    assert!(
        Role::Execution
            .parse(Role::Possession.oracle().as_bytes())
            .is_err()
    );
    assert!(
        Role::Possession
            .parse(Role::Execution.oracle().as_bytes())
            .is_err()
    );
    for role in ROLES {
        rejects(role, &json!({"version":1,"payload":role.value()}));
        let mut supplied = role.value();
        supplied["signature"] = json!("AA");
        rejects(role, &supplied);
    }
}

#[test]
fn original_caps_and_canonical_only_inputs_cannot_be_bypassed_by_reformatting() {
    for role in ROLES {
        let original = role.oracle();
        let source = role.value();
        let reversed = format!(
            "{{{}}}",
            source
                .as_object()
                .unwrap()
                .iter()
                .rev()
                .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
                .collect::<Vec<_>>()
                .join(",")
        );
        for input in [
            format!(" {original}"),
            serde_json::to_string_pretty(&source).unwrap(),
            reversed,
            original.replace("\"version\"", "\"\\u0076ersion\""),
        ] {
            assert_ne!(input, original);
            assert_eq!(
                role.parse(input.as_bytes()).unwrap_err(),
                ProofPayloadError::NonCanonical
            );
        }
        let padded = format!("{}{}", " ".repeat(role.limit() - original.len()), original);
        assert_eq!(padded.len(), role.limit());
        assert_eq!(
            role.parse(padded.as_bytes()).unwrap_err(),
            ProofPayloadError::NonCanonical
        );
        assert_eq!(
            role.parse(format!(" {padded}").as_bytes()).unwrap_err(),
            ProofPayloadError::InvalidPayload
        );
        // Fixed-size fields cannot form a schema-valid payload at these large
        // ceilings. Test no oversized normalized input is silently accepted.
        assert!(original.len() < role.limit());
    }
}

#[test]
fn decoded_duplicates_and_noninteger_tokens_are_rejected_before_normalization() {
    for role in ROLES {
        let original = role.oracle();
        for replacement in [
            "\"version\":1,\"\\u0076ersion\":1",
            "\"version\":1.0",
            "\"version\":1e0",
            "\"version\":01",
            "\"version\":-0",
        ] {
            let input = original.replace("\"version\":1", replacement);
            assert_ne!(input, original);
            assert_eq!(
                role.parse(input.as_bytes()).unwrap_err(),
                ProofPayloadError::InvalidPayload
            );
        }
        let bad = changed(role, "crypto_profile", json!("DO_NOT_ECHO_THIS_SECRET"));
        let error = role.parse(&canonical(&bad)).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
    }
}
