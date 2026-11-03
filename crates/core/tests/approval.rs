use serde_json::{Value, json};
use vollmacht_core::{ApprovalError, ApprovalPayload};

// The expected bytes were generated independently with the reviewed Node oracle.
// Never derive the expected canonical string using the implementation under test.
fn oracle() -> String {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap();
    fixture["canonical_approval"].as_str().unwrap().to_owned()
}

fn payload() -> Value {
    serde_json::from_str(&oracle()).unwrap()
}

fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn accepts(value: &Value) {
    assert!(ApprovalPayload::parse(&encoded(value)).is_ok(), "{value}");
}

fn rejects(value: &Value) {
    assert_eq!(
        ApprovalPayload::parse(&encoded(value)).unwrap_err(),
        ApprovalError::InvalidPayload,
        "{value}"
    );
}

fn with(path: &str, replacement: Value) -> Value {
    let mut value = payload();
    *value.pointer_mut(path).unwrap() = replacement;
    value
}

// Known base64url representation of all-zero bytes, not a general encoder.
fn zeros(bytes: usize) -> String {
    "A".repeat((bytes * 8).div_ceil(6))
}

#[test]
fn independent_current_fixture_matches_literal_canonical_oracle() {
    let original = oracle();
    let parsed = ApprovalPayload::parse(original.as_bytes()).unwrap();
    assert_eq!(parsed.fields().len(), 14);
    assert_eq!(parsed.canonical_bytes(), original.as_bytes());
    assert_eq!(parsed.fields()["operation"], payload()["operation"]);
    assert!(ApprovalPayload::parse_canonical(original.as_bytes()).is_ok());
}

#[test]
fn every_field_is_required_and_every_object_rejects_unknown_members() {
    for path in [
        "",
        "/operation",
        "/operation/resource",
        "/operation/constraints",
        "/display",
    ] {
        let source = payload();
        let fields = source.pointer(path).unwrap().as_object().unwrap();
        for name in fields.keys() {
            let mut changed = source.clone();
            changed
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(name);
            rejects(&changed);
        }
        for name in ["unexpected", "exp", "crypto_profile_extra"] {
            let mut changed = source.clone();
            changed
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(name.into(), json!(1));
            rejects(&changed);
        }
    }
}

#[test]
fn every_field_rejects_wrong_json_types_without_coercion() {
    for path in [
        "",
        "/operation",
        "/operation/resource",
        "/operation/constraints",
        "/display",
    ] {
        let source = payload();
        for (name, expected) in source.pointer(path).unwrap().as_object().unwrap() {
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
                rejects(&with(&format!("{path}/{name}"), wrong));
            }
        }
    }
}

#[test]
fn exact_literals_and_lowercase_identity_grammars_are_enforced() {
    for path in ["/version", "/display/version"] {
        for wrong in [0, 2, 9_007_199_254_740_991_u64] {
            rejects(&with(path, json!(wrong)));
        }
    }
    for (path, wrong) in [
        ("/crypto_profile", "vollmacht-local-es256-v0"),
        ("/crypto_profile", "VOLLMACHT-local-es256-v1"),
        ("/crypto_profile", ""),
        ("/operation/action", "github.pull_request.close"),
        ("/operation/resource/host", "GitHub.com"),
        ("/operation/resource/host", "github.com."),
    ] {
        rejects(&with(path, json!(wrong)));
    }
    for path in ["/mandate_id", "/issuer_id", "/audience", "/principal_id"] {
        accepts(&with(path, json!("0123456789abcdef0123456789abcdef")));
        for wrong in [
            "a".repeat(31),
            "a".repeat(33),
            "A".repeat(32),
            "g".repeat(32),
            "".into(),
        ] {
            rejects(&with(path, json!(wrong)));
        }
    }
}

#[test]
fn binary_fields_enforce_decoded_lengths_and_canonical_trailing_bits() {
    for path in ["/nonce", "/agent_jkt"] {
        accepts(&with(path, json!(zeros(32))));
        for wrong in [
            zeros(31),
            zeros(33),
            "".into(),
            format!("{}=", zeros(32)),
            format!("{}B", "A".repeat(42)),
            format!("{}+", "A".repeat(42)),
            format!("{}/", "A".repeat(42)),
            format!("{} ", zeros(32)),
        ] {
            rejects(&with(path, json!(wrong)));
        }
    }
    for length in [1, 2, 3, 32, 1_024] {
        accepts(&with("/credential_id", json!(zeros(length))));
    }
    for wrong in [
        "".into(),
        zeros(1_025),
        "AB".into(),
        "AA=".into(),
        "A".into(),
        "AA\n".into(),
    ] {
        rejects(&with("/credential_id", json!(wrong)));
    }
}

#[test]
fn timestamp_and_revision_bounds_are_schema_checks_not_current_time_checks() {
    const MAX: u64 = 9_007_199_254_740_991;
    for start in [0, 1, MAX - 300] {
        for ttl in [1, 120, 300] {
            let mut value = payload();
            value["issued_at"] = json!(start);
            value["expires_at"] = json!(start + ttl);
            accepts(&value);
        }
    }
    for (start, end) in [(1, 1), (2, 1), (0, 301), (MAX, 0), (MAX, MAX)] {
        let mut value = payload();
        value["issued_at"] = json!(start);
        value["expires_at"] = json!(end);
        rejects(&value);
    }
    for path in ["/issued_at", "/expires_at", "/policy_revision"] {
        for wrong in [json!(-1), json!(MAX + 1), json!(u64::MAX)] {
            rejects(&with(path, wrong));
        }
    }
    accepts(&with("/policy_revision", json!(MAX)));
    rejects(&with("/policy_revision", json!(0)));
}

#[test]
fn repository_and_pr_bounds_do_not_coerce_decimal_strings_to_u64() {
    for id in ["1", "99999999999999999999"] {
        accepts(&with("/operation/resource/repository_id", json!(id)));
    }
    for id in [
        "",
        "0",
        "01",
        "100000000000000000000",
        "+1",
        "1.0",
        "1e0",
        " 1",
        "1 ",
        "-1",
    ] {
        rejects(&with("/operation/resource/repository_id", json!(id)));
    }
    for number in [1, 2_147_483_647_u64] {
        accepts(&with(
            "/operation/resource/pull_request_number",
            json!(number),
        ));
    }
    for number in [0, 2_147_483_648_u64] {
        rejects(&with(
            "/operation/resource/pull_request_number",
            json!(number),
        ));
    }
    for sha in [
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
    ] {
        rejects(&with(
            "/operation/constraints/expected_head_sha",
            json!(sha),
        ));
    }
    accepts(&with(
        "/operation/constraints/expected_head_sha",
        json!("0123456789abcdef0123456789abcdef01234567"),
    ));
    for method in ["merge", "squash", "rebase"] {
        accepts(&with("/operation/constraints/merge_method", json!(method)));
    }
    for method in ["", "Merge", "squash ", "delete"] {
        rejects(&with("/operation/constraints/merge_method", json!(method)));
    }
}

#[test]
fn branch_profile_covers_every_frozen_exclusion_and_preserves_case() {
    let path = "/operation/constraints/base_ref";
    for branch in [
        "a",
        "main",
        "Feature/Ready",
        "a.b/c-d_e",
        "head",
        "a@b",
        "a.locked",
        "a]b",
    ] {
        let parsed = ApprovalPayload::parse(&encoded(&with(path, json!(branch)))).unwrap();
        assert_eq!(
            parsed.fields()["operation"]["constraints"]["base_ref"],
            branch
        );
    }
    accepts(&with(path, json!("a".repeat(255))));
    for branch in [
        "", "-x", "/x", "x/", "x//y", ".x", "x/.y", "x.lock", "x.lock/y", "a..b", "x@{y", "x.",
        "@", "HEAD", "a b", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b",
    ] {
        rejects(&with(path, json!(branch)));
    }
    rejects(&with(path, json!("a".repeat(256))));
    for byte in (0..=0x20_u8).chain([0x7f]) {
        rejects(&with(path, json!(format!("a{}b", char::from(byte)))));
    }
    rejects(&with(path, json!("café")));
}

#[test]
fn display_label_is_exactly_two_nonempty_ascii_components() {
    let path = "/display/repository";
    for label in [
        "a/b",
        "A_1.-/B-2._",
        &format!("{}/{}", "a".repeat(100), "b".repeat(100)),
    ] {
        accepts(&with(path, json!(label)));
    }
    for label in [
        "", "a", "/b", "a/", "a/b/c", "a//b", "a b/c", "a/b?", "é/b", "a\\b/c",
    ] {
        rejects(&with(path, json!(label)));
    }
    rejects(&with(
        path,
        json!(format!("{}/{}", "a".repeat(101), "b".repeat(100))),
    ));
}

#[test]
fn original_byte_limit_cannot_be_bypassed_by_normalization() {
    let original = oracle();
    let at_limit = format!("{}{}", " ".repeat(8_192 - original.len()), original);
    let parsed = ApprovalPayload::parse(at_limit.as_bytes()).unwrap();
    assert_eq!(parsed.canonical_bytes(), original.as_bytes());
    assert!(parsed.canonical_bytes().len() <= 8_192);
    assert_eq!(
        ApprovalPayload::parse_canonical(at_limit.as_bytes()).unwrap_err(),
        ApprovalError::NonCanonical
    );
    assert_eq!(
        ApprovalPayload::parse(format!(" {at_limit}").as_bytes()).unwrap_err(),
        ApprovalError::InvalidPayload
    );

    // All individually largest fields still fit below the canonical ceiling.
    // The raw 8192 boundary above is reachable using whitespace; canonical size
    // cannot be forced to 8192 by inventing fields the schema does not permit.
    let mut largest = payload();
    largest["credential_id"] = json!(zeros(1_024));
    largest["operation"]["constraints"]["base_ref"] = json!("a".repeat(255));
    largest["operation"]["resource"]["repository_id"] = json!("9".repeat(20));
    largest["display"]["repository"] = json!(format!("{}/{}", "a".repeat(100), "b".repeat(100)));
    let parsed = ApprovalPayload::parse(&encoded(&largest)).unwrap();
    assert!(parsed.canonical_bytes().len() <= 8_192);
    assert!(ApprovalPayload::parse_canonical(parsed.canonical_bytes()).is_ok());
}

#[test]
fn formatting_variants_canonicalize_to_independent_bytes_but_are_not_canonical_input() {
    let original = oracle();
    let source = payload();
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
    let escaped = original.replace("\"version\"", "\"\\u0076ersion\"");
    for variant in [
        format!(" \n{original}\t"),
        serde_json::to_string_pretty(&source).unwrap(),
        reversed,
        escaped,
    ] {
        assert_ne!(variant, original);
        let parsed = ApprovalPayload::parse(variant.as_bytes()).unwrap();
        assert_eq!(parsed.canonical_bytes(), original.as_bytes());
        assert_eq!(
            ApprovalPayload::parse_canonical(variant.as_bytes()).unwrap_err(),
            ApprovalError::NonCanonical
        );
        let reparsed = ApprovalPayload::parse_canonical(parsed.canonical_bytes()).unwrap();
        assert_eq!(reparsed.canonical_bytes(), original.as_bytes());
    }
}

#[test]
fn duplicate_and_lexical_checks_run_before_schema_normalization() {
    let original = oracle();
    for (old, new) in [
        ("\"version\":1", "\"version\":1,\"\\u0076ersion\":1"),
        (
            "\"action\":",
            "\"\\u0061ction\":\"github.pull_request.merge\",\"action\":",
        ),
        ("\"policy_revision\":1", "\"policy_revision\":1.0"),
        ("\"policy_revision\":1", "\"policy_revision\":1e0"),
        ("\"policy_revision\":1", "\"policy_revision\":01"),
    ] {
        let changed = original.replace(old, new);
        assert_ne!(changed, original);
        assert_eq!(
            ApprovalPayload::parse(changed.as_bytes()).unwrap_err(),
            ApprovalError::InvalidPayload
        );
    }
    let invalid = with("/crypto_profile", json!("DO_NOT_ECHO_THIS_SECRET"));
    let error = ApprovalPayload::parse(&encoded(&invalid)).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
}
