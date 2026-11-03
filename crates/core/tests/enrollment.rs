use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint},
    nid::Nid,
};
use serde_json::{Value, json};
use vollmacht_core::{AgentPublicKey, EnrollmentError, EnrollmentProposal};

const JKT: &str = "KYr_s7rLdcmRnbs5k_vZzNmmRFy-bdkEJ6tOWG7bmvA";
const ADMIN_DIGEST: &str = "1OVihwJNe8X0su9Rw8l8qZXRKJNq1fac7qAGrtqTm7g";
const KEY: &str = r#"{"crv":"P-256","kty":"EC","x":"Ij37A_aYrepvzVf98UJy1SmwPHO9_FgX2YfstttgLIY","y":"Zbru1vbQeWUvylQf0vdF__UNcoqT-a3fdiEaZTPZwOY"}"#;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}
fn oracle() -> String {
    fixture()["canonical_proposal"].as_str().unwrap().to_owned()
}
fn proposal() -> Value {
    serde_json::from_str(&oracle()).unwrap()
}
fn key() -> Value {
    serde_json::from_str(KEY).unwrap()
}
// Mutation encoding only. Positive expected bytes/digests above are independent
// reviewed fixture data, never calculated with production functions.
fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}
fn rejects(value: &Value) {
    assert!(
        EnrollmentProposal::parse_canonical(&canonical(value)).is_err(),
        "{value}"
    );
}
fn changed(field: &str, replacement: Value) -> Value {
    let mut value = proposal();
    value[field] = replacement;
    value
}

#[test]
fn independent_public_key_thumbprint_and_administrative_digest_oracles_match() {
    let f = fixture();
    assert_eq!(f["proposal"]["agent_key"], key());
    assert_eq!(f["proposal"]["agent_jkt"], JKT);
    assert_eq!(f["enrollment_challenge"], ADMIN_DIGEST);
    let parsed_key = AgentPublicKey::parse_canonical(KEY.as_bytes()).unwrap();
    assert_eq!(parsed_key.fields().len(), 4);
    assert_eq!(parsed_key.canonical_bytes(), KEY.as_bytes());
    assert_eq!(B64.encode(parsed_key.thumbprint().unwrap()), JKT);
    let original = oracle();
    let parsed = EnrollmentProposal::parse_canonical(original.as_bytes()).unwrap();
    assert_eq!(parsed.fields().len(), 17);
    assert_eq!(parsed.canonical_bytes(), original.as_bytes());
    assert_eq!(parsed.agent_key().canonical_bytes(), KEY.as_bytes());
    assert_eq!(
        B64.encode(parsed.authorization_digest().unwrap()),
        ADMIN_DIGEST
    );
}

#[test]
fn proposal_and_nested_key_require_every_field_and_reject_extras_and_wrong_types() {
    for path in ["", "/agent_key"] {
        let source = proposal();
        for (name, expected) in source.pointer(path).unwrap().as_object().unwrap() {
            let mut missing = source.clone();
            missing
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(name);
            rejects(&missing);
            for bad in [
                Value::Null,
                json!(true),
                json!([]),
                json!({}),
                json!(1),
                json!("1"),
            ] {
                if (expected.is_object() && bad.is_object())
                    || (expected.is_string() && bad.is_string())
                    || (expected.is_number() && bad.is_number())
                {
                    continue;
                }
                let mut modified = source.clone();
                modified.pointer_mut(path).unwrap()[name] = bad;
                rejects(&modified);
            }
        }
        for extra in ["unknown", "d", "kid", "alg", "exp"] {
            let mut modified = source.clone();
            modified.pointer_mut(path).unwrap()[extra] = json!("AA");
            rejects(&modified);
        }
    }
    for name in ["crv", "kty", "x", "y"] {
        let mut missing = key();
        missing.as_object_mut().unwrap().remove(name);
        assert!(AgentPublicKey::parse(&canonical(&missing)).is_err());
    }
    for extra in ["d", "alg", "use", "key_ops", "kid"] {
        let mut modified = key();
        modified[extra] = json!("AA");
        assert!(AgentPublicKey::parse(&canonical(&modified)).is_err());
    }
}

#[test]
fn public_key_labels_coordinate_encodings_and_curve_points_are_validated() {
    for (field, bad) in [
        ("kty", "RSA"),
        ("kty", "ec"),
        ("crv", "P-384"),
        ("crv", "prime256v1"),
    ] {
        let mut modified = key();
        modified[field] = json!(bad);
        assert!(AgentPublicKey::parse(&canonical(&modified)).is_err());
    }
    for field in ["x", "y"] {
        let original = key()[field].as_str().unwrap().to_owned();
        // Fixture's final character uses only the high four bits; adding one
        // preserves decoded bytes but sets forbidden nonzero trailing bits.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = alphabet
            .iter()
            .position(|byte| *byte == *original.as_bytes().last().unwrap())
            .unwrap();
        assert_eq!(last % 4, 0);
        let alias = format!("{}{}", &original[..42], char::from(alphabet[last + 1]));
        for bad in [
            "".into(),
            B64.encode([0; 31]),
            B64.encode([0; 33]),
            format!("{original}="),
            alias,
            format!("{original} "),
        ] {
            let mut modified = key();
            modified[field] = json!(bad);
            assert!(AgentPublicKey::parse(&canonical(&modified)).is_err());
        }
    }
    let mut zero = key();
    zero["x"] = json!(B64.encode([0; 32]));
    zero["y"] = json!(B64.encode([0; 32]));
    let mut outside = key();
    outside["x"] = json!(B64.encode([255; 32]));
    for invalid in [zero, outside] {
        assert!(AgentPublicKey::parse(&canonical(&invalid)).is_err());
        let mut nested = proposal();
        nested["agent_key"] = invalid;
        rejects(&nested);
    }
}

#[test]
fn field_shifted_coordinate_cannot_alias_a_valid_point() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut context = BigNumContext::new().unwrap();
    // Maintained compressed-point import finds a valid small x. No curve
    // equation or square-root implementation is duplicated in this test.
    let point = (0..=255_u8)
        .find_map(|small_x| {
            let mut compressed = [0_u8; 33];
            compressed[0] = 2;
            compressed[32] = small_x;
            EcPoint::from_bytes(&group, &compressed, &mut context).ok()
        })
        .expect("bounded fixture search must find a valid small-x point");
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    point
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)
        .unwrap();
    let mut p = BigNum::new().unwrap();
    let mut a = BigNum::new().unwrap();
    let mut b = BigNum::new().unwrap();
    group
        .components_gfp(&mut p, &mut a, &mut b, &mut context)
        .unwrap();
    let mut shifted_x = BigNum::new().unwrap();
    shifted_x.checked_add(&x, &p).unwrap();
    let original_x = x.to_vec_padded(32).unwrap();
    let shifted_x = shifted_x.to_vec_padded(32).unwrap();
    assert_ne!(original_x, shifted_x);
    let mut valid = key();
    valid["x"] = json!(B64.encode(original_x));
    valid["y"] = json!(B64.encode(y.to_vec_padded(32).unwrap()));
    assert!(AgentPublicKey::parse_canonical(&canonical(&valid)).is_ok());
    let mut shifted = valid;
    shifted["x"] = json!(B64.encode(shifted_x));
    // Reject whether the backend rejects or normalizes the same field residue.
    assert_eq!(
        AgentPublicKey::parse(&canonical(&shifted)).unwrap_err(),
        EnrollmentError::InvalidInput
    );
    let mut nested = proposal();
    nested["agent_key"] = shifted;
    rejects(&nested);
}

#[test]
fn candidate_thumbprint_must_match_but_matching_key_is_not_enrollment() {
    for jkt in [
        B64.encode([0; 32]),
        "".into(),
        B64.encode([0; 31]),
        B64.encode([0; 33]),
        format!("{JKT}="),
        format!("{}B", "A".repeat(42)),
    ] {
        rejects(&changed("agent_jkt", json!(jkt)));
    }
    // No current installation, administrator, ceremony or clock is supplied.
    // Changed well-formed references remain structural inputs, not trusted IDs.
    for field in [
        "operation_id",
        "installation_id",
        "audience",
        "principal_id",
        "ceremony_id",
    ] {
        let valid = changed(field, json!("0123456789abcdef0123456789abcdef"));
        let parsed = EnrollmentProposal::parse_canonical(&canonical(&valid)).unwrap();
        assert_ne!(
            B64.encode(parsed.authorization_digest().unwrap()),
            ADMIN_DIGEST
        );
        for bad in [
            "".into(),
            "a".repeat(31),
            "a".repeat(33),
            "A".repeat(32),
            "g".repeat(32),
        ] {
            rejects(&changed(field, json!(bad)));
        }
    }
}

#[test]
fn exact_literals_nonce_and_credential_bounds_are_enforced() {
    for (field, bad) in [
        ("version", json!(0)),
        ("version", json!(2)),
        ("crypto_profile", json!("unknown")),
        ("crypto_profile", json!("vollmacht-local-es256-v0")),
        ("operation", json!("rotate_agent")),
        ("operation", json!("enroll_agent ")),
    ] {
        rejects(&changed(field, bad));
    }
    for size in [1, 1_024] {
        assert!(
            EnrollmentProposal::parse_canonical(&canonical(&changed(
                "credential_id",
                json!(B64.encode(vec![0; size]))
            )))
            .is_ok()
        );
    }
    for bad in [
        "".into(),
        "AB".into(),
        "AA=".into(),
        B64.encode(vec![0; 1_025]),
    ] {
        rejects(&changed("credential_id", json!(bad)));
    }
    for bad in [
        "".into(),
        B64.encode([0; 31]),
        B64.encode([0; 33]),
        format!("{}=", B64.encode([0; 32])),
        format!("{}B", "A".repeat(42)),
    ] {
        rejects(&changed("nonce", json!(bad)));
    }
    let modified = changed("nonce", json!(B64.encode([2; 32])));
    assert_ne!(
        B64.encode(
            EnrollmentProposal::parse_canonical(&canonical(&modified))
                .unwrap()
                .authorization_digest()
                .unwrap()
        ),
        ADMIN_DIGEST
    );
}

#[test]
fn revisions_and_ttl_are_bounded_without_current_clock_or_unsigned_underflow() {
    const MAX: u64 = 9_007_199_254_740_991;
    for field in [
        "registry_revision",
        "credential_revision",
        "policy_revision",
    ] {
        for valid in [1, MAX] {
            assert!(
                EnrollmentProposal::parse_canonical(&canonical(&changed(field, json!(valid))))
                    .is_ok()
            );
        }
        for bad in [json!(0), json!(-1), json!(MAX + 1), json!(u64::MAX)] {
            rejects(&changed(field, bad));
        }
    }
    for start in [0, 1, MAX - 120] {
        for ttl in [1, 119, 120] {
            let mut valid = proposal();
            valid["issued_at"] = json!(start);
            valid["expires_at"] = json!(start + ttl);
            assert!(EnrollmentProposal::parse_canonical(&canonical(&valid)).is_ok());
        }
    }
    for (start, end) in [(0, 0), (1, 1), (2, 1), (0, 121), (MAX, 0), (MAX, MAX)] {
        let mut invalid = proposal();
        invalid["issued_at"] = json!(start);
        invalid["expires_at"] = json!(end);
        rejects(&invalid);
    }
    for field in ["issued_at", "expires_at"] {
        for bad in [json!(-1), json!(MAX + 1), json!(u64::MAX)] {
            rejects(&changed(field, bad));
        }
    }
}

#[test]
fn raw_byte_limits_are_enforced_before_reconstruction_and_only_proposal_canonicality_is_allowed() {
    let padded_key = format!("{}{}", " ".repeat(512 - KEY.len()), KEY);
    assert_eq!(
        AgentPublicKey::parse(padded_key.as_bytes())
            .unwrap()
            .canonical_bytes(),
        KEY.as_bytes()
    );
    assert_eq!(
        AgentPublicKey::parse_canonical(padded_key.as_bytes()).unwrap_err(),
        EnrollmentError::NonCanonical
    );
    assert!(AgentPublicKey::parse(format!(" {padded_key}").as_bytes()).is_err());
    let original = oracle();
    let padded = format!("{}{}", " ".repeat(4_096 - original.len()), original);
    assert_eq!(
        EnrollmentProposal::parse_canonical(padded.as_bytes()).unwrap_err(),
        EnrollmentError::NonCanonical
    );
    assert_eq!(
        EnrollmentProposal::parse_canonical(format!(" {padded}").as_bytes()).unwrap_err(),
        EnrollmentError::InvalidInput
    );
    let nested = original.replace(
        "\"agent_key\":{",
        &format!("\"agent_key\":{{{}", " ".repeat(513)),
    );
    assert_ne!(nested, original);
    assert!(nested.len() < 4_096);
    assert!(EnrollmentProposal::parse_canonical(nested.as_bytes()).is_err());
    for variant in [
        format!(" {original}"),
        serde_json::to_string_pretty(&proposal()).unwrap(),
        original.replace("\"version\"", "\"\\u0076ersion\""),
    ] {
        assert_eq!(
            EnrollmentProposal::parse_canonical(variant.as_bytes()).unwrap_err(),
            EnrollmentError::NonCanonical
        );
    }
    let formatted = serde_json::to_string_pretty(&key()).unwrap();
    assert_eq!(
        AgentPublicKey::parse(formatted.as_bytes())
            .unwrap()
            .canonical_bytes(),
        KEY.as_bytes()
    );
    assert_eq!(
        AgentPublicKey::parse_canonical(formatted.as_bytes()).unwrap_err(),
        EnrollmentError::NonCanonical
    );
}

#[test]
fn decoded_duplicate_and_lexical_failures_remain_redacted() {
    let original = oracle();
    for replacement in [
        "\"version\":1,\"\\u0076ersion\":1",
        "\"version\":1.0",
        "\"version\":1e0",
        "\"version\":-0",
    ] {
        let invalid = original.replace("\"version\":1", replacement);
        assert_ne!(invalid, original);
        assert!(EnrollmentProposal::parse_canonical(invalid.as_bytes()).is_err());
    }
    let duplicate_key = KEY.replace("\"kty\":", "\"\\u006bty\":\"EC\",\"kty\":");
    assert!(AgentPublicKey::parse(duplicate_key.as_bytes()).is_err());
    let error = EnrollmentProposal::parse_canonical(&canonical(&changed(
        "crypto_profile",
        json!("DO_NOT_ECHO_THIS_SECRET"),
    )))
    .unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
}
