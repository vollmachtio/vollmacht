use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use vollmacht_core::{CompactError, CompactRole, UnverifiedCompact, UnverifiedPayload};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}

fn cases() -> [(CompactRole, &'static str); 3] {
    [
        (CompactRole::Issuer, "issuer"),
        (CompactRole::Execution, "execution"),
        (CompactRole::EnrollmentPossession, "possession"),
    ]
}

fn parts(name: &str) -> Vec<String> {
    fixture()[name]["jws"]
        .as_str()
        .unwrap()
        .split('.')
        .map(str::to_owned)
        .collect()
}

fn kid(name: &str) -> String {
    let f = fixture();
    let header: Value = serde_json::from_str(f[name]["header_bytes"].as_str().unwrap()).unwrap();
    header["kid"].as_str().unwrap().to_owned()
}

fn reject(bytes: &[u8], role: CompactRole, expected: &str) {
    assert_eq!(
        UnverifiedCompact::parse(bytes, role, expected).unwrap_err(),
        CompactError
    );
}

fn altered(name: &str, segment: usize, decoded: &[u8]) -> String {
    let mut changed = parts(name);
    changed[segment] = B64.encode(decoded);
    changed.join(".")
}

#[test]
fn all_three_independent_artifacts_preserve_original_bytes_and_typed_payloads() {
    let f = fixture();
    for (role, name) in cases() {
        let original = f[name]["jws"].as_str().unwrap();
        let expected_kid = kid(name);
        let parsed = UnverifiedCompact::parse(original.as_bytes(), role, &expected_kid).unwrap();
        assert_eq!(parsed.role(), role);
        assert_eq!(parsed.compact_bytes(), original.as_bytes());
        assert_eq!(
            parsed.signing_input(),
            original.rsplit_once('.').unwrap().0.as_bytes()
        );
        assert_eq!(
            parsed.signature().as_slice(),
            B64.decode(parts(name)[2].as_bytes()).unwrap()
        );
        let canonical = match parsed.payload() {
            UnverifiedPayload::Issuer(value) => {
                assert_eq!(name, "issuer");
                value.canonical_bytes()
            }
            UnverifiedPayload::Execution(value) => {
                assert_eq!(name, "execution");
                value.canonical_bytes()
            }
            UnverifiedPayload::EnrollmentPossession(value) => {
                assert_eq!(name, "possession");
                value.canonical_bytes()
            }
        };
        assert_eq!(
            canonical,
            f[name]["canonical_payload"].as_str().unwrap().as_bytes()
        );
    }
}

#[test]
fn signature_shape_is_not_cryptographic_verification() {
    for (role, name) in cases() {
        for signature in [[0; 64], [255; 64]] {
            let original = altered(name, 2, &signature);
            let parsed = UnverifiedCompact::parse(original.as_bytes(), role, &kid(name)).unwrap();
            assert_eq!(parsed.signature(), &signature);
            assert_eq!(parsed.compact_bytes(), original.as_bytes());
        }
        for length in [0, 1, 63, 65, 128] {
            reject(
                altered(name, 2, &vec![0; length]).as_bytes(),
                role,
                &kid(name),
            );
        }
    }
}

#[test]
fn expected_role_and_key_id_must_match_without_request_selected_fallback() {
    let f = fixture();
    for (role, name) in cases() {
        let original = f[name]["jws"].as_str().unwrap().as_bytes();
        for (wrong_role, wrong_name) in cases() {
            if wrong_name != name {
                reject(original, wrong_role, &kid(name));
            }
        }
        for bad in [
            "".into(),
            " ".into(),
            "A".repeat(32),
            "a".repeat(31),
            "a".repeat(44),
            "../key".into(),
            "DO_NOT_ECHO_THIS_SECRET".into(),
        ] {
            reject(original, role, &bad);
        }
        let wrong_valid = if name == "issuer" {
            "0".repeat(32)
        } else {
            B64.encode([0; 32])
        };
        reject(original, role, &wrong_valid);
    }
}

#[test]
fn possession_thumbprint_matches_header_but_issuer_key_id_is_not_issuer_identity() {
    let f = fixture();
    let mut possession = f["possession"]["payload"].clone();
    possession["agent_jkt"] = json!(B64.encode([0; 32]));
    reject(
        altered("possession", 1, &serde_jcs::to_vec(&possession).unwrap()).as_bytes(),
        CompactRole::EnrollmentPossession,
        &kid("possession"),
    );
    let different_kid = "0".repeat(32);
    let header = format!(
        "{{\"typ\":\"vollmacht-mandate+jws\",\"alg\":\"ES256\",\"kid\":\"{different_kid}\"}}"
    );
    let compact = altered("issuer", 0, header.as_bytes());
    // Issuer identity and key ID are distinct registry fields. This unsigned
    // syntax gate cannot resolve their trusted registry association.
    assert!(
        UnverifiedCompact::parse(compact.as_bytes(), CompactRole::Issuer, &different_kid).is_ok()
    );
}

#[test]
fn deterministic_header_rules_reject_semantic_equivalence_and_extensions() {
    let f = fixture();
    for (role, name) in cases() {
        let original = f[name]["header_bytes"].as_str().unwrap();
        let header: Value = serde_json::from_str(original).unwrap();
        let reordered = format!(
            "{{\"alg\":\"ES256\",\"typ\":{},\"kid\":{}}}",
            header["typ"], header["kid"]
        );
        let escaped = original.replace("\"typ\"", "\"\\u0074yp\"");
        let duplicate = original.replacen('{', "{\"alg\":\"ES256\",", 1);
        for bad in [
            reordered,
            escaped,
            duplicate,
            format!(" {original}"),
            serde_json::to_string_pretty(&header).unwrap(),
        ] {
            assert_ne!(bad, original);
            reject(
                altered(name, 0, bad.as_bytes()).as_bytes(),
                role,
                &kid(name),
            );
        }
        for (field, replacement) in [
            ("typ", json!("JWT")),
            ("alg", json!("none")),
            ("alg", json!("ES384")),
            ("kid", json!("unknown")),
            ("crit", json!(["unknown"])),
            ("b64", json!(false)),
            ("jwk", json!({})),
            ("jku", json!("https://example.invalid/key")),
        ] {
            let mut changed = header.clone();
            changed[field] = replacement;
            reject(
                altered(name, 0, &serde_json::to_vec(&changed).unwrap()).as_bytes(),
                role,
                &kid(name),
            );
        }
        for field in ["typ", "alg", "kid"] {
            let mut changed = header.clone();
            changed.as_object_mut().unwrap().remove(field);
            reject(
                altered(name, 0, &serde_json::to_vec(&changed).unwrap()).as_bytes(),
                role,
                &kid(name),
            );
        }
    }
}

#[test]
fn compact_framing_and_segment_encodings_are_exact() {
    for (role, name) in cases() {
        let original = parts(name).join(".");
        for bad in [
            "".into(),
            format!("{original}."),
            format!(".{original}"),
            format!(" {original}"),
            format!("{original}\n"),
            parts(name)[..2].join("."),
            original.replace('.', ".."),
        ] {
            reject(bad.as_bytes(), role, &kid(name));
        }
        for index in 0..3 {
            for replacement in [
                "".into(),
                format!("{}=", parts(name)[index]),
                "+/".into(),
                "AA AA".into(),
                "A".into(),
            ] {
                let mut changed = parts(name);
                changed[index] = replacement;
                reject(changed.join(".").as_bytes(), role, &kid(name));
            }
        }
        // 64-byte signature ends with four unused bits. Alias keeps decoded
        // bytes but sets an unused bit, so unpadded spelling is noncanonical.
        let mut changed = parts(name);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let signature = &mut changed[2];
        let last = alphabet
            .iter()
            .position(|c| *c == *signature.as_bytes().last().unwrap())
            .unwrap();
        assert_eq!(last % 16, 0);
        signature.pop();
        signature.push(char::from(alphabet[last + 1]));
        reject(changed.join(".").as_bytes(), role, &kid(name));
        let mut invalid_utf8 = original.into_bytes();
        invalid_utf8[0] = 255;
        reject(&invalid_utf8, role, &kid(name));
    }
}

#[test]
fn typed_payload_validation_and_canonicality_remain_required_inside_compact() {
    let f = fixture();
    for (role, name) in cases() {
        let source = &f[name]["payload"];
        let original = f[name]["canonical_payload"].as_str().unwrap();
        for bad in [
            format!(" {original}"),
            serde_json::to_string_pretty(source).unwrap(),
            original.replace("\"version\"", "\"\\u0076ersion\""),
        ] {
            reject(
                altered(name, 1, bad.as_bytes()).as_bytes(),
                role,
                &kid(name),
            );
        }
        let mut unknown = source.clone();
        unknown["unexpected"] = json!(1);
        reject(
            altered(name, 1, &serde_jcs::to_vec(&unknown).unwrap()).as_bytes(),
            role,
            &kid(name),
        );
        let mut profile = source.clone();
        if name == "issuer" {
            profile["payload"]["crypto_profile"] = json!("unknown");
        } else {
            profile["crypto_profile"] = json!("unknown");
        }
        reject(
            altered(name, 1, &serde_jcs::to_vec(&profile).unwrap()).as_bytes(),
            role,
            &kid(name),
        );
        for (_, other_name) in cases() {
            if name != other_name {
                reject(
                    altered(
                        name,
                        1,
                        f[other_name]["canonical_payload"]
                            .as_str()
                            .unwrap()
                            .as_bytes(),
                    )
                    .as_bytes(),
                    role,
                    &kid(name),
                );
            }
        }
    }
}

#[test]
fn total_and_decoded_segment_caps_reject_without_public_diagnostics() {
    for (role, name) in cases() {
        let limit = if name == "issuer" { 100_000 } else { 8_192 };
        for size in [limit, limit + 1] {
            reject(&vec![b'A'; size], role, &kid(name));
        }
        reject(
            altered(name, 0, &vec![b' '; 513]).as_bytes(),
            role,
            &kid(name),
        );
        let payload_limit = match name {
            "issuer" => 65_536,
            "execution" => 8_192,
            _ => 2_048,
        };
        reject(
            altered(name, 1, &vec![b' '; payload_limit + 1]).as_bytes(),
            role,
            &kid(name),
        );
    }
    let error = UnverifiedCompact::parse(
        b"DO_NOT_ECHO_THIS_SECRET",
        CompactRole::Issuer,
        &"a".repeat(32),
    )
    .unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
}
