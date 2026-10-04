//! Structural candidate only: no library verification, policy or signature check.
#[path = "support/client_data.rs"]
mod candidate;

use candidate::{MAX_BYTES, MAX_DEPTH, Rejected, validate};

#[test]
fn shared_unsigned_corpus_matches_candidate_gate() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;
    use std::collections::BTreeSet;

    let corpus: Value = serde_json::from_str(include_str!(
        "../../simplewebauthn/client-data-vectors.json"
    ))
    .unwrap();
    assert_eq!(corpus["profile"], "candidate-client-data-syntax-v1");
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 24);
    let mut ids = BTreeSet::new();
    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        assert!(
            !id.is_empty() && ids.insert(id),
            "unique nonempty vector ID"
        );
        let encoded = vector["raw_base64url"].as_str().unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&bytes), encoded, "{id}");
        let expected = match vector["expected_gate"].as_str().unwrap() {
            "accept" => Ok(()),
            "reject" => Err(Rejected),
            other => panic!("unknown expected gate {other}"),
        };
        assert_eq!(validate(&bytes), expected, "{id}");
    }
}

#[test]
fn root_must_be_one_complete_object() {
    for input in [
        "",
        " ",
        "null",
        "true",
        "1",
        "\"text\"",
        "[]",
        "{}{}",
        "{} trailing",
    ] {
        assert_eq!(validate(input.as_bytes()), Err(Rejected), "{input:?}");
    }
    for input in ["{}", " \r\n\t{} \n", "{\"unknown\":null}"] {
        assert_eq!(validate(input.as_bytes()), Ok(()));
    }
}

#[test]
fn supported_unknown_field_types_are_not_an_ipc_profile() {
    let input =
        r#"{"日本語":{"emoji":"😀","array":[null,true,false,-1,0,1.25,1e3,{},[]]},"other":[]}"#;
    assert_eq!(validate(input.as_bytes()), Ok(()));
    assert_eq!(validate(br#"{"x":[[[]],{"nested":[null]}]}"#), Ok(()));
}

#[test]
fn unknown_members_are_not_security_semantics() {
    // Structural validity does not mean any field is a valid WebAuthn claim.
    for input in [
        r#"{}"#,
        r#"{"type":null,"challenge":7,"origin":false}"#,
        r#"{"crossOrigin":true}"#,
    ] {
        assert_eq!(validate(input.as_bytes()), Ok(()));
    }
}

#[test]
fn duplicates_use_decoded_names_at_every_depth() {
    for duplicate in [
        r#"{"challenge":1,"challenge":2}"#,
        r#"{"challenge":1,"\u0063hallenge":2}"#,
        r#"{"😀":1,"\ud83d\ude00":2}"#,
        r#"{"":1,"":2}"#,
        r#"{"__proto__":1,"__proto__":2}"#,
    ] {
        assert_eq!(validate(duplicate.as_bytes()), Err(Rejected));
        assert_eq!(
            validate(format!("{{\"x\":[{duplicate}]}}").as_bytes()),
            Err(Rejected)
        );
        for containers in 1..MAX_DEPTH {
            let nested = format!(
                "{}{}{}",
                "{\"x\":".repeat(containers),
                duplicate,
                "}".repeat(containers)
            );
            assert_eq!(validate(nested.as_bytes()), Err(Rejected));
        }
    }
}

#[test]
fn equal_names_in_different_objects_are_allowed_without_unicode_normalization() {
    assert_eq!(
        validate(br#"{"left":{"x":1},"right":{"x":2},"x":3}"#),
        Ok(())
    );
    assert_eq!(validate("{\"é\":1,\"e\\u0301\":2}".as_bytes()), Ok(()));
    assert_eq!(
        validate(br#"{"__proto__":{},"constructor":[],"prototype":null}"#),
        Ok(())
    );
}

#[test]
fn unicode_scalar_values_and_valid_surrogate_pairs_are_allowed() {
    for input in [
        r#"{"x":"\ud83d\ude00"}"#,
        r#"{"\ud83d\ude00":"😀"}"#,
        r#"{"x":"\u0000\ufeff"}"#,
    ] {
        assert_eq!(validate(input.as_bytes()), Ok(()));
    }
}

#[test]
fn unpaired_surrogates_invalid_escapes_and_raw_controls_are_rejected() {
    for input in [
        r#"{"x":"\ud800"}"#,
        r#"{"x":"\udc00"}"#,
        r#"{"x":"\ud800a"}"#,
        r#"{"x":"\ud800\ud800"}"#,
        r#"{"\ud800":1}"#,
        r#"{"x":"\x20"}"#,
        r#"{"x":"\u12"}"#,
        "{\"x\":\"\n\"}",
        "{\"x\":\"\0\"}",
    ] {
        assert_eq!(validate(input.as_bytes()), Err(Rejected), "{input:?}");
    }
}

#[test]
fn utf8_errors_and_bom_are_rejected_before_json_interpretation() {
    for invalid in [
        &[0xff][..],
        &[0xc0, 0xaf],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xe2, 0x82],
    ] {
        let bytes = [b"{\"x\":\"".as_slice(), invalid, b"\"}"].concat();
        assert_eq!(validate(&bytes), Err(Rejected));
    }
    for prefix in [b"\xef\xbb\xbf".as_slice(), b" \xef\xbb\xbf"] {
        assert_eq!(validate(&[prefix, b"{}"].concat()), Err(Rejected));
    }
}

#[test]
fn container_depth_counts_objects_and_arrays_including_root() {
    for depth in 1..=MAX_DEPTH + 2 {
        let objects = format!("{}0{}", "{\"x\":".repeat(depth), "}".repeat(depth));
        assert_eq!(validate(objects.as_bytes()).is_ok(), depth <= MAX_DEPTH);
        let arrays = format!(
            "{{\"x\":{}0{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert_eq!(validate(arrays.as_bytes()).is_ok(), depth <= MAX_DEPTH);
    }
    let deepest_empty = format!(
        "{{\"x\":{}{}}}",
        "[".repeat(MAX_DEPTH - 1),
        "]".repeat(MAX_DEPTH - 1)
    );
    assert_eq!(validate(deepest_empty.as_bytes()), Ok(()));
}

#[test]
fn byte_bound_includes_whitespace_and_multibyte_text() {
    for length in [MAX_BYTES - 1, MAX_BYTES, MAX_BYTES + 1] {
        let body = format!("{{\"x\":\"{}\"}}", "a".repeat(length - 8));
        assert_eq!(body.len(), length);
        assert_eq!(validate(body.as_bytes()).is_ok(), length <= MAX_BYTES);
    }
    let boundary = format!("{{\"x\":\"{}\"}}", "é".repeat((MAX_BYTES - 8) / 2));
    assert_eq!(boundary.len(), MAX_BYTES);
    assert_eq!(validate(boundary.as_bytes()), Ok(()));
    assert_eq!(validate(format!("{boundary} ").as_bytes()), Err(Rejected));
}

#[test]
fn signed_fraction_exponent_and_negative_zero_are_permitted() {
    for number in [
        "-1",
        "-0",
        "-0.0",
        "1.0",
        "1e0",
        "1E+2",
        "1e-2",
        "9007199254740993",
        "18446744073709551615",
        "1e308",
    ] {
        assert_eq!(
            validate(format!("{{\"unknown\":{number}}}").as_bytes()),
            Ok(()),
            "{number}"
        );
    }
    // No integer-exactness claim or numeric interpretation escapes this validator.
}

#[test]
fn unsupported_numeric_range_and_malformed_numbers_are_rejected() {
    for number in [
        "1e400", "-1e400", "NaN", "Infinity", "+1", "01", "1.", ".1", "1e",
    ] {
        assert_eq!(
            validate(format!("{{\"unknown\":{number}}}").as_bytes()),
            Err(Rejected),
            "{number}"
        );
    }
}

#[test]
fn malformed_containers_and_trailing_data_fail_closed() {
    for input in [
        "{",
        "{]",
        "{\"x\":}",
        "{\"x\":1,}",
        "{\"x\":[1,]}",
        "{\"x\":[}",
        "{/*comment*/}",
        "{}\0",
    ] {
        assert_eq!(validate(input.as_bytes()), Err(Rejected), "{input:?}");
    }
}

#[test]
fn valid_bytes_are_preserved_without_reserialization() {
    for bytes in [
        b"{\"origin\":\"http:\\/\\/localhost:8374\"}".as_slice(),
        b"{\n \"z\": -0, \"a\": 1e0\n}\n",
    ] {
        let original = bytes.to_vec();
        assert_eq!(validate(bytes), Ok(()));
        assert_eq!(bytes, original);
    }
}
