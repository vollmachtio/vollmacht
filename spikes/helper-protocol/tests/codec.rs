use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use vollmacht_helper_probe::{
    Error, FrameDecoder, MAX_BODY, Request, decode_response, frame, rejection_frame,
};

fn b64(size: usize) -> String {
    URL_SAFE_NO_PAD.encode(vec![0; size])
}

// Deliberately not a valid COSE key or assertion; exercises transport only.
fn fixture() -> Value {
    json!({
        "version": 1, "kind": "verify_assertion",
        "request_id": "000102030405060708090a0b0c0d0e0f", "challenge": b64(32),
        "rp_id": "localhost", "origin": "http://localhost:8374",
        "credential": {"id": "AA", "public_key": "AA", "counter": 0,
            "user_handle": "AA", "backup_eligible": false},
        "assertion": {"id": "AA", "raw_id": "AA", "type": "public-key",
            "client_data_json": "AA", "authenticator_data": b64(37),
            "signature": "AA", "user_handle": ""}
    })
}

fn parse(value: &Value) -> Result<Request, Error> {
    Request::parse(&serde_json::to_vec(value).unwrap())
}

fn success() -> Value {
    json!({"version": 1, "kind": "verification_result",
        "request_id": "000102030405060708090a0b0c0d0e0f", "challenge": b64(32),
        "outcome": "verified", "new_counter": 0, "backup_eligible": false, "backed_up": false})
}

fn response(
    value: &Value,
    request: &Request,
) -> Result<vollmacht_helper_probe::HelperResult, Error> {
    decode_response(&serde_json::to_vec(value).unwrap(), request)
}

fn unframe(bytes: &[u8], chunk: usize) -> Result<Vec<u8>, Error> {
    let mut decoder = FrameDecoder::default();
    for part in bytes.chunks(chunk) {
        decoder.feed(part)?;
    }
    decoder.finish()
}

#[test]
fn fake_helper_roundtrip_matches_spec_vector() {
    let request = parse(&fixture()).unwrap();
    let received = unframe(&request.to_frame().unwrap(), 1).unwrap();
    let fake_received = Request::parse(&received).unwrap();
    let reply = rejection_frame(&fake_received).unwrap();
    let bytes = unframe(&reply, 3).unwrap();
    let vectors: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        vectors["rejection_response"]
    );
    assert_eq!(
        decode_response(&bytes, &request),
        Err(Error::VerificationRejected)
    );
}

#[test]
fn every_frame_split_and_chunk_size() {
    let bytes = frame(b"{\"hello\":true}").unwrap();
    for split in 0..=bytes.len() {
        let mut decoder = FrameDecoder::default();
        decoder.feed(&bytes[..split]).unwrap();
        decoder.feed(&bytes[split..]).unwrap();
        assert_eq!(decoder.finish().unwrap(), b"{\"hello\":true}");
    }
    for chunk in 1..=bytes.len() {
        assert_eq!(unframe(&bytes, chunk).unwrap(), b"{\"hello\":true}");
    }
}

#[test]
fn frames_bound_length_and_require_exact_eof() {
    assert_eq!(frame(b""), Err(Error::Protocol));
    assert_eq!(frame(&vec![0; MAX_BODY + 1]), Err(Error::Protocol));
    for length in [0_u32, 65_537, u32::MAX] {
        let mut decoder = FrameDecoder::default();
        assert_eq!(decoder.feed(&length.to_be_bytes()), Err(Error::Protocol));
        assert_eq!(decoder.feed(&[]), Err(Error::Protocol));
        assert_eq!(decoder.finish(), Err(Error::Protocol));
    }
    let bytes = frame(b"{}").unwrap();
    assert_eq!(&bytes[..4], &[0, 0, 0, 2]);
    for truncated in 0..bytes.len() {
        assert_eq!(unframe(&bytes[..truncated], 1), Err(Error::Protocol));
    }
    for suffix in [vec![0], bytes.clone()] {
        let mut decoder = FrameDecoder::default();
        decoder.feed(&bytes).unwrap();
        assert_eq!(decoder.feed(&suffix), Err(Error::Protocol));
        assert_eq!(decoder.finish(), Err(Error::Protocol));
        assert_eq!(
            unframe(&[bytes.clone(), suffix].concat(), 100),
            Err(Error::Protocol)
        );
    }
    let large = vec![b' '; MAX_BODY];
    assert_eq!(unframe(&frame(&large).unwrap(), 17).unwrap(), large);
}

#[test]
fn schema_rejects_missing_unknown_null_and_wrong_type_at_each_object() {
    for pointer in ["", "/credential", "/assertion"] {
        let original = fixture();
        let keys: Vec<_> = original
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut missing = original.clone();
            missing
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(parse(&missing).is_err(), "missing {pointer}/{key}");
            for replacement in [Value::Null, json!([]), json!({})] {
                let mut wrong = original.clone();
                wrong.pointer_mut(pointer).unwrap()[&key] = replacement;
                assert!(parse(&wrong).is_err(), "wrong {pointer}/{key}");
            }
        }
        let mut extra = original;
        extra.pointer_mut(pointer).unwrap()["extra"] = json!(true);
        assert!(parse(&extra).is_err());
    }
}

#[test]
fn integer_lexemes_cannot_be_normalized_before_validation() {
    let original = serde_json::to_string(&fixture()).unwrap();
    for token in [
        "-0",
        "-1",
        "0.0",
        "0e0",
        "00",
        "4294967296",
        "18446744073709551616",
    ] {
        let mutated = original.replace("\"counter\":0", &format!("\"counter\":{token}"));
        assert!(Request::parse(mutated.as_bytes()).is_err(), "{token}");
    }
    let mut max = fixture();
    max["credential"]["counter"] = json!(u32::MAX);
    assert!(parse(&max).is_ok());
}

#[test]
fn duplicate_keys_in_request_and_response_rejected_before_tag_dispatch() {
    let source = serde_json::to_string(&fixture()).unwrap();
    for (old, new) in [
        ("\"version\":1", "\"version\":1,\"version\":1"),
        ("\"counter\":0", "\"counter\":0,\"counter\":0"),
        (
            "\"signature\":\"AA\"",
            "\"signature\":\"AA\",\"signature\":\"AA\"",
        ),
    ] {
        assert!(Request::parse(source.replace(old, new).as_bytes()).is_err());
    }
    let request = parse(&fixture()).unwrap();
    let source = serde_json::to_string(&success()).unwrap();
    for (key, value) in [("outcome", "\"verified\""), ("new_counter", "0")] {
        let needle = format!("\"{key}\":{value}");
        let body = source.replace(&needle, &format!("{needle},{needle}"));
        assert_eq!(
            decode_response(body.as_bytes(), &request),
            Err(Error::Protocol)
        );
    }
}

#[test]
fn binary_fields_enforce_canonical_encoding_and_each_boundary() {
    let fields = [
        ("/challenge", 32, 32),
        ("/credential/id", 1, 1024),
        ("/credential/public_key", 1, 4096),
        ("/credential/user_handle", 1, 64),
        ("/assertion/id", 1, 1024),
        ("/assertion/raw_id", 1, 1024),
        ("/assertion/client_data_json", 1, 12288),
        ("/assertion/authenticator_data", 37, 8192),
        ("/assertion/signature", 1, 1024),
        ("/assertion/user_handle", 0, 64),
    ];
    let mut largest = fixture();
    for (pointer, min, max) in fields {
        for size in [min, max] {
            let mut valid = fixture();
            *valid.pointer_mut(pointer).unwrap() = json!(b64(size));
            assert!(parse(&valid).is_ok(), "{pointer} {size}");
        }
        *largest.pointer_mut(pointer).unwrap() = json!(b64(max));
        let mut too_large = fixture();
        *too_large.pointer_mut(pointer).unwrap() = json!(b64(max + 1));
        assert!(parse(&too_large).is_err());
        if min > 0 {
            let mut short = fixture();
            *short.pointer_mut(pointer).unwrap() = json!(b64(min - 1));
            assert!(parse(&short).is_err());
        }
        for invalid in ["A", "AA=", "AA==", "AB", "+A", "/A", "A A", "é"] {
            let mut bad = fixture();
            *bad.pointer_mut(pointer).unwrap() = json!(invalid);
            assert!(parse(&bad).is_err(), "{pointer} {invalid}");
        }
    }
    assert!(parse(&largest).unwrap().to_frame().unwrap().len() <= MAX_BODY + 4);
}

#[test]
fn request_literals_and_identifiers_are_exact() {
    for (pointer, replacement) in [
        ("/version", json!(2)),
        ("/version", json!("1")),
        ("/kind", json!("register")),
        ("/rp_id", json!("example.com")),
        ("/origin", json!("http://127.0.0.1:8374")),
        ("/assertion/type", json!("other")),
        ("/request_id", json!("000102030405060708090A0B0C0D0E0F")),
        ("/request_id", json!("000102030405060708090a0b0c0d0e0")),
    ] {
        let mut bad = fixture();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(parse(&bad).is_err(), "{pointer}");
    }
}

#[test]
fn raw_signed_fields_survive_roundtrip_unchanged() {
    let mut value = fixture();
    let raw = b"{ \"challenge\" : \"opaque\" }\n";
    value["assertion"]["client_data_json"] = json!(URL_SAFE_NO_PAD.encode(raw));
    let request = parse(&value).unwrap();
    let encoded = unframe(&request.to_frame().unwrap(), 9).unwrap();
    let decoded: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn response_requires_exact_schema_correlation_and_tag() {
    let request = parse(&fixture()).unwrap();
    let good = success();
    assert!(response(&good, &request).is_ok());
    for key in good.as_object().unwrap().keys() {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert_eq!(response(&missing, &request), Err(Error::Protocol));
    }
    for (key, value) in [
        ("version", json!(2)),
        ("kind", json!("verify_assertion")),
        ("request_id", json!("ffffffffffffffffffffffffffffffff")),
        ("challenge", json!(URL_SAFE_NO_PAD.encode([1; 32]))),
        ("outcome", json!("success")),
        ("code", json!("verification_rejected")),
        ("new_counter", json!(4294967296_u64)),
        ("new_counter", json!(1.0)),
        ("backed_up", Value::Null),
        ("extra", json!(true)),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert_eq!(response(&bad, &request), Err(Error::Protocol), "{key}");
    }
    let bytes = unframe(&rejection_frame(&request).unwrap(), 3).unwrap();
    let rejected: Value = serde_json::from_slice(&bytes).unwrap();
    for key in rejected.as_object().unwrap().keys() {
        let mut missing = rejected.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert_eq!(response(&missing, &request), Err(Error::Protocol));
    }
    let mut bad = rejected.clone();
    bad["new_counter"] = json!(0);
    assert_eq!(response(&bad, &request), Err(Error::Protocol));
    let mut bad = rejected;
    bad["code"] = json!("arbitrary library error");
    assert_eq!(response(&bad, &request), Err(Error::Protocol));
}

#[test]
fn counter_and_backup_checks_are_not_crypto_verification() {
    for (old, new, allowed) in [
        (0, 0, true),
        (0, 1, true),
        (1, 2, true),
        (1, 1, false),
        (1, 0, false),
        (u32::MAX, u32::MAX, false),
    ] {
        let mut input = fixture();
        input["credential"]["counter"] = json!(old);
        let request = parse(&input).unwrap();
        let mut reply = success();
        reply["new_counter"] = json!(new);
        assert_eq!(response(&reply, &request).is_ok(), allowed);
    }
    for stored in [false, true] {
        for eligible in [false, true] {
            for backed in [false, true] {
                let mut input = fixture();
                input["credential"]["backup_eligible"] = json!(stored);
                let request = parse(&input).unwrap();
                let mut reply = success();
                reply["backup_eligible"] = json!(eligible);
                reply["backed_up"] = json!(backed);
                assert_eq!(
                    response(&reply, &request).is_ok(),
                    stored == eligible && (!backed || eligible)
                );
            }
        }
    }
}

#[test]
fn invalid_vector_bodies_rejected() {
    let vectors: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
    let request = parse(&fixture()).unwrap();
    for vector in vectors["invalid_json_bodies"].as_array().unwrap() {
        let body = vector["body_utf8"].as_str().unwrap().as_bytes();
        assert!(Request::parse(body).is_err());
        assert_eq!(decode_response(body, &request), Err(Error::Protocol));
    }
}
