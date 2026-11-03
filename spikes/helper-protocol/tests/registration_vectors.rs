//! Test-only proposal model. No implemented v2 codec or registration verifier.
#[path = "support/client_data.rs"]
mod client_data;
#[path = "../src/json.rs"]
mod strict_json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use vollmacht_helper_probe::{Error, FrameDecoder, MAX_BODY, Request, decode_response, frame};

type ModelResult<T> = Result<T, Error>;
const PROFILE: &str = "vollmacht-local-es256-v1";

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../registration-vectors.json")).unwrap()
}
fn body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn exact(value: &Value, fields: &[&str]) -> ModelResult<()> {
    let object = value.as_object().ok_or(Error::Protocol)?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(Error::Protocol);
    }
    Ok(())
}
fn literal(value: &Value, expected: &str) -> ModelResult<()> {
    if value.as_str() != Some(expected) {
        return Err(Error::Protocol);
    }
    Ok(())
}
fn binary(value: &Value, min: usize, max: usize) -> ModelResult<Vec<u8>> {
    let text = value.as_str().ok_or(Error::Protocol)?;
    // Bound encoded input before allocating decoded bytes. Ceiling(8n/6).
    if text.len() < (min * 8).div_ceil(6) || text.len() > (max * 8).div_ceil(6) {
        return Err(Error::Protocol);
    }
    let bytes = B64.decode(text).map_err(|_| Error::Protocol)?;
    if !(min..=max).contains(&bytes.len()) || B64.encode(&bytes) != text {
        return Err(Error::Protocol);
    }
    Ok(bytes)
}
fn common(value: &Value, kind: &str) -> ModelResult<()> {
    if value["version"].as_u64() != Some(2) {
        return Err(Error::Protocol);
    }
    literal(&value["kind"], kind)?;
    literal(&value["crypto_profile"], PROFILE)?;
    let id = value["request_id"].as_str().ok_or(Error::Protocol)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Protocol);
    }
    binary(&value["challenge"], 32, 32)?;
    Ok(())
}
fn request(bytes: &[u8]) -> ModelResult<Value> {
    let value = strict_json::parse(bytes)?;
    exact(
        &value,
        &[
            "version",
            "kind",
            "request_id",
            "crypto_profile",
            "challenge",
            "rp_id",
            "origin",
            "registration",
        ],
    )?;
    common(&value, "verify_registration")?;
    literal(&value["rp_id"], "localhost")?;
    literal(&value["origin"], "http://localhost:8374")?;
    let registration = &value["registration"];
    exact(
        registration,
        &[
            "id",
            "raw_id",
            "type",
            "client_data_json",
            "attestation_object",
        ],
    )?;
    binary(&registration["id"], 1, 1024)?;
    binary(&registration["raw_id"], 1, 1024)?;
    literal(&registration["type"], "public-key")?;
    binary(&registration["client_data_json"], 1, 12288)?;
    binary(&registration["attestation_object"], 1, 16384)?;
    Ok(value)
}
// Only two proposed preconditions. Ok does not mean WebAuthn verification.
fn syntax_and_browser_ids(value: &Value) -> ModelResult<()> {
    let registration = &value["registration"];
    if binary(&registration["id"], 1, 1024)? != binary(&registration["raw_id"], 1, 1024)? {
        return Err(Error::VerificationRejected);
    }
    let raw = binary(&registration["client_data_json"], 1, 12288)?;
    client_data::validate(&raw).map_err(|_| Error::VerificationRejected)
}
// Ok(true) means a success-shaped correlated synthetic message, never authority.
fn response(bytes: &[u8], expected: &Value) -> ModelResult<bool> {
    let value = strict_json::parse(bytes)?;
    common(&value, "registration_result")?;
    for field in ["request_id", "crypto_profile", "challenge"] {
        if value[field] != expected[field] {
            return Err(Error::Protocol);
        }
    }
    match value["outcome"].as_str() {
        Some("rejected") => {
            exact(
                &value,
                &[
                    "version",
                    "kind",
                    "request_id",
                    "crypto_profile",
                    "challenge",
                    "outcome",
                    "code",
                ],
            )?;
            literal(&value["code"], "verification_rejected")?;
            Ok(false)
        }
        Some("verified") => {
            exact(
                &value,
                &[
                    "version",
                    "kind",
                    "request_id",
                    "crypto_profile",
                    "challenge",
                    "outcome",
                    "credential",
                ],
            )?;
            let credential = &value["credential"];
            exact(
                credential,
                &[
                    "id",
                    "public_key",
                    "counter",
                    "backup_eligible",
                    "backed_up",
                ],
            )?;
            let id = binary(&credential["id"], 1, 1024)?;
            binary(&credential["public_key"], 1, 4096)?;
            let counter = credential["counter"].as_u64().ok_or(Error::Protocol)?;
            let eligible = credential["backup_eligible"]
                .as_bool()
                .ok_or(Error::Protocol)?;
            let backed = credential["backed_up"].as_bool().ok_or(Error::Protocol)?;
            if counter > u64::from(u32::MAX)
                || (backed && !eligible)
                || id != binary(&expected["registration"]["id"], 1, 1024)?
                || id != binary(&expected["registration"]["raw_id"], 1, 1024)?
            {
                return Err(Error::Protocol);
            }
            Ok(true)
        }
        _ => Err(Error::Protocol),
    }
}

#[test]
fn synthetic_shapes_roundtrip_without_claiming_verification() {
    let f = fixtures();
    let expected = request(&body(&f["request"])).unwrap();
    assert!(syntax_and_browser_ids(&expected).is_ok()); // {} is syntax, not valid client data.
    for (name, outcome) in [("success", true), ("rejection", false)] {
        let encoded = frame(&body(&f[name])).unwrap();
        for chunk in [1, 3, encoded.len()] {
            let mut decoder = FrameDecoder::default();
            for part in encoded.chunks(chunk) {
                decoder.feed(part).unwrap();
            }
            assert_eq!(response(&decoder.finish().unwrap(), &expected), Ok(outcome));
        }
    }
    assert!(Request::parse(&body(&f["request"])).is_err());
    let mut v1 = f["request"].clone();
    v1["version"] = json!(1);
    assert!(request(&body(&v1)).is_err());
    assert!(Request::parse(&body(&v1)).is_err());
    let old: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
    assert!(response(&body(&old["rejection_response"]), &expected).is_err());
    let mut assertion = json!({
        "version": 1, "kind": "verify_assertion",
        "request_id": f["request"]["request_id"], "challenge": B64.encode([0; 32]),
        "rp_id": "localhost", "origin": "http://localhost:8374",
        "credential": {"id": "AA", "public_key": "AA", "counter": 0,
            "user_handle": "AA", "backup_eligible": false},
        "assertion": {"id": "AA", "raw_id": "AA", "type": "public-key",
            "client_data_json": "e30", "authenticator_data": B64.encode([0; 37]),
            "signature": "AA", "user_handle": ""}
    });
    let v1_request = Request::parse(&body(&assertion)).unwrap();
    for version in [1, 2] {
        assertion["version"] = json!(version);
        assert!(request(&body(&assertion)).is_err());
    }
    for name in ["success", "rejection"] {
        assert!(decode_response(&body(&f[name]), &v1_request).is_err());
    }
}

#[test]
fn every_required_field_rejects_missing_unknown_null_and_wrong_type() {
    let f = fixtures();
    for (name, pointers) in [
        ("request", vec!["", "/registration"]),
        ("success", vec!["", "/credential"]),
        ("rejection", vec![""]),
    ] {
        let check = |value: &Value| {
            if name == "request" {
                request(&body(value)).is_ok()
            } else {
                response(&body(value), &f["request"]).is_ok()
            }
        };
        for pointer in pointers {
            let original = &f[name];
            for field in original
                .pointer(pointer)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
            {
                let mut missing = original.clone();
                missing
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert!(!check(&missing), "missing {name}{pointer}/{field}");
                for wrong in [Value::Null, json!([]), json!({})] {
                    let mut changed = original.clone();
                    changed.pointer_mut(pointer).unwrap()[field] = wrong;
                    assert!(!check(&changed), "wrong {name}{pointer}/{field}");
                }
            }
            let mut extra = original.clone();
            extra.pointer_mut(pointer).unwrap()["extra"] = json!(true);
            assert!(!check(&extra));
        }
    }
}

#[test]
fn duplicates_and_integer_lexemes_reject_before_normalization() {
    let f = fixtures();
    for name in ["request", "success", "rejection"] {
        let source = serde_json::to_string(&f[name]).unwrap();
        for duplicate in [
            r#""version":2,"version":2"#,
            r#""version":2,"\u0076ersion":2"#,
        ] {
            let changed = source.replace(r#""version":2"#, duplicate);
            assert!(strict_json::parse(changed.as_bytes()).is_err());
        }
        for number in ["-0", "2.0", "2e0", "02"] {
            let changed = source.replace(r#""version":2"#, &format!("\"version\":{number}"));
            assert!(strict_json::parse(changed.as_bytes()).is_err());
        }
    }
    for (name, member) in [
        ("request", r#""raw_id":"AA""#),
        ("success", r#""counter":0"#),
    ] {
        let source = serde_json::to_string(&f[name]).unwrap();
        let changed = source.replace(member, &format!("{member},{member}"));
        assert!(strict_json::parse(changed.as_bytes()).is_err());
    }
    for number in ["-0", "0.0", "0e0", "4294967296", "18446744073709551616"] {
        let source = serde_json::to_string(&f["success"])
            .unwrap()
            .replace(r#""counter":0"#, &format!("\"counter\":{number}"));
        assert!(response(source.as_bytes(), &f["request"]).is_err());
    }
}

#[test]
fn literals_correlation_ids_and_result_alternatives_are_bound() {
    let f = fixtures();
    for (pointer, wrong) in [
        ("/rp_id", "example.com"),
        ("/origin", "http://127.0.0.1:8374"),
        ("/registration/type", "other"),
    ] {
        let mut changed = f["request"].clone();
        *changed.pointer_mut(pointer).unwrap() = json!(wrong);
        assert!(request(&body(&changed)).is_err());
    }
    let mut rejection = f["rejection"].clone();
    rejection["code"] = json!("library diagnostic");
    assert!(response(&body(&rejection), &f["request"]).is_err());
    for name in ["request", "success", "rejection"] {
        for (field, wrong) in [
            ("version", json!(1)),
            ("kind", json!("verify_assertion")),
            ("crypto_profile", json!("unknown")),
            ("request_id", json!("000102030405060708090A0B0C0D0E0F")),
        ] {
            let mut changed = f[name].clone();
            changed[field] = wrong;
            assert!(if name == "request" {
                request(&body(&changed)).is_err()
            } else {
                response(&body(&changed), &f["request"]).is_err()
            });
        }
    }
    for name in ["success", "rejection"] {
        for (field, wrong) in [
            ("request_id", json!("ffffffffffffffffffffffffffffffff")),
            ("challenge", json!(B64.encode([1; 32]))),
            ("outcome", json!("success")),
        ] {
            let mut changed = f[name].clone();
            changed[field] = wrong;
            assert!(response(&body(&changed), &f["request"]).is_err());
        }
    }
    let mut mixed = f["success"].clone();
    mixed["code"] = json!("verification_rejected");
    assert!(response(&body(&mixed), &f["request"]).is_err());
    mixed = f["rejection"].clone();
    mixed["credential"] = f["success"]["credential"].clone();
    assert!(response(&body(&mixed), &f["request"]).is_err());
    for id_field in ["id", "raw_id"] {
        let mut changed = f["request"].clone();
        changed["registration"][id_field] = json!("AQ");
        let parsed = request(&body(&changed)).unwrap();
        assert_eq!(
            syntax_and_browser_ids(&parsed),
            Err(Error::VerificationRejected)
        );
        assert!(response(&body(&f["success"]), &parsed).is_err());
    }
    let mut changed = f["success"].clone();
    changed["credential"]["id"] = json!("AQ");
    assert!(response(&body(&changed), &f["request"]).is_err());
    for eligible in [false, true] {
        for backed in [false, true] {
            let mut changed = f["success"].clone();
            changed["credential"]["backup_eligible"] = json!(eligible);
            changed["credential"]["backed_up"] = json!(backed);
            changed["credential"]["counter"] = json!(u32::MAX);
            assert_eq!(
                response(&body(&changed), &f["request"]).is_ok(),
                !backed || eligible
            );
        }
    }
}

#[test]
fn binary_field_boundaries_and_noncanonical_encodings() {
    let f = fixtures();
    for (name, pointer, min, max) in [
        ("request", "/challenge", 32, 32),
        ("request", "/registration/id", 1, 1024),
        ("request", "/registration/raw_id", 1, 1024),
        ("request", "/registration/client_data_json", 1, 12288),
        ("request", "/registration/attestation_object", 1, 16384),
        ("success", "/credential/public_key", 1, 4096),
        ("success", "/credential/id", 1, 1024),
    ] {
        for size in [min - 1, min, max, max + 1] {
            let encoded = B64.encode(vec![0; size]);
            assert_eq!(encoded.len(), (size * 8).div_ceil(6));
            let mut changed = f[name].clone();
            *changed.pointer_mut(pointer).unwrap() = json!(encoded);
            let mut expected = f["request"].clone();
            if pointer == "/credential/id" {
                expected["registration"]["id"] = changed["credential"]["id"].clone();
                expected["registration"]["raw_id"] = changed["credential"]["id"].clone();
            }
            let accepted = if name == "request" {
                request(&body(&changed)).is_ok()
            } else {
                response(&body(&changed), &expected).is_ok()
            };
            assert_eq!(accepted, (min..=max).contains(&size), "{pointer}: {size}");
        }
        for bad in ["A", "AA=", "AA==", "AB", "+A", "/A", "A A", "é"] {
            let mut changed = f[name].clone();
            *changed.pointer_mut(pointer).unwrap() = json!(bad);
            assert!(if name == "request" {
                request(&body(&changed)).is_err()
            } else {
                response(&body(&changed), &f["request"]).is_err()
            });
        }
    }
}

#[test]
fn original_bytes_and_full_frame_limit_survive_model_processing() {
    let f = fixtures();
    let raw = b" { \"type\" : \"webauthn.create\", \"unknown\" : \"\\u0061\" }\n";
    let attestation = [0, 255, 2, 128, 0]; // Opaque invalid evidence, not CBOR validation.
    let mut changed = f["request"].clone();
    changed["registration"]["client_data_json"] = json!(B64.encode(raw));
    changed["registration"]["attestation_object"] = json!(B64.encode(attestation));
    let parsed = request(&body(&changed)).unwrap();
    assert!(syntax_and_browser_ids(&parsed).is_ok());
    assert_eq!(
        binary(&parsed["registration"]["client_data_json"], 1, 12288).unwrap(),
        raw
    );
    assert_eq!(
        binary(&parsed["registration"]["attestation_object"], 1, 16384).unwrap(),
        attestation
    );
    for invalid in [
        b"{\"x\":1,\"x\":2}".as_slice(),
        b"{}{}",
        b"\xef\xbb\xbf{}",
        b"\xff",
    ] {
        changed["registration"]["client_data_json"] = json!(B64.encode(invalid));
        let parsed = request(&body(&changed)).unwrap();
        assert_eq!(
            syntax_and_browser_ids(&parsed),
            Err(Error::VerificationRejected)
        );
    }
    let mut largest = f["request"].clone();
    for (field, size) in [
        ("id", 1024),
        ("raw_id", 1024),
        ("client_data_json", 12288),
        ("attestation_object", 16384),
    ] {
        largest["registration"][field] = json!(B64.encode(vec![0; size]));
    }
    let mut bytes = body(&largest);
    assert!(bytes.len() < MAX_BODY);
    bytes.resize(MAX_BODY, b' ');
    assert!(request(&bytes).is_ok());
    let framed = frame(&bytes).unwrap();
    let mut decoder = FrameDecoder::default();
    decoder.feed(&framed).unwrap();
    assert_eq!(decoder.finish().unwrap(), bytes);
    bytes.push(b' ');
    assert!(request(&bytes).is_err());
    assert!(frame(&bytes).is_err());
    let mut decoder = FrameDecoder::default();
    decoder.feed(&framed).unwrap();
    assert!(decoder.feed(&framed).is_err());
    assert!(decoder.finish().is_err());
}
