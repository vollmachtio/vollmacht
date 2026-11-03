use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeSet;
use vollmacht_core::{ClientDataError, SyntaxCheckedClientData};

fn accepts(bytes: &[u8]) -> bool {
    SyntaxCheckedClientData::parse(bytes).is_ok()
}

#[test]
fn independent_shared_corpus_matches_frozen_syntax_policy() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spikes/simplewebauthn/client-data-vectors.json"
    ))
    .unwrap();
    assert_eq!(corpus["profile"], "candidate-client-data-syntax-v1");
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 24);
    let mut ids = BTreeSet::new();
    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        assert!(ids.insert(id));
        let encoded = vector["raw_base64url"].as_str().unwrap();
        let original = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&original), encoded);
        let expected = match vector["expected_gate"].as_str().unwrap() {
            "accept" => true,
            "reject" => false,
            _ => panic!("unknown oracle outcome"),
        };
        assert_eq!(accepts(&original), expected, "{id}");
    }
}

#[test]
fn returned_bytes_borrow_the_unchanged_signed_input() {
    let original = " \t{\"z\":-0.0,\"é\":\"\\ud83d\\ude00\",\"a\":[1E+2,null]}\r\n";
    let checked = SyntaxCheckedClientData::parse(original.as_bytes()).unwrap();
    assert_eq!(checked.original_bytes(), original.as_bytes());
    assert_eq!(checked.original_bytes().as_ptr(), original.as_ptr());
    assert_eq!(format!("{checked:?}"), "SyntaxCheckedClientData { .. }");
}

#[test]
fn syntax_success_makes_no_webauthn_claim() {
    for input in [
        "{}",
        r#"{"type":null,"challenge":7,"origin":false,"crossOrigin":true}"#,
        r#"{"unknown":[null,true,false,-1,1.25,{},[]]}"#,
        r#"{"__proto__":{},"constructor":[],"prototype":null}"#,
    ] {
        assert!(accepts(input.as_bytes()), "{input}");
    }
}

#[test]
fn exactly_one_object_is_required() {
    for input in [
        "",
        " ",
        "null",
        "true",
        "1",
        "\"text\"",
        "[]",
        "{}{}",
        "{}x",
        "{",
        "{]",
        "{\"a\":}",
        "{\"a\":1,}",
        "{\"a\":[1,]}",
        "{\"a\":[}",
    ] {
        assert!(!accepts(input.as_bytes()), "{input:?}");
    }
    assert!(accepts(b" \r\n\t{} \n"));
}

#[test]
fn duplicate_decoded_names_fail_at_every_container_depth() {
    for object in [
        r#"{"challenge":1,"\u0063hallenge":2}"#,
        r#"{"😀":1,"\ud83d\ude00":2}"#,
        r#"{"":1,"":2}"#,
        r#"{"x":{},"x":[]}"#,
    ] {
        for depth in 1..=16 {
            let wrapped = format!(
                "{}{}{}",
                "{\"nested\":".repeat(depth - 1),
                object,
                "}".repeat(depth - 1)
            );
            assert!(!accepts(wrapped.as_bytes()));
        }
        assert!(!accepts(format!("{{\"a\":[{object}]}}").as_bytes()));
    }
    assert!(accepts(br#"{"left":{"x":1},"right":{"x":2}}"#));
    assert!(accepts("{\"é\":1,\"e\\u0301\":2}".as_bytes()));
}

#[test]
fn utf8_bom_escapes_and_surrogates_are_checked_without_normalization() {
    for invalid in [
        &[0xff][..],
        &[0xc0, 0xaf],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xe2, 0x82],
    ] {
        assert!(!accepts(&[b"{\"x\":\"", invalid, b"\"}"].concat()));
    }
    for input in [
        "\u{feff}{}",
        " \u{feff}{}",
        r#"{"x":"\ud800"}"#,
        r#"{"\udc00":1}"#,
        r#"{"x":"\ud800a"}"#,
        r#"{"x":"\ud800\ud800"}"#,
        r#"{"x":"\x20"}"#,
        r#"{"x":"\u12"}"#,
        "{\"x\":\"\n\"}",
        "{\"x\":\"\0\"}",
    ] {
        assert!(!accepts(input.as_bytes()), "{input:?}");
    }
    for input in [
        r#"{"x":"\ud83d\ude00"}"#,
        r#"{"\ud83d\ude00":"😀"}"#,
        r#"{"x":"\u0000\ufeff"}"#,
        "{\"日本語\":\"é😀\"}",
    ] {
        assert!(accepts(input.as_bytes()));
    }
}

#[test]
fn byte_limit_counts_all_original_whitespace_and_utf8_bytes() {
    for length in [12_287, 12_288, 12_289] {
        let input = format!("{{\"x\":\"{}\"}}", "a".repeat(length - 8));
        assert_eq!(input.len(), length);
        assert_eq!(accepts(input.as_bytes()), length <= 12_288);
        let whitespace = format!("{}{{}}", " ".repeat(length - 2));
        assert_eq!(accepts(whitespace.as_bytes()), length <= 12_288);
    }
    let utf8 = format!("{{\"x\":\"{}\"}}", "é".repeat(6140));
    assert_eq!(utf8.len(), 12_288);
    assert!(accepts(utf8.as_bytes()));
    assert!(!accepts(format!("{utf8} ").as_bytes()));
}

#[test]
fn depth_sixteen_includes_root_and_empty_containers() {
    for depth in 1..=18 {
        let objects = format!("{}0{}", "{\"x\":".repeat(depth), "}".repeat(depth));
        assert_eq!(accepts(objects.as_bytes()), depth <= 16);
        for scalar in ["", "0", "null", "\"x\""] {
            // Root object plus depth-1 arrays. Empty deepest array counts too.
            if depth > 1 {
                let arrays = format!(
                    "{{\"x\":{}{scalar}{}}}",
                    "[".repeat(depth - 1),
                    "]".repeat(depth - 1)
                );
                assert_eq!(accepts(arrays.as_bytes()), depth <= 16);
            }
        }
    }
}

#[test]
fn finite_number_syntax_is_not_application_integer_semantics() {
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
        assert!(accepts(format!("{{\"extension\":{number}}}").as_bytes()));
    }
    for number in [
        "1e400", "-1e400", "NaN", "Infinity", "+1", "01", "1.", ".1", "1e",
    ] {
        assert!(!accepts(format!("{{\"extension\":{number}}}").as_bytes()));
    }
}

#[test]
fn errors_do_not_echo_signed_data_or_parser_diagnostics() {
    let error = SyntaxCheckedClientData::parse(b"{\"secret-value\":}").unwrap_err();
    assert_eq!(error, ClientDataError);
    assert_eq!(error.to_string(), "client-data syntax rejected");
    assert_eq!(format!("{error:?}"), "ClientDataError");
}
