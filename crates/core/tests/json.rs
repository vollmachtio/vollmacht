use serde_json::json;
use vollmacht_core::{InputLimit, MAX_INPUT_BYTES, ParseError, parse_object};

fn accepts(input: &[u8]) -> bool {
    parse_object(input, InputLimit::MAX).is_ok()
}

fn rejects(input: &[u8]) {
    assert!(!accepts(input), "unexpected acceptance: {input:?}");
}

#[test]
fn syntax_is_not_schema_or_canonicality() {
    let input = b" \r\n\t{\"unknown\":{},\"\":\"\",\"n\":9007199254740991,\"z\":0} \t";
    let parsed = parse_object(input, InputLimit::MAX).unwrap();
    assert_eq!(parsed.fields()["n"], json!(9_007_199_254_740_991_u64));
    assert_eq!(parsed.fields()["z"], json!(0));
    assert_eq!(parsed.fields()[""], json!(""));
    assert_eq!(parsed.fields()["unknown"], json!({}));
    assert!(accepts(br#"{"x":"\u0041\/\"\\"}"#));
    assert_eq!(
        parse_object(br#"{"x":"\u0041"}"#, InputLimit::MAX).unwrap(),
        parse_object(br#"{"x":"A"}"#, InputLimit::MAX).unwrap()
    );
}

#[test]
fn numeric_lexemes_are_not_normalized_into_acceptance() {
    for token in [
        "-0",
        "-1",
        "+0",
        "00",
        "01",
        "0.0",
        "1.0",
        "1e0",
        "1E0",
        "1e+0",
        "1e-0",
        "1.",
        ".1",
        "1e400",
        "NaN",
        "Infinity",
        "9007199254740992",
        "18446744073709551615",
        "18446744073709551616",
        "-9007199254740991",
    ] {
        rejects(format!("{{\"n\":{token}}}").as_bytes());
        rejects(format!("{{\"a\":{{\"n\":{token}}}}}").as_bytes());
    }
    for token in ["0", "1", "10", "4294967295", "9007199254740991"] {
        assert!(accepts(format!("{{\"n\":{token}}}").as_bytes()));
    }
}

#[test]
fn only_object_roots_and_allowed_nested_types() {
    for token in ["0", "-0", "\"x\"", "[]", "[{}]", "null", "true", "false"] {
        rejects(token.as_bytes());
    }
    for token in ["[]", "[{}]", "null", "true", "false"] {
        rejects(format!("{{\"x\":{token}}}").as_bytes());
    }
    for input in [
        " ",
        "\n\t",
        "{",
        "}",
        "{x:1}",
        "{'x':1}",
        "{\"x\":}",
        "{\"x\":1,}",
        "{,}",
    ] {
        rejects(input.as_bytes());
    }
}

#[test]
fn depth_counts_root_as_one_and_duplicates_at_every_depth_reject() {
    for depth in 1..=10 {
        let wrap = |inner: &str| {
            format!(
                "{}{}{}",
                "{\"a\":".repeat(depth - 1),
                inner,
                "}".repeat(depth - 1)
            )
        };
        assert_eq!(accepts(wrap("{}").as_bytes()), depth <= 8);
        assert_eq!(accepts(wrap("{\"n\":0}").as_bytes()), depth <= 8);
        rejects(wrap(r#"{"x":0,"x":1}"#).as_bytes());
        rejects(wrap(r#"{"x":0,"\u0078":1}"#).as_bytes());
        rejects(wrap(r#"{"\u0078":0,"x":1}"#).as_bytes());
        rejects(wrap(r#"{"":0,"":1}"#).as_bytes());
    }
    assert!(accepts(br#"{"a":{"x":0},"b":{"x":1}}"#));
}

#[test]
fn decoded_keys_and_strings_require_printable_ascii() {
    for code in 0..=255_u32 {
        let escaped = format!("\\u{code:04x}");
        let allowed = (0x20..=0x7e).contains(&code);
        assert_eq!(
            accepts(format!("{{\"k\":\"{escaped}\"}}").as_bytes()),
            allowed,
            "value {code}"
        );
        assert_eq!(
            accepts(format!("{{\"{escaped}\":0}}").as_bytes()),
            allowed,
            "key {code}"
        );
    }
    for value in [
        "é", "中", "😀", "\u{feff}", "\u{7f}", "\n", "\t", "\r", "\0",
    ] {
        rejects(format!("{{\"k\":\"{value}\"}}").as_bytes());
        rejects(format!("{{\"{value}\":0}}").as_bytes());
    }
    for value in [
        r"\ud800",
        r"\udfff",
        r"\ud800\udc00",
        r"\uD83D\uDE00",
        r"\u00",
        r"\uXXXX",
        r"\v",
    ] {
        rejects(format!("{{\"k\":\"{value}\"}}").as_bytes());
        rejects(format!("{{\"{value}\":0}}").as_bytes());
    }
    for byte in 0_u8..=31 {
        let mut input = b"{\"k\":\"".to_vec();
        input.push(byte);
        input.extend_from_slice(b"\"}");
        rejects(&input);
    }
}

#[test]
fn invalid_utf8_bom_trailing_content_and_non_json_whitespace_reject() {
    for bytes in [
        vec![0xff],
        vec![0xc0, 0xaf],
        vec![0xed, 0xa0, 0x80],
        vec![0xe2, 0x82],
    ] {
        let mut input = b"{\"x\":\"".to_vec();
        input.extend(bytes);
        input.extend_from_slice(b"\"}");
        rejects(&input);
    }
    for suffix in [
        "{}",
        "0",
        "null",
        "\0",
        "// comment",
        "/* comment */",
        "\u{feff}",
        "\u{a0}",
        "\u{b}",
    ] {
        rejects(format!("{{}}{suffix}").as_bytes());
    }
    rejects("\u{feff}{}".as_bytes());
    rejects(" \u{feff}{}".as_bytes());
    assert!(accepts(b"\r\n\t {} \r\n\t"));
}

#[test]
fn fixed_and_trusted_smaller_byte_limits_include_whitespace() {
    assert_eq!(InputLimit::new(0), None);
    assert_eq!(InputLimit::new(MAX_INPUT_BYTES + 1), None);
    assert_eq!(InputLimit::new(usize::MAX), None);
    assert_eq!(InputLimit::new(MAX_INPUT_BYTES), Some(InputLimit::MAX));
    assert_eq!(
        parse_object(b"", InputLimit::MAX),
        Err(ParseError::InputSize)
    );
    assert_eq!(
        parse_object(b"{}", InputLimit::new(1).unwrap()),
        Err(ParseError::InputSize)
    );
    assert!(parse_object(b"{}", InputLimit::new(2).unwrap()).is_ok());
    assert_eq!(
        parse_object(b" {}", InputLimit::new(2).unwrap()),
        Err(ParseError::InputSize)
    );
    for cap in [2, 512, 8192, MAX_INPUT_BYTES] {
        let mut bytes = b"{}".to_vec();
        bytes.resize(cap, b' ');
        let limit = InputLimit::new(cap).unwrap();
        assert!(parse_object(&bytes, limit).is_ok());
        bytes.push(b' ');
        assert_eq!(parse_object(&bytes, limit), Err(ParseError::InputSize));
    }
    let long_string = format!("{{\"x\":\"{}\"}}", "x".repeat(MAX_INPUT_BYTES - 8));
    assert_eq!(long_string.len(), MAX_INPUT_BYTES);
    assert!(accepts(long_string.as_bytes()));
    let long_key = format!("{{\"{}\":0}}", "k".repeat(MAX_INPUT_BYTES - 6));
    assert_eq!(long_key.len(), MAX_INPUT_BYTES);
    assert!(accepts(long_key.as_bytes()));
}

#[test]
fn deterministic_generated_inputs_do_not_panic_or_broaden_the_profile() {
    // Fixed deterministic corpus, not a fuzzing or exhaustive safety claim.
    let mut state = 0x1234_5678_u32;
    for len in 0..256 {
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((state >> 24) as u8);
        }
        let _ = parse_object(&bytes, InputLimit::MAX);
    }
    for count in 0..128 {
        let fields = (0..count)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let input = format!("{{{fields}}}");
        let parsed = parse_object(input.as_bytes(), InputLimit::MAX).unwrap();
        assert_eq!(parsed.fields().len(), count);
        if count > 0 {
            rejects(format!("{{{fields},\"k0\":0}}").as_bytes());
        }
    }
}

#[test]
fn errors_are_bounded_and_do_not_echo_input() {
    let error = parse_object(b"secret-not-json", InputLimit::MAX).unwrap_err();
    assert_eq!(error, ParseError::InvalidSyntax);
    assert_eq!(error.to_string(), "application JSON syntax rejected");
    assert_eq!(
        ParseError::InputSize.to_string(),
        "application JSON input size rejected"
    );
    assert!(std::error::Error::source(&error).is_none());
}
