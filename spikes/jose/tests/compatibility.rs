use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    JoseError,
    jws::{self, ES256, JwsAlgorithm, JwsHeader, JwsSigner},
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sha::sha256,
    sign::{Signer, Verifier},
};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

const HEADER: &[u8] = br#"{"alg":"ES256","kid":"test-key","typ":"vollmacht-experiment+jws"}"#;
const PAYLOAD: &[u8] = br#"{"operation":"fixture-only"}"#;

// The JOSE trait sees a signer, not exported private bytes. This test implementation
// still holds an exportable software key and proves no hardware confinement.
#[derive(Clone)]
struct SoftwareSigner {
    key: PKey<Private>,
    seen: Arc<Mutex<Vec<u8>>>,
}

// Deterministic public test vector: RFC 6979 A.2.5, SHA-256, message "sample".
// Only public coordinates and signature are used; no deterministic signer is added.
fn rfc_public_and_signature() -> (PKey<Public>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let x =
        BigNum::from_hex_str("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
            .unwrap();
    let y =
        BigNum::from_hex_str("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
            .unwrap();
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
    key.check_key().unwrap();
    let r =
        BigNum::from_hex_str("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
            .unwrap();
    let s =
        BigNum::from_hex_str("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
            .unwrap();
    (
        PKey::from_ec_key(key).unwrap(),
        [r.to_vec_padded(32).unwrap(), s.to_vec_padded(32).unwrap()].concat(),
    )
}

#[test]
fn fixed_scalar_encoding_vectors_preserve_padding_without_claiming_validity() {
    // Synthetic scalar pairs exercise encoding only, not valid signatures.
    for (r, s, expected_der) in [
        (1, 128, vec![0x30, 7, 2, 1, 1, 2, 2, 0, 128]),
        (128, 1, vec![0x30, 7, 2, 2, 0, 128, 2, 1, 1]),
        (1, 1, vec![0x30, 6, 2, 1, 1, 2, 1, 1]),
    ] {
        let signature = EcdsaSig::from_private_components(
            BigNum::from_u32(r).unwrap(),
            BigNum::from_u32(s).unwrap(),
        )
        .unwrap();
        assert_eq!(signature.to_der().unwrap(), expected_der);
        let parsed = EcdsaSig::from_der(&expected_der).unwrap();
        let raw = [
            parsed.r().to_vec_padded(32).unwrap(),
            parsed.s().to_vec_padded(32).unwrap(),
        ]
        .concat();
        let mut expected_raw = [0_u8; 64];
        expected_raw[31] = u8::try_from(r).unwrap();
        expected_raw[63] = u8::try_from(s).unwrap();
        assert_eq!(raw, expected_raw);
    }
}

#[test]
fn malformed_der_cannot_be_trusted_by_decode_success_alone() {
    let minimal = [0x30, 6, 2, 1, 1, 2, 1, 1];
    let trailing = [minimal.as_slice(), &[0]].concat();
    // The maintained decoder accepts a prefix. Exact re-encoding detects trailing data.
    assert_eq!(
        EcdsaSig::from_der(&trailing).unwrap().to_der().unwrap(),
        minimal
    );
    assert_ne!(
        EcdsaSig::from_der(&trailing).unwrap().to_der().unwrap(),
        trailing
    );
    for bad in [
        vec![],
        vec![0x30, 6, 2, 1, 1],
        vec![0x30, 3, 2, 1, 1],
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        vec![0x30, 6, 2, 1, 0xff, 2, 1, 1],
    ] {
        // No permissive decode result may establish canonical positive scalars.
        if let Ok(parsed) = EcdsaSig::from_der(&bad) {
            assert!(
                parsed.r().is_negative()
                    || parsed.s().is_negative()
                    || parsed.to_der().unwrap() != bad
            );
        }
    }
    let too_wide = BigNum::from_hex_str(
        "01000000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(too_wide.to_vec_padded(32).is_err());
}

#[test]
fn deterministic_scalar_boundaries_fail_verification() {
    use josekit::jws::JwsVerifier;
    let (public, valid) = rfc_public_and_signature();
    let verifier = ES256
        .verifier_from_pem(public.public_key_to_pem().unwrap())
        .unwrap();
    verifier.verify(b"sample", &valid).unwrap();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut order = BigNum::new().unwrap();
    group
        .order(&mut order, &mut BigNumContext::new().unwrap())
        .unwrap();
    let mut beyond = order.to_owned().unwrap();
    beyond.add_word(1).unwrap();
    for scalar in [
        vec![0; 32],
        order.to_vec_padded(32).unwrap(),
        beyond.to_vec_padded(32).unwrap(),
        vec![255; 32],
    ] {
        for offset in [0, 32] {
            let mut invalid = valid.clone();
            invalid[offset..offset + 32].copy_from_slice(&scalar);
            assert!(verifier.verify(b"sample", &invalid).is_err());
        }
    }
}

#[test]
fn deterministic_high_and_low_s_signatures_both_verify() {
    use josekit::jws::JwsVerifier;
    let (public, original) = rfc_public_and_signature();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut order = BigNum::new().unwrap();
    group
        .order(&mut order, &mut BigNumContext::new().unwrap())
        .unwrap();
    let s = BigNum::from_slice(&original[32..]).unwrap();
    let mut alternate_s = BigNum::new().unwrap();
    alternate_s.checked_sub(&order, &s).unwrap();
    let mut alternate = original.clone();
    alternate[32..].copy_from_slice(&alternate_s.to_vec_padded(32).unwrap());
    assert_ne!(original, alternate);
    let verifier = ES256
        .verifier_from_pem(public.public_key_to_pem().unwrap())
        .unwrap();
    for raw in [&original, &alternate] {
        verifier.verify(b"sample", raw).unwrap();
        let der = EcdsaSig::from_private_components(
            BigNum::from_slice(&raw[..32]).unwrap(),
            BigNum::from_slice(&raw[32..]).unwrap(),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let mut direct = Verifier::new(MessageDigest::sha256(), &public).unwrap();
        direct.update(b"sample").unwrap();
        assert!(direct.verify(&der).unwrap());
        assert!(verifier.verify(b"changed", raw).is_err());
    }
    // These are raw ES256 verifier vectors, not compact JWS tokens. Different
    // signature bytes cannot be a reliable single-use/replay identity.
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareTestSigner")
    }
}

impl SoftwareSigner {
    fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Self {
            key: PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap(),
            seen: Arc::default(),
        }
    }
}

impl JwsSigner for SoftwareSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &ES256
    }
    fn key_id(&self) -> Option<&str> {
        None
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        *self.seen.lock().unwrap() = message.to_vec();
        let operation = || -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
            signer.update(message)?; // Original input: hash exactly once here.
            let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
            Ok([
                signature.r().to_vec_padded(32)?,
                signature.s().to_vec_padded(32)?,
            ]
            .concat())
        };
        operation().map_err(|error| JoseError::InvalidSignature(error.into()))
    }
}

fn header() -> JwsHeader {
    let mut result = JwsHeader::new();
    result.set_algorithm("ES256");
    result.set_key_id("test-key");
    result.set_token_type("vollmacht-experiment+jws");
    result
}

fn independent_verify(signer: &SoftwareSigner, input: &[u8], raw: &[u8]) -> bool {
    if raw.len() != 64 {
        return false;
    }
    let der = EcdsaSig::from_private_components(
        BigNum::from_slice(&raw[..32]).unwrap(),
        BigNum::from_slice(&raw[32..]).unwrap(),
    )
    .unwrap()
    .to_der()
    .unwrap();
    let public = PKey::public_key_from_pem(&signer.key.public_key_to_pem().unwrap()).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public).unwrap();
    verifier.update(input).unwrap();
    verifier.verify(&der).unwrap_or(false)
}

fn signed_raw_header(signer: &SoftwareSigner, header: &[u8]) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(PAYLOAD));
    format!(
        "{}.{}",
        input,
        B64.encode(signer.sign(input.as_bytes()).unwrap())
    )
}

#[test]
fn custom_signer_receives_exact_input_and_hashes_once() {
    let signer = SoftwareSigner::new();
    let compact = jws::serialize_compact(PAYLOAD, &header(), &signer).unwrap();
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(B64.decode(parts[0]).unwrap(), HEADER);
    let expected = format!("{}.{}", B64.encode(HEADER), B64.encode(PAYLOAD));
    assert_eq!(*signer.seen.lock().unwrap(), expected.as_bytes());
    let raw = B64.decode(parts[2]).unwrap();
    assert_eq!(raw.len(), signer.signature_len());
    assert!(independent_verify(&signer, expected.as_bytes(), &raw));
    assert!(!independent_verify(
        &signer,
        &sha256(expected.as_bytes()),
        &raw
    ));
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    assert_eq!(
        jws::deserialize_compact(&compact, &verifier).unwrap().0,
        PAYLOAD
    );
}

#[test]
fn mutation_and_wrong_key_are_denied() {
    let signer = SoftwareSigner::new();
    let compact = jws::serialize_compact(PAYLOAD, &header(), &signer).unwrap();
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    let parts: Vec<_> = compact.split('.').collect();
    let mut raw = B64.decode(parts[2]).unwrap();
    for invalid in [vec![], vec![0; 63], vec![0; 65], vec![0; 64], vec![255; 64]] {
        assert!(
            jws::deserialize_compact(
                format!("{}.{}.{}", parts[0], parts[1], B64.encode(invalid)),
                &verifier
            )
            .is_err()
        );
    }
    raw[0] ^= 1;
    assert!(
        jws::deserialize_compact(
            format!("{}.{}.{}", parts[0], parts[1], B64.encode(raw)),
            &verifier
        )
        .is_err()
    );
    assert!(
        jws::deserialize_compact(
            format!("{}.{}.{}", parts[0], B64.encode(b"changed"), parts[2]),
            &verifier
        )
        .is_err()
    );
    let wrong = SoftwareSigner::new();
    let wrong_verifier = ES256
        .verifier_from_pem(wrong.key.public_key_to_pem().unwrap())
        .unwrap();
    assert!(jws::deserialize_compact(&compact, &wrong_verifier).is_err());
}

#[test]
fn header_serialization_is_insertion_order_not_canonicalization() {
    let signer = SoftwareSigner::new();
    let mut reordered = JwsHeader::new();
    reordered.set_token_type("vollmacht-experiment+jws");
    reordered.set_key_id("test-key");
    reordered.set_algorithm("ES256");
    let compact = jws::serialize_compact(PAYLOAD, &reordered, &signer).unwrap();
    let bytes = B64.decode(compact.split('.').next().unwrap()).unwrap();
    assert_eq!(
        bytes,
        br#"{"typ":"vollmacht-experiment+jws","kid":"test-key","alg":"ES256"}"#
    );
    assert_ne!(bytes, HEADER);
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    assert!(jws::deserialize_compact(&compact, &verifier).is_ok());
}

#[test]
fn validly_signed_wrong_algorithm_and_unknown_critical_are_denied() {
    let signer = SoftwareSigner::new();
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    for bytes in [
        br#"{"alg":"HS256"}"#.as_slice(),
        br#"{"alg":"ES256","crit":["future"],"future":true}"#,
    ] {
        let compact = signed_raw_header(&signer, bytes);
        assert!(jws::deserialize_compact(compact, &verifier).is_err());
    }
}

#[test]
fn valid_signature_is_not_typ_kid_or_extra_header_policy() {
    let signer = SoftwareSigner::new();
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    for bytes in [
        br#"{"alg":"ES256","typ":"wrong"}"#.as_slice(),
        br#"{"alg":"ES256","kid":"untrusted"}"#,
        br#"{"alg":"ES256","extra":true}"#,
        br#"{"alg":"ES256","b64":false}"#,
    ] {
        // b64 without a matching critical declaration is ignored by this library.
        assert!(jws::deserialize_compact(signed_raw_header(&signer, bytes), &verifier).is_ok());
    }
    let mut bound_verifier = verifier;
    bound_verifier.set_key_id("test-key");
    assert!(
        jws::deserialize_compact(
            signed_raw_header(&signer, br#"{"alg":"ES256","kid":"wrong"}"#),
            &bound_verifier
        )
        .is_err()
    );
}

#[test]
fn unencoded_payload_requires_explicit_critical_opt_in() {
    let signer = SoftwareSigner::new();
    let mut unencoded = header();
    unencoded.set_critical(&vec!["b64"]);
    unencoded.set_base64url_encode_payload(false);
    let compact = jws::serialize_compact(PAYLOAD, &unencoded, &signer).unwrap();
    assert_eq!(compact.split('.').nth(1).unwrap().as_bytes(), PAYLOAD);
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    assert!(jws::deserialize_compact(&compact, &verifier).is_err());
    let mut context = jws::JwsContext::new();
    context.add_acceptable_critical("b64");
    assert_eq!(
        context.deserialize_compact(compact, &verifier).unwrap().0,
        PAYLOAD
    );
}

#[test]
fn duplicate_protected_header_is_not_rejected_before_map_collapse() {
    let signer = SoftwareSigner::new();
    let verifier = ES256
        .verifier_from_pem(signer.key.public_key_to_pem().unwrap())
        .unwrap();
    let compact = signed_raw_header(&signer, br#"{"alg":"HS256","alg":"ES256"}"#);
    assert!(jws::deserialize_compact(compact, &verifier).is_ok());
    // Negative demonstration only. Future strict parsing must reject this first.
}
