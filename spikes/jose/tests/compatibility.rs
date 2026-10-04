use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    JoseError,
    jws::{self, ES256, JwsAlgorithm, JwsHeader, JwsSigner},
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
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
