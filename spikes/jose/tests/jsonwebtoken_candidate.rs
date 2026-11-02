//! One process-local provider assessment, not a production signer or parser.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    crypto::{CryptoProvider, JwtSigner, KeyUtils},
    errors::{ErrorKind, Result},
    signature,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
};
use std::sync::{Mutex, OnceLock};

const CANONICAL_HEADER: &[u8] =
    br#"{"alg":"ES256","kid":"test-key","typ":"vollmacht-experiment+jws"}"#;
const OBSERVED_HEADER: &[u8] =
    br#"{"typ":"vollmacht-experiment+jws","alg":"ES256","kid":"test-key"}"#;
const PAYLOAD: &[u8] = br#"{"operation":"fixture-only"}"#;
static KEY: OnceLock<PKey<Private>> = OnceLock::new();
static SEEN: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

struct SoftwareSigner;

impl signature::Signer<Vec<u8>> for SoftwareSigner {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        // Same ephemeral software-key/DER conversion pattern as compatibility.rs.
        // No native call, exported key input, or private-key confinement claim.
        SEEN.lock().unwrap().push(message.to_vec());
        let sign = || -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
            let mut signer = Signer::new(MessageDigest::sha256(), KEY.get().unwrap())?;
            signer.update(message)?;
            let signature = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
            Ok([
                signature.r().to_vec_padded(32)?,
                signature.s().to_vec_padded(32)?,
            ]
            .concat())
        };
        sign().map_err(|_| signature::Error::new())
    }
}

impl JwtSigner for SoftwareSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

fn select(algorithm: &Algorithm, handle: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if *algorithm != Algorithm::ES256 || handle.as_bytes() != b"fixture-key-handle" {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    Ok(Box::new(SoftwareSigner))
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: select,
    // No generic JWT verification or JWK utility is exercised in this assessment.
    verifier_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    key_utils: KeyUtils::new_unimplemented(),
};

fn verify_actual_input(compact: &str, public: &PKey<Public>) {
    let (input, encoded_signature) = compact.rsplit_once('.').unwrap();
    let signature = B64.decode(encoded_signature).unwrap();
    assert_eq!(signature.len(), 64);
    let der = EcdsaSig::from_private_components(
        BigNum::from_slice(&signature[..32]).unwrap(),
        BigNum::from_slice(&signature[32..]).unwrap(),
    )
    .unwrap()
    .to_der()
    .unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), public).unwrap();
    verifier.update(input.as_bytes()).unwrap();
    assert!(verifier.verify(&der).unwrap());
    let mut altered = Verifier::new(MessageDigest::sha256(), public).unwrap();
    altered.update(b"different signing input").unwrap();
    assert!(!altered.verify(&der).unwrap());
}

#[test]
fn custom_signer_works_but_public_encoder_does_not_preserve_canonical_header() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
    KEY.set(private).unwrap();
    PROVIDER.install_default().unwrap();
    assert!(PROVIDER.install_default().is_err());

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("vollmacht-experiment+jws".into());
    header.kid = Some("test-key".into());
    let claims: serde_json::Value = serde_json::from_slice(PAYLOAD).unwrap();
    // from_ec_der is a container on this custom-provider path; these bytes are
    // deliberately not DER or private key material. Factory routing is test-only.
    let handle = EncodingKey::from_ec_der(b"fixture-key-handle");
    let compact = jsonwebtoken::encode(&header, &claims, &handle).unwrap();
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(B64.decode(parts[0]).unwrap(), OBSERVED_HEADER);
    assert_ne!(B64.decode(parts[0]).unwrap(), CANONICAL_HEADER);
    assert_eq!(B64.decode(parts[1]).unwrap(), PAYLOAD);
    let input = format!("{}.{}", B64.encode(OBSERVED_HEADER), B64.encode(PAYLOAD));
    assert_eq!(*SEEN.lock().unwrap(), vec![input.as_bytes().to_vec()]);
    verify_actual_input(&compact, &public);

    // Neither an unknown handle nor a different algorithm may reach this signer.
    for bad in [b"unknown".as_slice(), b"", b"fixture-key-handle-extra"] {
        assert!(jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ec_der(bad)).is_err());
    }
    header.alg = Algorithm::ES384;
    assert!(jsonwebtoken::encode(&header, &claims, &handle).is_err());
    assert_eq!(SEEN.lock().unwrap().len(), 1);

    // Existing independently generated fixture supplies the expected payload
    // bytes. Parse those bytes, not the deliberately noncanonical envelope map.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-envelope-vector.json"
    ))
    .unwrap();
    let canonical = fixture["canonical_envelope"].as_str().unwrap();
    let envelope: serde_json::Value = serde_json::from_str(canonical).unwrap();
    assert_eq!(envelope, fixture["envelope"]);
    header = serde_json::from_value(fixture["protected_header"].clone()).unwrap();
    let compact = jsonwebtoken::encode(&header, &envelope, &handle).unwrap();
    let segments: Vec<_> = compact.split('.').collect();
    assert_eq!(segments.len(), 3);
    const ENVELOPE_HEADER: &[u8] = br#"{"typ":"vollmacht-mandate+jws","alg":"ES256","kid":"11111111111111111111111111111111"}"#;
    assert_eq!(B64.decode(segments[0]).unwrap(), ENVELOPE_HEADER);
    assert_ne!(
        B64.decode(segments[0]).unwrap(),
        fixture["canonical_header"].as_str().unwrap().as_bytes()
    );
    assert_eq!(B64.decode(segments[1]).unwrap(), canonical.as_bytes());
    let expected_input = format!("{}.{}", B64.encode(ENVELOPE_HEADER), B64.encode(canonical));
    assert_eq!(SEEN.lock().unwrap()[1], expected_input.as_bytes());
    verify_actual_input(&compact, &public);

    // The factory receives alg and handle, NOT kid. A wrong claimed kid still
    // signs with the same key. A production caller must bind these separately.
    header.kid = Some("unbound-other-key".into());
    let mismatched = jsonwebtoken::encode(&header, &envelope, &handle).unwrap();
    let mismatched_header: serde_json::Value =
        serde_json::from_slice(&B64.decode(mismatched.split('.').next().unwrap()).unwrap())
            .unwrap();
    assert_eq!(mismatched_header["kid"], "unbound-other-key");
    verify_actual_input(&mismatched, &public);
    assert_eq!(SEEN.lock().unwrap().len(), 3);
}
