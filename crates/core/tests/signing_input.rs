use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    crypto::{CryptoProvider, JwtSigner, KeyUtils},
    errors::ErrorKind,
    signature,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};
use std::{
    process::Command,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use vollmacht_core::{
    AgentPublicKey, EnrollmentPossessionPayload, ExecutionProofPayload, MandateEnvelope,
    PreparedSigningInput, SigningInputError, VerificationRuntime,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}
fn public(value: &Value) -> AgentPublicKey {
    AgentPublicKey::parse(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn prepare(
    role: &str,
    payload: &[u8],
    kid: &str,
    key: &AgentPublicKey,
) -> Result<PreparedSigningInput, SigningInputError> {
    match role {
        "issuer" => PreparedSigningInput::issuer(
            &MandateEnvelope::parse_canonical(payload).unwrap(),
            kid,
            key,
        ),
        "execution" => PreparedSigningInput::execution(
            &ExecutionProofPayload::parse_canonical(payload).unwrap(),
            kid,
            key,
        ),
        "possession" => PreparedSigningInput::enrollment_possession(
            &EnrollmentPossessionPayload::parse_canonical(payload).unwrap(),
            kid,
            key,
        ),
        _ => panic!("test role"),
    }
}
fn fixture_prepared(role: &str) -> PreparedSigningInput {
    let f = fixture();
    let header: Value = serde_json::from_str(f[role]["header_bytes"].as_str().unwrap()).unwrap();
    let key = public(
        &f["trusted"][if role == "issuer" {
            "issuer_jwk"
        } else {
            "agent_jwk"
        }],
    );
    prepare(
        role,
        f[role]["canonical_payload"].as_str().unwrap().as_bytes(),
        header["kid"].as_str().unwrap(),
        &key,
    )
    .unwrap()
}

#[test]
fn independently_generated_three_role_inputs_match_exactly() {
    let f = fixture();
    for role in ["issuer", "execution", "possession"] {
        let prepared = fixture_prepared(role);
        let expected = f[role]["jws"].as_str().unwrap().rsplit_once('.').unwrap().0;
        assert_eq!(prepared.signing_input(), expected.as_bytes());
        prepared.check_callback_input(expected.as_bytes()).unwrap();
        for other in ["issuer", "execution", "possession"] {
            if other != role {
                assert!(
                    prepared
                        .check_callback_input(fixture_prepared(other).signing_input())
                        .is_err()
                );
            }
        }
        let mut calls = 0;
        for bad in [
            b"".to_vec(),
            [expected.as_bytes(), b"."].concat(),
            expected.as_bytes()[1..].to_vec(),
        ] {
            let guarded = || -> Result<(), SigningInputError> {
                prepared.check_callback_input(&bad)?;
                Ok(())
            };
            if guarded().is_ok() {
                calls += 1;
            }
        }
        assert_eq!(
            calls, 0,
            "mismatches cannot reach the fake signing operation"
        );
        assert!(!format!("{prepared:?}").contains(expected));
    }
}

#[test]
fn key_kid_and_possession_body_binding_fail_closed() {
    let f = fixture();
    let wrong = public(&f["trusted"]["wrong_jwk"]);
    for role in ["execution", "possession"] {
        let header: Value =
            serde_json::from_str(f[role]["header_bytes"].as_str().unwrap()).unwrap();
        let bytes = f[role]["canonical_payload"].as_str().unwrap().as_bytes();
        assert!(prepare(role, bytes, header["kid"].as_str().unwrap(), &wrong).is_err());
        assert!(prepare(role, bytes, "invalid", &public(&f["trusted"]["agent_jwk"])).is_err());
    }
    let mut body: Value =
        serde_json::from_str(f["possession"]["canonical_payload"].as_str().unwrap()).unwrap();
    body["agent_jkt"] = json!(B64.encode([1; 32]));
    let header: Value =
        serde_json::from_str(f["possession"]["header_bytes"].as_str().unwrap()).unwrap();
    assert!(
        prepare(
            "possession",
            &serde_jcs::to_vec(&body).unwrap(),
            header["kid"].as_str().unwrap(),
            &public(&f["trusted"]["agent_jwk"])
        )
        .is_err()
    );
    assert_eq!(format!("{SigningInputError:?}"), "SigningInputError");
}

static PRIVATE: OnceLock<PKey<Private>> = OnceLock::new();
static EXPECTED: Mutex<Option<PreparedSigningInput>> = Mutex::new(None);
static SIGN_CALLS: AtomicUsize = AtomicUsize::new(0);
struct TestSigner;
impl signature::Signer<Vec<u8>> for TestSigner {
    fn try_sign(&self, input: &[u8]) -> Result<Vec<u8>, signature::Error> {
        EXPECTED
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .check_callback_input(input)
            .map_err(|_| signature::Error::new())?;
        SIGN_CALLS.fetch_add(1, Ordering::SeqCst);
        let mut signer = Signer::new(MessageDigest::sha256(), PRIVATE.get().unwrap()).unwrap();
        signer.update(input).unwrap();
        let sig = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
        Ok([
            sig.r().to_vec_padded(32).unwrap(),
            sig.s().to_vec_padded(32).unwrap(),
        ]
        .concat())
    }
}
impl JwtSigner for TestSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}
static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |alg, handle| {
        if *alg != Algorithm::ES256 || handle.as_bytes() != b"test-only-handle" {
            return Err(ErrorKind::InvalidAlgorithm.into());
        }
        Ok(Box::new(TestSigner))
    },
    verifier_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    key_utils: KeyUtils::new_unimplemented(),
};

#[test]
fn encoder_child_entry() {
    if std::env::var_os("VOLLMACHT_SIGNING_INPUT_CHILD").is_none() {
        return;
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
        .unwrap();
    let jwk = json!({"kty":"EC","crv":"P-256","x":B64.encode(x.to_vec_padded(32).unwrap()),"y":B64.encode(y.to_vec_padded(32).unwrap())});
    let key = public(&jwk);
    let jkt = B64.encode(key.thumbprint().unwrap());
    PRIVATE.set(PKey::from_ec_key(ec).unwrap()).unwrap();
    PROVIDER.install_default().unwrap();
    let f = fixture();
    let mut records = Vec::new();
    for role in ["issuer", "execution", "possession"] {
        let mut header: Header =
            serde_json::from_str(f[role]["header_bytes"].as_str().unwrap()).unwrap();
        if role != "issuer" {
            header.kid = Some(jkt.clone());
        }
        let mut payload: Value =
            serde_json::from_str(f[role]["canonical_payload"].as_str().unwrap()).unwrap();
        if role == "possession" {
            payload["agent_jkt"] = json!(jkt);
        }
        let canonical = serde_jcs::to_vec(&payload).unwrap();
        let prepared = prepare(role, &canonical, header.kid.as_ref().unwrap(), &key).unwrap();
        *EXPECTED.lock().unwrap() = Some(prepared);
        let before = SIGN_CALLS.load(Ordering::SeqCst);
        let compact = jsonwebtoken::encode(
            &header,
            &payload,
            &EncodingKey::from_ec_der(b"test-only-handle"),
        )
        .unwrap();
        assert_eq!(SIGN_CALLS.load(Ordering::SeqCst), before + 1);
        let mut changed = payload.clone();
        if role == "issuer" {
            changed["payload"]["nonce"] = json!(B64.encode([2; 32]));
        } else {
            changed["challenge"] = json!(B64.encode([2; 32]));
        }
        assert!(
            jsonwebtoken::encode(
                &header,
                &changed,
                &EncodingKey::from_ec_der(b"test-only-handle")
            )
            .is_err()
        );
        assert_eq!(
            SIGN_CALLS.load(Ordering::SeqCst),
            before + 1,
            "no signing or retry after mismatch"
        );
        let mut wrong_header = header.clone();
        wrong_header.typ = Some("different-role+jws".into());
        assert!(
            jsonwebtoken::encode(
                &wrong_header,
                &payload,
                &EncodingKey::from_ec_der(b"test-only-handle")
            )
            .is_err()
        );
        assert_eq!(SIGN_CALLS.load(Ordering::SeqCst), before + 1);
        records.push(json!({"role":role,"kid":header.kid,"payload":String::from_utf8(canonical).unwrap(),"compact":compact}));
    }
    println!("SIGNING_RESULT:{}", json!({"jwk":jwk,"records":records}));
}

#[test]
fn final_outputs_require_original_binding_and_real_signatures() {
    let runtime = VerificationRuntime::initialize().unwrap();
    let f = fixture();
    for role in ["issuer", "execution", "possession"] {
        let prepared = fixture_prepared(role);
        let token = f[role]["jws"].as_str().unwrap();
        prepared
            .validate_output(&runtime, token.as_bytes())
            .unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[2] = B64.encode([0; 64]);
        assert!(
            prepared
                .validate_output(&runtime, parts.join(".").as_bytes())
                .is_err()
        );
        for other in ["issuer", "execution", "possession"] {
            if other != role {
                assert!(
                    prepared
                        .validate_output(&runtime, f[other]["jws"].as_str().unwrap().as_bytes())
                        .is_err()
                );
            }
        }
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["encoder_child_entry", "--nocapture"])
        .env("VOLLMACHT_SIGNING_INPUT_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let text = String::from_utf8(child.stdout).unwrap();
    let record: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("SIGNING_RESULT:"))
            .unwrap(),
    )
    .unwrap();
    let key = public(&record["jwk"]);
    for result in record["records"].as_array().unwrap() {
        let role = result["role"].as_str().unwrap();
        let bytes = result["payload"].as_str().unwrap().as_bytes();
        let kid = result["kid"].as_str().unwrap();
        let prepared = prepare(role, bytes, kid, &key).unwrap();
        let token = result["compact"].as_str().unwrap();
        let checked = prepared
            .validate_output(&runtime, token.as_bytes())
            .unwrap();
        assert_eq!(checked.artifact().signing_input(), prepared.signing_input());
        if role == "issuer" {
            let wrong = prepare(role, bytes, kid, &public(&f["trusted"]["wrong_jwk"])).unwrap();
            assert!(wrong.validate_output(&runtime, token.as_bytes()).is_err());
        }
        let mut changed: Value = serde_json::from_slice(bytes).unwrap();
        if role == "issuer" {
            changed["payload"]["nonce"] = json!(B64.encode([3; 32]));
        } else {
            changed["challenge"] = json!(B64.encode([3; 32]));
        }
        let mutated = prepare(role, &serde_jcs::to_vec(&changed).unwrap(), kid, &key).unwrap();
        assert!(mutated.validate_output(&runtime, token.as_bytes()).is_err());
    }
}
