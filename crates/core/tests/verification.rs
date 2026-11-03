use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{
    crypto::{CryptoProvider, KeyUtils},
    errors::ErrorKind,
};
use openssl::{
    bn::BigNumContext,
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
    sync::atomic::{AtomicUsize, Ordering},
};
use vollmacht_core::{
    AgentPublicKey, CompactRole, VerificationBinding, VerificationError, VerificationRuntime,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}
fn key(name: &str) -> AgentPublicKey {
    AgentPublicKey::parse(&serde_json::to_vec(&fixture()["trusted"][name]).unwrap()).unwrap()
}
fn cases() -> [(CompactRole, &'static str, &'static str); 3] {
    [
        (CompactRole::Issuer, "issuer", "issuer_jwk"),
        (CompactRole::Execution, "execution", "agent_jwk"),
        (CompactRole::EnrollmentPossession, "possession", "agent_jwk"),
    ]
}
fn kid(name: &str) -> String {
    let header: Value =
        serde_json::from_str(fixture()[name]["header_bytes"].as_str().unwrap()).unwrap();
    header["kid"].as_str().unwrap().to_owned()
}
fn token(name: &str) -> String {
    fixture()[name]["jws"].as_str().unwrap().to_owned()
}
fn binding(role: CompactRole, name: &str, key_name: &str) -> VerificationBinding {
    VerificationBinding::new(role, &kid(name), &key(key_name)).unwrap()
}
fn segment(name: &str, index: usize, bytes: &[u8]) -> String {
    let mut parts: Vec<String> = token(name).split('.').map(str::to_owned).collect();
    parts[index] = B64.encode(bytes);
    parts.join(".")
}

static FOREIGN_CALLS: AtomicUsize = AtomicUsize::new(0);
static FOREIGN: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| {
        FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(ErrorKind::InvalidAlgorithm.into())
    },
    verifier_factory: |_, _| {
        FOREIGN_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(ErrorKind::InvalidAlgorithm.into())
    },
    key_utils: KeyUtils::new_unimplemented(),
};

#[test]
fn independent_processes_exercise_startup_and_signature_boundaries() {
    for scenario in ["once", "foreign", "race", "fixtures", "signed_negatives"] {
        let result = Command::new(std::env::current_exe().unwrap())
            .arg("verification_child_entry")
            .env("VOLLMACHT_VERIFICATION_TEST_CASE", scenario)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "scenario {scenario}: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn verification_child_entry() {
    let Ok(scenario) = std::env::var("VOLLMACHT_VERIFICATION_TEST_CASE") else {
        return;
    };
    match scenario.as_str() {
        "once" => {
            let runtime = VerificationRuntime::initialize().unwrap();
            assert!(matches!(
                VerificationRuntime::initialize(),
                Err(VerificationError::Initialization)
            ));
            assert!(
                runtime
                    .verify(
                        token("issuer").as_bytes(),
                        &binding(CompactRole::Issuer, "issuer", "issuer_jwk")
                    )
                    .is_ok()
            );
        }
        "foreign" => {
            // Constructing a public binding must not lazily install a provider.
            let _binding = binding(CompactRole::Issuer, "issuer", "issuer_jwk");
            FOREIGN.install_default().unwrap();
            assert!(matches!(
                VerificationRuntime::initialize(),
                Err(VerificationError::Initialization)
            ));
            assert!(matches!(
                VerificationRuntime::initialize(),
                Err(VerificationError::Initialization)
            ));
            assert_eq!(FOREIGN_CALLS.load(Ordering::SeqCst), 0);
        }
        "race" => {
            let threads: Vec<_> = (0..8)
                .map(|_| std::thread::spawn(VerificationRuntime::initialize))
                .collect();
            let mut winners = Vec::new();
            for thread in threads {
                match thread.join().unwrap() {
                    Ok(runtime) => winners.push(runtime),
                    Err(error) => assert_eq!(error, VerificationError::Initialization),
                }
            }
            assert_eq!(winners.len(), 1);
            assert!(
                winners[0]
                    .verify(
                        token("issuer").as_bytes(),
                        &binding(CompactRole::Issuer, "issuer", "issuer_jwk")
                    )
                    .is_ok()
            );
        }
        "fixtures" => fixture_cases(),
        "signed_negatives" => signed_negative_cases(),
        _ => panic!("unknown test scenario"),
    }
}

fn fixture_cases() {
    let runtime = VerificationRuntime::initialize().unwrap();
    for (role, name, public) in cases() {
        let bound = binding(role, name, public);
        let original = token(name);
        let checked = runtime.verify(original.as_bytes(), &bound).unwrap();
        assert_eq!(checked.artifact().compact_bytes(), original.as_bytes());
        assert_eq!(
            checked.artifact().signing_input(),
            original.rsplit_once('.').unwrap().0.as_bytes()
        );
        assert_eq!(checked.artifact().role(), role);
        // Fixed historical timestamps succeed cryptographically: this API has
        // no clock, live registry, reservation state or WebAuthn trust context.
        for signature in [vec![0; 64], vec![255; 64], vec![0; 63], vec![0; 65]] {
            assert!(
                runtime
                    .verify(segment(name, 2, &signature).as_bytes(), &bound)
                    .is_err()
            );
        }
        let signature = B64.decode(original.rsplit_once('.').unwrap().1).unwrap();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut order = openssl::bn::BigNum::new().unwrap();
        group
            .order(&mut order, &mut BigNumContext::new().unwrap())
            .unwrap();
        let order = order.to_vec_padded(32).unwrap();
        for half in [0, 32] {
            let mut zero_scalar = signature.clone();
            zero_scalar[half..half + 32].fill(0);
            assert!(
                runtime
                    .verify(segment(name, 2, &zero_scalar).as_bytes(), &bound)
                    .is_err()
            );
            let mut order_scalar = signature.clone();
            order_scalar[half..half + 32].copy_from_slice(&order);
            assert!(
                runtime
                    .verify(segment(name, 2, &order_scalar).as_bytes(), &bound)
                    .is_err()
            );
        }
        let mut flipped = signature;
        flipped[0] ^= 1;
        assert!(
            runtime
                .verify(segment(name, 2, &flipped).as_bytes(), &bound)
                .is_err()
        );
        let mut payload = fixture()[name]["payload"].clone();
        if name == "issuer" {
            payload["payload"]["policy_revision"] = json!(2);
        } else {
            payload["challenge"] = json!(B64.encode([0; 32]));
        }
        assert!(matches!(
            runtime.verify(
                segment(name, 1, &serde_jcs::to_vec(&payload).unwrap()).as_bytes(),
                &bound
            ),
            Err(VerificationError::Signature)
        ));
        let mut unsupported = fixture()[name]["payload"].clone();
        if name == "issuer" {
            unsupported["payload"]["crypto_profile"] = json!("unknown");
        } else {
            unsupported["crypto_profile"] = json!("unknown");
        }
        assert!(matches!(
            runtime.verify(
                segment(name, 1, &serde_jcs::to_vec(&unsupported).unwrap()).as_bytes(),
                &bound
            ),
            Err(VerificationError::InvalidArtifact)
        ));
        let pretty = serde_json::to_string_pretty(&fixture()[name]["payload"]).unwrap();
        assert!(matches!(
            runtime.verify(segment(name, 1, pretty.as_bytes()).as_bytes(), &bound),
            Err(VerificationError::InvalidArtifact)
        ));
        let wrong = VerificationBinding::new(role, &kid(name), &key("wrong_jwk"));
        if name == "issuer" {
            assert!(matches!(
                runtime.verify(original.as_bytes(), &wrong.unwrap()),
                Err(VerificationError::Signature)
            ));
        } else {
            assert!(matches!(wrong, Err(VerificationError::InvalidBinding)));
        }
        for bad_kid in ["", "../key", "DO_NOT_ECHO_THIS_SECRET"] {
            assert!(matches!(
                VerificationBinding::new(role, bad_kid, &key(public)),
                Err(VerificationError::InvalidBinding)
            ));
        }
    }
    let issuer_binding = binding(CompactRole::Issuer, "issuer", "issuer_jwk");
    assert!(matches!(
        runtime.verify(token("execution").as_bytes(), &issuer_binding),
        Err(VerificationError::InvalidArtifact)
    ));
    let error = runtime
        .verify(b"DO_NOT_ECHO_THIS_SECRET", &issuer_binding)
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_THIS_SECRET"));
}

// Synthetic software-key signing only, using maintained OpenSSL APIs. These
// negative test signatures are not production encoders or hardware evidence.
fn sign(header: &str, payload: &str, private: &PKey<Private>) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let mut signer = Signer::new(MessageDigest::sha256(), private).unwrap();
    signer.update(input.as_bytes()).unwrap();
    let signature = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
    let raw = [
        signature.r().to_vec_padded(32).unwrap(),
        signature.s().to_vec_padded(32).unwrap(),
    ]
    .concat();
    format!("{input}.{}", B64.encode(raw))
}

fn signed_negative_cases() {
    let runtime = VerificationRuntime::initialize().unwrap();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)
        .unwrap();
    let public = AgentPublicKey::parse(
        &serde_json::to_vec(&json!({"kty":"EC","crv":"P-256",
        "x":B64.encode(x.to_vec_padded(32).unwrap()),"y":B64.encode(y.to_vec_padded(32).unwrap())}))
        .unwrap(),
    )
    .unwrap();
    let private = PKey::from_ec_key(ec).unwrap();
    let bound = VerificationBinding::new(CompactRole::Issuer, &kid("issuer"), &public).unwrap();
    let f = fixture();
    let header = f["issuer"]["header_bytes"].as_str().unwrap();
    let payload = f["issuer"]["canonical_payload"].as_str().unwrap();
    assert!(
        runtime
            .verify(sign(header, payload, &private).as_bytes(), &bound)
            .is_ok()
    );
    // The outer issuer signature can be valid while retained WebAuthn bytes
    // are nonsense. This layer must not claim evidence verification/authority.
    let mut opaque = f["issuer"]["payload"].clone();
    opaque["evidence"]["client_data_json"] = json!("AA");
    opaque["evidence"]["signature"] = json!("AA");
    let opaque = String::from_utf8(serde_jcs::to_vec(&opaque).unwrap()).unwrap();
    assert!(
        runtime
            .verify(sign(header, &opaque, &private).as_bytes(), &bound)
            .is_ok()
    );
    for bad_header in [
        header.replace("ES256", "ES384"),
        header.replace("vollmacht-mandate+jws", "JWT"),
        format!(" {header}"),
        header.replacen('{', "{\"extra\":1,", 1),
        header.replacen('{', "{\"alg\":\"ES256\",", 1),
    ] {
        assert!(matches!(
            runtime.verify(sign(&bad_header, payload, &private).as_bytes(), &bound),
            Err(VerificationError::InvalidArtifact)
        ));
    }
    let mut unknown = f["issuer"]["payload"].clone();
    unknown["payload"]["crypto_profile"] = json!("unknown");
    let unknown = String::from_utf8(serde_jcs::to_vec(&unknown).unwrap()).unwrap();
    for bad_payload in [
        unknown,
        format!(" {payload}"),
        payload.replace("\"version\":1", "\"version\":1,\"\\u0076ersion\":1"),
    ] {
        assert!(matches!(
            runtime.verify(sign(header, &bad_payload, &private).as_bytes(), &bound),
            Err(VerificationError::InvalidArtifact)
        ));
    }
}
