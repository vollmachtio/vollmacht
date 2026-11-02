//! Bounded public-verifier assessment, not a production profile gate.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    crypto::{CryptoProvider, JwtVerifier, KeyUtils},
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
use serde_json::Value;
use std::sync::Mutex;

static SEEN: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
struct PublicVerifier(PKey<Public>);

impl signature::Verifier<Vec<u8>> for PublicVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), signature::Error> {
        SEEN.lock().unwrap().push(message.to_vec());
        if signature.len() != 64 {
            return Err(signature::Error::new());
        }
        let verify = || -> std::result::Result<bool, openssl::error::ErrorStack> {
            let der = EcdsaSig::from_private_components(
                BigNum::from_slice(&signature[..32])?,
                BigNum::from_slice(&signature[32..])?,
            )?
            .to_der()?;
            let mut verifier = Verifier::new(MessageDigest::sha256(), &self.0)?;
            verifier.update(message)?;
            verifier.verify(&der)
        };
        match verify() {
            Ok(true) => Ok(()),
            _ => Err(signature::Error::new()),
        }
    }
}

impl JwtVerifier for PublicVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

fn select(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if *algorithm != Algorithm::ES256 {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    let public = PKey::public_key_from_der(key.try_get_as_bytes()?)
        .map_err(|_| ErrorKind::InvalidKeyFormat)?;
    let ec = public.ec_key().map_err(|_| ErrorKind::InvalidKeyFormat)?;
    if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    ec.check_key().map_err(|_| ErrorKind::InvalidKeyFormat)?;
    Ok(Box::new(PublicVerifier(public)))
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    verifier_factory: select,
    key_utils: KeyUtils::new_unimplemented(),
};

fn fixture_public(jwk: &Value) -> PKey<Public> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let x = BigNum::from_slice(&B64.decode(jwk["x"].as_str().unwrap()).unwrap()).unwrap();
    let y = BigNum::from_slice(&B64.decode(jwk["y"].as_str().unwrap()).unwrap()).unwrap();
    PKey::from_ec_key(EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap()).unwrap()
}

fn non_jwt_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.leeway = 0;
    validation
}

// Test-only malformed/profile-incompatible fixtures signed by OpenSSL. This is
// not a reusable JOSE encoder and cannot be reached by production code.
fn signed_variant(header: &str, payload: &str, key: &PKey<Private>) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(input.as_bytes()).unwrap();
    let der = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
    let raw = [
        der.r().to_vec_padded(32).unwrap(),
        der.s().to_vec_padded(32).unwrap(),
    ]
    .concat();
    format!("{input}.{}", B64.encode(raw))
}

#[test]
fn public_verifier_preserves_original_bytes_but_is_not_a_profile_gate() {
    PROVIDER.install_default().unwrap();
    assert!(PROVIDER.install_default().is_err());
    let f: Value = serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap();
    let validation = non_jwt_validation();
    assert_eq!(validation.algorithms, vec![Algorithm::ES256]);
    let wrong = DecodingKey::from_ec_der(
        &fixture_public(&f["trusted"]["wrong_jwk"])
            .public_key_to_der()
            .unwrap(),
    );
    for (name, key_name) in [
        ("issuer", "issuer_jwk"),
        ("execution", "agent_jwk"),
        ("possession", "agent_jwk"),
    ] {
        let artifact = &f[name];
        let token = artifact["jws"].as_str().unwrap();
        let key = DecodingKey::from_ec_der(
            &fixture_public(&f["trusted"][key_name])
                .public_key_to_der()
                .unwrap(),
        );
        let default_error =
            jsonwebtoken::decode::<Value>(token, &key, &Validation::new(Algorithm::ES256))
                .unwrap_err();
        assert_eq!(
            default_error.kind(),
            &ErrorKind::MissingRequiredClaim("exp".into())
        );
        let before = SEEN.lock().unwrap().len();
        let decoded = jsonwebtoken::decode::<Value>(token, &key, &validation).unwrap();
        assert_eq!(decoded.claims, artifact["payload"]);
        let (input, _) = token.rsplit_once('.').unwrap();
        let seen = SEEN.lock().unwrap();
        assert_eq!(seen.len(), before + 1);
        assert_eq!(seen[before], input.as_bytes());
        assert_eq!(
            input,
            format!(
                "{}.{}",
                B64.encode(artifact["header_bytes"].as_str().unwrap()),
                B64.encode(artifact["canonical_payload"].as_str().unwrap())
            )
        );
        drop(seen);
        assert!(jsonwebtoken::decode::<Value>(token, &wrong, &validation).is_err());
        let parts: Vec<_> = token.split('.').collect();
        let payload = artifact["canonical_payload"].as_str().unwrap();
        assert_eq!(payload.matches("vollmacht-local-es256-v1").count(), 1);
        let changed = payload.replace("vollmacht-local-es256-v1", "vollmacht-local-es256-v0");
        let tampered = format!("{}.{}.{}", parts[0], B64.encode(changed), parts[2]);
        assert!(jsonwebtoken::decode::<Value>(&tampered, &key, &validation).is_err());
        for length in [0, 63, 64, 65] {
            let mut raw = B64.decode(parts[2]).unwrap();
            raw[0] ^= 1;
            raw.resize(length, 0);
            let tampered = format!("{}.{}.{}", parts[0], parts[1], B64.encode(raw));
            assert!(jsonwebtoken::decode::<Value>(&tampered, &key, &validation).is_err());
        }
        let changed_header = artifact["header_bytes"]
            .as_str()
            .unwrap()
            .replace("ES256", "ES384");
        let bad_alg = format!("{}.{}.{}", B64.encode(changed_header), parts[1], parts[2]);
        let before = SEEN.lock().unwrap().len();
        assert_eq!(
            jsonwebtoken::decode::<Value>(&bad_alg, &key, &validation)
                .unwrap_err()
                .kind(),
            &ErrorKind::InvalidAlgorithm
        );
        assert_eq!(SEEN.lock().unwrap().len(), before);
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let key = DecodingKey::from_ec_der(&private.public_key_to_der().unwrap());
    let expected = f["execution"]["header_bytes"].as_str().unwrap();
    let payload = f["execution"]["canonical_payload"].as_str().unwrap();
    let header_value: Value = serde_json::from_str(expected).unwrap();
    let typ = serde_json::to_string(&header_value["typ"]).unwrap();
    let kid = serde_json::to_string(&header_value["kid"]).unwrap();
    let baseline = signed_variant(expected, payload, &private);
    assert_eq!(
        jsonwebtoken::decode::<Value>(&baseline, &key, &validation)
            .unwrap()
            .claims,
        f["execution"]["payload"]
    );
    // Each header case changes only one dimension of the actual fixture header;
    // all keep the original fixture payload unchanged.
    for header in [
        format!(r#"{{"typ":"wrong","alg":"ES256","kid":{kid}}}"#),
        format!(r#"{{"typ":{typ},"alg":"ES256","kid":"wrong"}}"#),
        format!(r#"{{"typ":{typ},"alg":"ES256","kid":{kid},"extra":true}}"#),
        format!(r#"{{"typ":{typ},"alg":"ES256","kid":{kid},"crit":["unsupported"]}}"#),
        format!(r#"{{"alg":"ES256","kid":{kid},"typ":{typ}}}"#),
    ] {
        let token = signed_variant(&header, payload, &private);
        let decoded = jsonwebtoken::decode::<Value>(&token, &key, &validation).unwrap();
        assert_ne!(header, expected);
        assert_eq!(decoded.claims, f["execution"]["payload"]);
    }
    // Payload policy gaps are separate from header permissiveness.
    for (field, value) in [
        ("crypto_profile", Value::from("unknown")),
        ("expires_at", Value::from(0)),
    ] {
        let mut changed = f["execution"]["payload"].clone();
        changed[field] = value.clone();
        let token = signed_variant(
            expected,
            &serde_json::to_string(&changed).unwrap(),
            &private,
        );
        let decoded = jsonwebtoken::decode::<Value>(&token, &key, &validation).unwrap();
        assert_eq!(decoded.claims, changed);
        assert_eq!(decoded.claims[field], value);
    }
    // Valid signatures isolate parser behavior from cryptographic failures.
    let duplicate_header = signed_variant(
        &expected.replace(r#""alg":"ES256""#, r#""alg":"ES256","alg":"ES256""#),
        payload,
        &private,
    );
    assert!(jsonwebtoken::decode::<Value>(&duplicate_header, &key, &validation).is_err());
    let duplicate_payload = signed_variant(
        expected,
        &payload.replace(
            r#""crypto_profile":"vollmacht-local-es256-v1""#,
            r#""crypto_profile":"unknown","crypto_profile":"vollmacht-local-es256-v1""#,
        ),
        &private,
    );
    assert_eq!(
        jsonwebtoken::decode::<Value>(&duplicate_payload, &key, &validation)
            .unwrap()
            .claims["crypto_profile"],
        "vollmacht-local-es256-v1"
    );
    // Registered JWT claim validation is root-only. Neither these settings nor
    // JWT defaults understand Vollmacht's expires_at or nested approval scope.
    let root_exp = signed_variant(expected, r#"{"exp":0}"#, &private);
    assert!(jsonwebtoken::decode::<Value>(&root_exp, &key, &validation).is_ok());
    assert_eq!(
        jsonwebtoken::decode::<Value>(&root_exp, &key, &Validation::new(Algorithm::ES256))
            .unwrap_err()
            .kind(),
        &ErrorKind::ExpiredSignature
    );
    let nested_exp = signed_variant(expected, r#"{"payload":{"exp":0}}"#, &private);
    assert_eq!(
        jsonwebtoken::decode::<Value>(&nested_exp, &key, &Validation::new(Algorithm::ES256))
            .unwrap_err()
            .kind(),
        &ErrorKind::MissingRequiredClaim("exp".into())
    );
    let mut optional_exp = validation.clone();
    optional_exp.validate_exp = true;
    assert!(jsonwebtoken::decode::<Value>(&nested_exp, &key, &optional_exp).is_ok());
    for bad_der in [b"".as_slice(), b"not-a-public-key"] {
        assert!(
            jsonwebtoken::decode::<Value>(
                &root_exp,
                &DecodingKey::from_ec_der(bad_der),
                &validation
            )
            .is_err()
        );
    }
    // These field/byte comparisons characterize missing application gates;
    // they are not an implementation of those gates or acceptance policy.
}
