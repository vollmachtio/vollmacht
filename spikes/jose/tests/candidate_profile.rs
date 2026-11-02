//! Independent verification and context comparisons, not production enforcement.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use josekit::{
    jwk::Jwk,
    jws::{self, ES256},
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sha::sha256,
    sign::Verifier,
};
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}
fn verify(artifact: &Value, key: &Value) {
    let verifier = ES256
        .verifier_from_jwk(&Jwk::from_bytes(serde_json::to_vec(key).unwrap()).unwrap())
        .unwrap();
    let compact = artifact["jws"].as_str().unwrap();
    let parts: Vec<_> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        B64.decode(parts[0]).unwrap(),
        artifact["header_bytes"].as_str().unwrap().as_bytes()
    );
    let (body, header) = jws::deserialize_compact(compact, &verifier).unwrap();
    assert_eq!(
        body,
        artifact["canonical_payload"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        artifact["payload"]
    );
    let expected = format!(
        "{{\"typ\":{},\"alg\":\"ES256\",\"kid\":{}}}",
        serde_json::to_string(header.token_type().unwrap()).unwrap(),
        serde_json::to_string(header.key_id().unwrap()).unwrap()
    );
    assert_eq!(artifact["header_bytes"], expected);
    let mut signature = B64.decode(parts[2]).unwrap();
    assert_eq!(signature.len(), 64);
    signature[0] ^= 1;
    assert!(
        jws::deserialize_compact(
            format!("{}.{}.{}", parts[0], parts[1], B64.encode(signature)),
            &verifier
        )
        .is_err()
    );
}

#[test]
fn signed_profile_artifacts_preserve_header_order_and_reject_wrong_key() {
    let f = fixture();
    for (name, key) in [
        ("issuer", "issuer_jwk"),
        ("execution", "agent_jwk"),
        ("possession", "agent_jwk"),
    ] {
        verify(&f[name], &f["trusted"][key]);
        let verifier = ES256
            .verifier_from_jwk(
                &Jwk::from_bytes(serde_json::to_vec(&f["trusted"][key]).unwrap()).unwrap(),
            )
            .unwrap();
        let parts: Vec<_> = f[name]["jws"].as_str().unwrap().split('.').collect();
        let original_payload = f[name]["canonical_payload"].as_str().unwrap();
        assert_eq!(
            original_payload.matches("vollmacht-local-es256-v1").count(),
            1
        );
        let changed_payload =
            original_payload.replace("vollmacht-local-es256-v1", "vollmacht-local-es256-v0");
        let changed: Value = serde_json::from_str(&changed_payload).unwrap();
        let profile = if name == "issuer" {
            &changed["payload"]["crypto_profile"]
        } else {
            &changed["crypto_profile"]
        };
        assert_eq!(profile, "vollmacht-local-es256-v0");
        // Original protected header and signature, changed profile-bearing body.
        assert!(
            jws::deserialize_compact(
                format!("{}.{}.{}", parts[0], B64.encode(changed_payload), parts[2]),
                &verifier,
            )
            .is_err()
        );
        let wrong = ES256
            .verifier_from_jwk(
                &Jwk::from_bytes(serde_json::to_vec(&f["trusted"]["wrong_jwk"]).unwrap()).unwrap(),
            )
            .unwrap();
        assert!(jws::deserialize_compact(f[name]["jws"].as_str().unwrap(), &wrong).is_err());
    }
    let variants = f["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 3);
    for variant in variants {
        verify(variant, &f["trusted"]["agent_jwk"]);
        // Valid signatures do not satisfy the separate exact profile comparison.
        assert_ne!(
            variant["payload"]["crypto_profile"],
            f["trusted"]["pending_profile"]
        );
        assert_ne!(
            variant["payload"]["crypto_profile"],
            f["trusted"]["installation_profile"]
        );
    }
}

#[test]
fn both_synthetic_approval_assertions_verify_original_challenge_bytes() {
    let f = fixture();
    let jwk = &f["trusted"]["credential_jwk"];
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let x = BigNum::from_slice(&B64.decode(jwk["x"].as_str().unwrap()).unwrap()).unwrap();
    let y = BigNum::from_slice(&B64.decode(jwk["y"].as_str().unwrap()).unwrap()).unwrap();
    let public =
        PKey::from_ec_key(EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap())
            .unwrap();
    for (assertion, challenge) in [
        (
            &f["issuer"]["payload"]["evidence"],
            &f["approval_challenge"],
        ),
        (&f["enrollment_assertion"], &f["enrollment_challenge"]),
    ] {
        let client = B64
            .decode(assertion["client_data_json"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&client).unwrap()["challenge"],
            *challenge
        );
        let auth = B64
            .decode(assertion["authenticator_data"].as_str().unwrap())
            .unwrap();
        assert_eq!(auth.len(), 37);
        assert_eq!(&auth[..32], &sha256(b"localhost"));
        assert_eq!(auth[32], 5);
        let input = [auth, sha256(&client).to_vec()].concat();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public).unwrap();
        verifier.update(&input).unwrap();
        assert!(
            verifier
                .verify(
                    &B64.decode(assertion["signature"].as_str().unwrap())
                        .unwrap()
                )
                .unwrap()
        );
    }
}
