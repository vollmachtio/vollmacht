//! Revised candidate fixture comparisons, not a production profile validator.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::sha::sha256;
use serde_json::Value;

const PROFILE: &str = "vollmacht-local-es256-v1";
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/candidate-profile-vector.json")).unwrap()
}
fn digest(domain: &[u8], value: &Value) -> String {
    B64.encode(sha256(
        &[domain, &serde_jcs::to_vec(value).unwrap()].concat(),
    ))
}

#[test]
fn all_four_profile_fields_match_trusted_context_and_canonical_bytes() {
    let f = fixture();
    assert_eq!(f["trusted"]["installation_profile"], PROFILE);
    assert_eq!(f["trusted"]["pending_profile"], PROFILE);
    for (value, bytes) in [
        (&f["approval"], &f["canonical_approval"]),
        (&f["proposal"], &f["canonical_proposal"]),
        (
            &f["execution"]["payload"],
            &f["execution"]["canonical_payload"],
        ),
        (
            &f["possession"]["payload"],
            &f["possession"]["canonical_payload"],
        ),
    ] {
        assert_eq!(value["version"], 1);
        assert_eq!(value["crypto_profile"], PROFILE);
        assert_eq!(
            serde_jcs::to_vec(value).unwrap(),
            bytes.as_str().unwrap().as_bytes()
        );
        for replacement in [
            None,
            Some("unknown-profile"),
            Some("vollmacht-local-es256-v0"),
        ] {
            let mut changed = value.clone();
            if let Some(profile) = replacement {
                changed["crypto_profile"] = Value::from(profile);
            } else {
                changed.as_object_mut().unwrap().remove("crypto_profile");
            }
            assert_ne!(
                changed["crypto_profile"],
                f["trusted"]["installation_profile"]
            );
            assert_ne!(changed["crypto_profile"], f["trusted"]["pending_profile"]);
            assert_ne!(
                serde_jcs::to_vec(&changed).unwrap(),
                serde_jcs::to_vec(value).unwrap()
            );
        }
        // Even a recognized profile is insufficient if trusted pending disagrees.
        assert_ne!(value["crypto_profile"], "different-pending-profile");
    }
    assert!(f["issuer"]["payload"].get("crypto_profile").is_none());
    assert_eq!(f["issuer"]["payload"]["payload"], f["approval"]);
    let agent = B64.encode(sha256(
        &serde_jcs::to_vec(&f["trusted"]["agent_jwk"]).unwrap(),
    ));
    assert_eq!(f["approval"]["agent_jkt"], agent);
    assert_eq!(f["proposal"]["agent_jkt"], agent);
    assert_eq!(f["possession"]["payload"]["agent_jkt"], agent);
    assert_eq!(f["proposal"]["agent_key"], f["trusted"]["agent_jwk"]);
    for (name, typ, kid) in [
        (
            "issuer",
            "vollmacht-mandate+jws",
            f["approval"]["issuer_id"].as_str().unwrap(),
        ),
        ("execution", "vollmacht-execution+jws", agent.as_str()),
        (
            "possession",
            "vollmacht-agent-enrollment+jws",
            agent.as_str(),
        ),
    ] {
        let expected = format!("{{\"typ\":\"{typ}\",\"alg\":\"ES256\",\"kid\":\"{kid}\"}}");
        assert_eq!(f[name]["header_bytes"], expected);
        assert_eq!(
            serde_jcs::to_vec(&f[name]["payload"]).unwrap(),
            f[name]["canonical_payload"].as_str().unwrap().as_bytes()
        );
    }
}

#[test]
fn profile_is_challenge_bound_and_execution_and_enrollment_links_are_recomputed() {
    let f = fixture();
    let approval = digest(b"vollmacht:mandate:v1\0", &f["approval"]);
    let enrollment = digest(b"vollmacht:admin:enroll-agent:v1\0", &f["proposal"]);
    assert_eq!(approval, f["approval_challenge"]);
    assert_eq!(enrollment, f["enrollment_challenge"]);
    assert_eq!(f["execution"]["payload"]["mandate_digest"], approval);
    assert_eq!(
        f["possession"]["payload"]["authorization_digest"],
        enrollment
    );
    assert_eq!(
        f["execution"]["payload"]["operation_digest"],
        digest(b"vollmacht:operation:v1\0", &f["approval"]["operation"])
    );
    assert_eq!(
        f["execution"]["payload"]["envelope_digest"],
        digest(b"vollmacht:envelope:v1\0", &f["issuer"]["payload"])
    );
    for (body, domain, assertion) in [
        (
            &f["approval"],
            b"vollmacht:mandate:v1\0".as_slice(),
            &f["issuer"]["payload"]["evidence"],
        ),
        (
            &f["proposal"],
            b"vollmacht:admin:enroll-agent:v1\0".as_slice(),
            &f["enrollment_assertion"],
        ),
    ] {
        let client: Value = serde_json::from_slice(
            &B64.decode(assertion["client_data_json"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(client["challenge"], digest(domain, body));
        let mut legacy = body.clone();
        legacy.as_object_mut().unwrap().remove("crypto_profile");
        assert_ne!(client["challenge"], digest(domain, &legacy));
    }
}
