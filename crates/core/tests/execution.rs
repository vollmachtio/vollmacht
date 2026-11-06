//! Independent signed fixtures with a fake evidence boundary, not an executor.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};
use vollmacht_core::{
    AgentPublicKey, AssertionRecheckResult, EvidenceRecheckError, EvidenceRecheckRequest,
    EvidenceRechecker, ExecutionContext, ExecutionTime, ExecutionTrust, MandateEnvelope,
    OriginalCredential, PendingExecution, VerificationRuntime, verify_claimed_attempt,
};

const NOW: u64 = 1_800_000_061;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../spikes/canonicalization/fixtures/candidate-profile-vector.json"
    ))
    .unwrap()
}
fn key(name: &str) -> AgentPublicKey {
    AgentPublicKey::parse(&serde_json::to_vec(&fixture()["trusted"][name]).unwrap()).unwrap()
}
fn envelope() -> MandateEnvelope {
    MandateEnvelope::parse_canonical(
        fixture()["issuer"]["canonical_payload"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap()
}
fn trust(now: Instant) -> ExecutionTrust {
    let f = fixture();
    let a = &f["approval"];
    let s = |name: &str| a[name].as_str().unwrap().to_owned();
    ExecutionTrust {
        issuer_kid: s("issuer_id"),
        issuer_id: s("issuer_id"),
        principal_id: s("principal_id"),
        credential_id: s("credential_id"),
        agent_jkt: s("agent_jkt"),
        audience: s("audience"),
        crypto_profile: s("crypto_profile"),
        policy_revision: 1,
        registry_revisions: [1, 2, 3, 4],
        enabled: [true; 4],
        session_id: "abababababababababababababababab".into(),
        approval_deadline: now + Duration::from_secs(59),
    }
}
fn pending(now: Instant) -> PendingExecution {
    let f = fixture();
    let p = &f["execution"]["payload"];
    let s = |name: &str| p[name].as_str().unwrap().to_owned();
    PendingExecution {
        challenge: s("challenge"),
        mandate_digest: s("mandate_digest"),
        operation_digest: s("operation_digest"),
        envelope_digest: s("envelope_digest"),
        issued_at: p["issued_at"].as_u64().unwrap(),
        expires_at: p["expires_at"].as_u64().unwrap(),
        deadline: now + Duration::from_secs(29),
    }
}
fn credential() -> OriginalCredential {
    OriginalCredential {
        public_key:"pQECAyYgASFYIL2_8Ph4poaew3QADVDs4RT7czgMAYoF0FBxWbo1_PS7Ilgg6BQzrKwlIHSF8lIZThcaIYyZuPFbvMpu4ntylGG6BE8".into(),
        counter:0, user_handle:"AA".into(), backup_eligible:false, backed_up:false, expected_counter:1, expected_backed_up:false,
    }
}
fn context(now: Instant) -> ExecutionContext {
    ExecutionContext::new(
        envelope(),
        trust(now),
        pending(now),
        credential(),
        &key("issuer_jwk"),
        &key("agent_jwk"),
    )
    .unwrap()
}
fn clock(now: Instant) -> ExecutionTime {
    ExecutionTime {
        wall_seconds: NOW,
        monotonic: now,
        session_id: "abababababababababababababababab".into(),
    }
}
struct Evidence {
    calls: Cell<usize>,
    mode: u8,
}
impl EvidenceRechecker for Evidence {
    fn recheck(
        &self,
        request: &EvidenceRecheckRequest,
    ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(
            request.envelope().canonical_bytes(),
            envelope().canonical_bytes()
        );
        assert_eq!(
            request.webauthn_challenge(),
            "cPADub8ZYk9k4lytHWn0RCCKrzTZhTnW0oAeVlhGmjg"
        );
        assert_eq!(
            request.credential().counter,
            0,
            "use original verification context"
        );
        if self.mode == 1 {
            return Err(EvidenceRecheckError);
        }
        Ok(AssertionRecheckResult {
            new_counter: if self.mode == 2 { 2 } else { 1 },
            backup_eligible: self.mode == 3,
            backed_up: self.mode == 4,
        })
    }
}

#[test]
fn trusted_context_rejects_substituted_record_and_key_bindings() {
    let now = Instant::now();
    for field in 0..9 {
        let mut t = trust(now);
        match field {
            0 => t.issuer_id = "9".repeat(32),
            1 => t.principal_id = "9".repeat(32),
            2 => t.credential_id = "AQ".into(),
            3 => t.agent_jkt = B64.encode([9; 32]),
            4 => t.audience = "9".repeat(32),
            5 => t.crypto_profile = "other".into(),
            6 => t.policy_revision = 2,
            7 => t.enabled[2] = false,
            _ => t.issuer_kid = "invalid".into(),
        }
        assert!(
            ExecutionContext::new(
                envelope(),
                t,
                pending(now),
                credential(),
                &key("issuer_jwk"),
                &key("agent_jwk")
            )
            .is_err(),
            "field {field}"
        );
    }
    for field in 0..3 {
        let mut p = pending(now);
        match field {
            0 => p.mandate_digest = B64.encode([9; 32]),
            1 => p.operation_digest = B64.encode([9; 32]),
            _ => p.envelope_digest = B64.encode([9; 32]),
        };
        assert!(
            ExecutionContext::new(
                envelope(),
                trust(now),
                p,
                credential(),
                &key("issuer_jwk"),
                &key("agent_jwk")
            )
            .is_err()
        );
    }
    assert!(
        ExecutionContext::new(
            envelope(),
            trust(now),
            pending(now),
            credential(),
            &key("issuer_jwk"),
            &key("wrong_jwk")
        )
        .is_err()
    );
}

#[test]
fn real_signatures_require_context_time_and_exact_evidence_result() {
    let runtime = VerificationRuntime::initialize().unwrap();
    let f = fixture();
    let issuer = f["issuer"]["jws"].as_str().unwrap().as_bytes();
    let proof = f["execution"]["jws"].as_str().unwrap().as_bytes();
    let now = Instant::now();
    let context = context(now);
    let good = Evidence {
        calls: Cell::new(0),
        mode: 0,
    };
    let checked =
        verify_claimed_attempt(&runtime, &context, issuer, proof, &good, clock(now)).unwrap();
    assert_eq!(checked.operation(), &f["approval"]["operation"]);
    assert_eq!(good.calls.get(), 1);
    assert_eq!(checked.proof_issued_at(), 1_800_000_060);
    assert_eq!(checked.proof_expires_at(), 1_800_000_090);
    assert_eq!(checked.context().trust().registry_revisions, [1, 2, 3, 4]);
    assert!(std::ptr::eq(checked.context(), &context));
    for mode in 1..=4 {
        let helper = Evidence {
            calls: Cell::new(0),
            mode,
        };
        assert!(
            verify_claimed_attempt(&runtime, &context, issuer, proof, &helper, clock(now)).is_err()
        );
        assert_eq!(helper.calls.get(), 1);
    }
    for wall in [1_800_000_000, 1_800_000_090, 1_800_000_120] {
        let mut time = clock(now);
        time.wall_seconds = wall;
        assert!(verify_claimed_attempt(&runtime, &context, issuer, proof, &good, time).is_err());
    }
    let mut expired = clock(now);
    expired.monotonic = now + Duration::from_secs(29);
    let calls = good.calls.get();
    assert!(verify_claimed_attempt(&runtime, &context, issuer, proof, &good, expired).is_err());
    assert_eq!(good.calls.get(), calls);
    let mut other_session = clock(now);
    other_session.session_id = "other-session".into();
    assert!(
        verify_claimed_attempt(&runtime, &context, issuer, proof, &good, other_session).is_err()
    );
    assert_eq!(good.calls.get(), calls);
    let corrupt = |bytes: &[u8]| {
        let mut out = bytes.to_vec();
        let i = out.iter().rposition(|b| *b == b'.').unwrap() + 1;
        out[i] = if out[i] == b'A' { b'B' } else { b'A' };
        out
    };
    assert!(
        verify_claimed_attempt(
            &runtime,
            &context,
            &corrupt(issuer),
            proof,
            &good,
            clock(now)
        )
        .is_err()
    );
    assert_eq!(good.calls.get(), calls, "bad issuer never invokes helper");
    assert!(
        verify_claimed_attempt(
            &runtime,
            &context,
            issuer,
            &corrupt(proof),
            &good,
            clock(now)
        )
        .is_err()
    );
    let mut wrong_pending = pending(now);
    wrong_pending.challenge = B64.encode([9; 32]);
    let different = ExecutionContext::new(
        envelope(),
        trust(now),
        wrong_pending,
        credential(),
        &key("issuer_jwk"),
        &key("agent_jwk"),
    )
    .unwrap();
    assert!(
        verify_claimed_attempt(&runtime, &different, issuer, proof, &good, clock(now)).is_err()
    );
    let wrong_issuer = ExecutionContext::new(
        envelope(),
        trust(now),
        pending(now),
        credential(),
        &key("wrong_jwk"),
        &key("agent_jwk"),
    )
    .unwrap();
    assert!(
        verify_claimed_attempt(&runtime, &wrong_issuer, issuer, proof, &good, clock(now)).is_err()
    );
    shorter_signed_window(&runtime, now);
}

fn shorter_signed_window(runtime: &VerificationRuntime, now: Instant) {
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey},
        ecdsa::EcdsaSig,
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        sign::Signer,
    };
    use vollmacht_core::{envelope_digest, mandate_digest, operation_digest};
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
        .unwrap();
    let public = AgentPublicKey::parse(&serde_json::to_vec(&serde_json::json!({"kty":"EC","crv":"P-256","x":B64.encode(x.to_vec_padded(32).unwrap()),"y":B64.encode(y.to_vec_padded(32).unwrap())})).unwrap()).unwrap();
    let private = PKey::from_ec_key(ec).unwrap();
    let jkt = B64.encode(public.thumbprint().unwrap());
    let f = fixture();
    let mut e: Value =
        serde_json::from_str(f["issuer"]["canonical_payload"].as_str().unwrap()).unwrap();
    e["payload"]["agent_jkt"] = Value::from(jkt.clone());
    let envelope = MandateEnvelope::parse_canonical(&serde_jcs::to_vec(&e).unwrap()).unwrap();
    let mut t = trust(now);
    t.agent_jkt = jkt.clone();
    let mut p = pending(now);
    p.mandate_digest = B64.encode(mandate_digest(envelope.approval()).unwrap());
    p.operation_digest = B64.encode(operation_digest(envelope.approval()).unwrap());
    p.envelope_digest = B64.encode(envelope_digest(&envelope).unwrap());
    let mut proof = f["execution"]["payload"].clone();
    proof["mandate_digest"] = Value::from(p.mandate_digest.clone());
    proof["operation_digest"] = Value::from(p.operation_digest.clone());
    proof["envelope_digest"] = Value::from(p.envelope_digest.clone());
    proof["issued_at"] = Value::from(NOW);
    proof["expires_at"] = Value::from(NOW + 1);
    let sign = |typ: &str, kid: &str, payload: &Value| {
        let header = format!("{{\"typ\":\"{typ}\",\"alg\":\"ES256\",\"kid\":\"{kid}\"}}");
        let input = format!(
            "{}.{}",
            B64.encode(header),
            B64.encode(serde_jcs::to_vec(payload).unwrap())
        );
        let mut signer = Signer::new(MessageDigest::sha256(), &private).unwrap();
        signer.update(input.as_bytes()).unwrap();
        let sig = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
        format!(
            "{input}.{}",
            B64.encode(
                [
                    sig.r().to_vec_padded(32).unwrap(),
                    sig.s().to_vec_padded(32).unwrap()
                ]
                .concat()
            )
        )
    };
    let issuer = sign("vollmacht-mandate+jws", &t.issuer_kid, &e);
    let proof = sign("vollmacht-execution+jws", &jkt, &proof);
    let context = ExecutionContext::new(envelope, t, p, credential(), &public, &public).unwrap();
    // This test isolates proof timing with deliberately fake evidence, not a
    // valid fresh WebAuthn ceremony or production signer.
    struct FakeEvidence;
    impl EvidenceRechecker for FakeEvidence {
        fn recheck(
            &self,
            _: &EvidenceRecheckRequest,
        ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
            Ok(AssertionRecheckResult {
                new_counter: 1,
                backup_eligible: false,
                backed_up: false,
            })
        }
    }
    let candidate = verify_claimed_attempt(
        runtime,
        &context,
        issuer.as_bytes(),
        proof.as_bytes(),
        &FakeEvidence,
        clock(now),
    )
    .unwrap();
    assert_eq!(candidate.proof_issued_at(), NOW);
    assert_eq!(candidate.proof_expires_at(), NOW + 1);
    assert!(candidate.proof_expires_at() < candidate.context().pending().expires_at);
    let mut expired = clock(now);
    expired.wall_seconds = NOW + 1;
    assert!(
        verify_claimed_attempt(
            runtime,
            &context,
            issuer.as_bytes(),
            proof.as_bytes(),
            &FakeEvidence,
            expired
        )
        .is_err()
    );
}

#[test]
fn constructor_bounds_trusted_context_without_claiming_storage_provenance() {
    let now = Instant::now();
    for case in 0..17 {
        let mut t = trust(now);
        let mut p = pending(now);
        let mut c = credential();
        match case {
            0 => p.expires_at = p.issued_at,
            1 => p.expires_at = p.issued_at - 1,
            2 => p.expires_at = p.issued_at + 31,
            3 => p.issued_at = 1_799_999_999,
            4 => {
                p.issued_at = 1_800_000_110;
                p.expires_at = 1_800_000_121;
            }
            5 => p.deadline = t.approval_deadline + Duration::from_secs(1),
            6 => p.challenge.push('='),
            7 => c.public_key = String::new(),
            8 => c.user_handle = String::new(),
            9 => c.user_handle = B64.encode([0; 65]),
            10 => t.session_id = "invalid".into(),
            11 => t.registry_revisions[0] = 0,
            12 => t.registry_revisions[3] = 9_007_199_254_740_992,
            13 => c.backed_up = true,
            14 => c.expected_backed_up = true,
            15 => c.counter = c.expected_counter,
            _ => c.counter = c.expected_counter + 1,
        }
        assert!(
            ExecutionContext::new(envelope(), t, p, c, &key("issuer_jwk"), &key("agent_jwk"))
                .is_err(),
            "case {case}"
        );
    }
    let mut zero = credential();
    zero.expected_counter = 0;
    assert!(
        ExecutionContext::new(
            envelope(),
            trust(now),
            pending(now),
            zero,
            &key("issuer_jwk"),
            &key("agent_jwk")
        )
        .is_ok()
    );
}
