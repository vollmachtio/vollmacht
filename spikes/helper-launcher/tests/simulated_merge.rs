//! Test-only integrated execution simulation. Fixed public signed fixtures and
//! an in-memory approved record are setup, not enrollment or issuer provisioning.
//! No GitHub client, credentials, durable state, hardware or runtime fallback.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use vollmacht_core::{
    AgentPublicKey, CompactRole, MandateEnvelope, SyntaxCheckedClientData, UnverifiedPayload,
    VerificationBinding, VerificationRuntime, envelope_digest, mandate_digest, operation_digest,
};
use vollmacht_helper_probe::{Coordinator, Launch, Request};

const FIXTURE: &str = include_str!("../../canonicalization/fixtures/candidate-profile-vector.json");
const NOW: u64 = 1_800_000_061;

#[derive(Debug, PartialEq, Eq)]
enum Denial {
    Signature,
    Record,
    Evidence,
    Proof,
    State,
    Stale,
    Replay,
}

// This deliberately is NOT a production store or dispatch permit. Test setup
// selects the fixture's clock, registry, session and fixed pending challenge.
struct Simulation {
    approved: bool,
    enabled: bool,
    policy: u64,
    now: u64,
    challenge_used: bool,
    pending_challenge: String,
    reserved: bool,
    expected_head: String,
    dispatches: Vec<Value>,
}
impl Simulation {
    fn fresh() -> Self {
        Self {
            approved: true,
            enabled: true,
            policy: 1,
            now: NOW,
            challenge_used: false,
            pending_challenge: B64.encode([12; 32]),
            reserved: false,
            expected_head: "a".repeat(40),
            dispatches: Vec::new(),
        }
    }
}

struct Harness {
    fixture: Value,
    credential: Value,
    launch: Launch,
    runtime: VerificationRuntime,
    issuer: VerificationBinding,
    agent: VerificationBinding,
    approved_envelope: MandateEnvelope,
}
impl Harness {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../simplewebauthn")
            .canonicalize()
            .unwrap();
        let node = PathBuf::from(
            std::env::var_os("VOLLMACHT_TEST_NODE")
                .expect("required pinned VOLLMACHT_TEST_NODE executable"),
        );
        assert!(
            node.is_absolute() && node.is_file(),
            "absolute pinned Node executable required"
        );
        let version = Command::new(&node)
            .arg("--version")
            .env_clear()
            .output()
            .unwrap();
        assert!(version.status.success());
        assert_eq!(version.stdout, b"v24.21.0\n");
        let context = Command::new(&node)
            .arg(directory.join("simulation-context.mjs"))
            .env_clear()
            .output()
            .unwrap();
        assert!(
            context.status.success(),
            "trusted fixture context adapter failed"
        );
        assert!(context.stderr.is_empty() && context.stdout.len() <= 8192);
        let credential = serde_json::from_slice(&context.stdout).unwrap();
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let public = |role: &str| {
            AgentPublicKey::parse(&serde_json::to_vec(&fixture["trusted"][role]).unwrap()).unwrap()
        };
        let issuer = VerificationBinding::new(
            CompactRole::Issuer,
            fixture["approval"]["issuer_id"].as_str().unwrap(),
            &public("issuer_jwk"),
        )
        .unwrap();
        let agent = VerificationBinding::new(
            CompactRole::Execution,
            fixture["approval"]["agent_jkt"].as_str().unwrap(),
            &public("agent_jwk"),
        )
        .unwrap();
        let approved_envelope = MandateEnvelope::parse_canonical(
            fixture["issuer"]["canonical_payload"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        Self {
            fixture,
            credential,
            launch: Launch {
                executable: node,
                launcher: PathBuf::from(env!("CARGO_BIN_EXE_vollmacht-helper-launcher")),
                helper: Some(directory.join("helper.mjs")),
                directory,
            },
            runtime: VerificationRuntime::initialize().unwrap(),
            issuer,
            agent,
            approved_envelope,
        }
    }

    fn evidence(&self, envelope: &MandateEnvelope, credential: Value) -> Result<(), Denial> {
        let e = envelope.evidence();
        let bytes = B64
            .decode(e["client_data_json"].as_str().unwrap())
            .map_err(|_| Denial::Evidence)?;
        SyntaxCheckedClientData::parse(&bytes).map_err(|_| Denial::Evidence)?;
        let challenge =
            B64.encode(mandate_digest(envelope.approval()).map_err(|_| Denial::Evidence)?);
        let request = json!({"version":1,"kind":"verify_assertion","request_id":"abababababababababababababababab", "challenge":challenge,"rp_id":"localhost","origin":"http://localhost:8374","credential":credential,
            "assertion":{"id":e["credential_id"],"raw_id":e["credential_id"],"type":"public-key","client_data_json":e["client_data_json"],"authenticator_data":e["authenticator_data"],"signature":e["signature"],"user_handle":e["user_handle"]}});
        let request =
            Request::parse(&serde_json::to_vec(&request).unwrap()).map_err(|_| Denial::Evidence)?;
        let coordinator = Coordinator::new(request, Instant::now() + Duration::from_secs(5));
        let result = coordinator
            .verify(self.launch.clone())
            .map_err(|_| Denial::Evidence)?;
        if result.new_counter != 1 || result.backup_eligible || result.backed_up {
            return Err(Denial::Evidence);
        }
        Ok(())
    }

    fn execute(
        &self,
        state: &mut Simulation,
        issuer: &[u8],
        proof: &[u8],
        credential: Value,
    ) -> Result<(), Denial> {
        if state.reserved || state.challenge_used {
            return Err(Denial::Replay);
        }
        let signed = self
            .runtime
            .verify(issuer, &self.issuer)
            .map_err(|_| Denial::Signature)?;
        let UnverifiedPayload::Issuer(envelope) = signed.artifact().payload() else {
            return Err(Denial::Record);
        };
        // Exact approved bytes bind every identity, profile and operation field.
        // This record was installed by trusted TEST SETUP, never artifact input.
        if !state.approved || envelope.canonical_bytes() != self.approved_envelope.canonical_bytes()
        {
            return Err(Denial::Record);
        }
        self.evidence(envelope, credential)?;
        let approval = envelope.approval().fields();
        // This test models a claimed matching execution attempt. Once proof
        // processing starts every outcome consumes it, including later policy,
        // registry, clock or metadata failures. Pre-proof rejection is separate.
        state.challenge_used = true;
        let signed = match self.runtime.verify(proof, &self.agent) {
            Ok(value) => value,
            Err(_) => {
                state.challenge_used = true;
                return Err(Denial::Proof);
            }
        };
        let UnverifiedPayload::Execution(proof) = signed.artifact().payload() else {
            return Err(Denial::Proof);
        };
        let fields = proof.fields();
        let expected = &self.fixture["execution"]["payload"];
        let matches = fields["mandate_digest"]
            == B64.encode(mandate_digest(envelope.approval()).unwrap())
            && fields["operation_digest"]
                == B64.encode(operation_digest(envelope.approval()).unwrap())
            && fields["envelope_digest"] == B64.encode(envelope_digest(envelope).unwrap())
            && fields["audience"] == approval["audience"]
            && fields["crypto_profile"] == approval["crypto_profile"]
            && fields["challenge"] == state.pending_challenge
            && fields["issued_at"] == expected["issued_at"]
            && fields["expires_at"] == expected["expires_at"];
        if !matches {
            state.challenge_used = true;
            return Err(Denial::Proof);
        }
        // Failed proof attempts, including proof time failures, consume the
        // pending challenge. Other pre-proof denials do not simulate a retry
        // policy or mint a replacement challenge.
        if state.now < fields["issued_at"].as_u64().unwrap()
            || state.now >= fields["expires_at"].as_u64().unwrap()
        {
            state.challenge_used = true;
            return Err(Denial::State);
        }
        if !state.enabled
            || state.policy != approval["policy_revision"].as_u64().unwrap()
            || state.now < approval["issued_at"].as_u64().unwrap()
            || state.now >= approval["expires_at"].as_u64().unwrap()
        {
            return Err(Denial::State);
        }
        let operation = &approval["operation"];
        if operation["constraints"]["expected_head_sha"] != state.expected_head {
            return Err(Denial::Stale);
        }
        // One synchronous simulated transaction, with no await or external call.
        // No persistence, crash safety or concurrent-store guarantee is claimed.
        state.challenge_used = true;
        state.reserved = true;
        state.dispatches.push(json!({"method":"PUT","repository_id":operation["resource"]["repository_id"],"pull_request_number":operation["resource"]["pull_request_number"],"body":{"sha":operation["constraints"]["expected_head_sha"],"merge_method":operation["constraints"]["merge_method"]}}));
        Ok(())
    }
}

#[test]
fn real_verifiers_gate_one_simulated_merge_and_deny_replays_and_faults() {
    let h = Harness::new();
    let issuer = h.fixture["issuer"]["jws"].as_str().unwrap().as_bytes();
    let proof = h.fixture["execution"]["jws"].as_str().unwrap().as_bytes();
    let mut state = Simulation::fresh();
    assert_eq!(
        h.execute(&mut state, issuer, proof, h.credential.clone()),
        Ok(())
    );
    assert_eq!(
        state.dispatches,
        vec![
            json!({"method":"PUT","repository_id":"12345","pull_request_number":42,"body":{"sha":"a".repeat(40),"merge_method":"squash"}})
        ]
    );
    assert_eq!(
        h.execute(&mut state, issuer, proof, h.credential.clone()),
        Err(Denial::Replay)
    );
    assert_eq!(state.dispatches.len(), 1);
    let mut wrong_pending = Simulation::fresh();
    wrong_pending.pending_challenge = B64.encode([13; 32]);
    // The proof still has a valid enrolled-agent signature. It is rejected for
    // mismatch with independently selected pending context, not bad crypto.
    assert_eq!(
        h.execute(&mut wrong_pending, issuer, proof, h.credential.clone()),
        Err(Denial::Proof)
    );
    assert!(wrong_pending.challenge_used && wrong_pending.dispatches.is_empty());
    assert_eq!(
        h.execute(&mut wrong_pending, issuer, proof, h.credential.clone()),
        Err(Denial::Replay)
    );
    // Retained evidence checks use original counter context, not the updated 1.
    assert_eq!(
        h.evidence(&h.approved_envelope, h.credential.clone()),
        Ok(())
    );
    let mut advanced = h.credential.clone();
    advanced["counter"] = json!(1);
    assert_eq!(
        h.evidence(&h.approved_envelope, advanced.clone()),
        Err(Denial::Evidence)
    );
    let mut state = Simulation::fresh();
    assert_eq!(
        h.execute(&mut state, issuer, proof, advanced),
        Err(Denial::Evidence)
    );
    assert!(state.dispatches.is_empty());
    for (change, expected) in [
        (0, Denial::Record),
        (1, Denial::State),
        (2, Denial::State),
        (3, Denial::State),
        (4, Denial::Stale),
        (5, Denial::State),
        (6, Denial::State),
    ] {
        let mut state = Simulation::fresh();
        match change {
            0 => state.approved = false,
            1 => state.enabled = false,
            2 => state.policy = 2,
            3 => state.now += 30,
            4 => state.expected_head = "b".repeat(40),
            5 => state.now = h.fixture["approval"]["expires_at"].as_u64().unwrap(),
            _ => state.now = h.fixture["approval"]["issued_at"].as_u64().unwrap() - 1,
        }
        assert_eq!(
            h.execute(&mut state, issuer, proof, h.credential.clone()),
            Err(expected)
        );
        assert!(state.dispatches.is_empty());
        if change != 0 {
            assert!(state.challenge_used);
            // Restoring simulated policy/status/time/metadata never revives
            // the claimed challenge. A new challenge is not created here.
            state.enabled = true;
            state.policy = 1;
            state.now = NOW;
            state.expected_head = "a".repeat(40);
            assert_eq!(
                h.execute(&mut state, issuer, proof, h.credential.clone()),
                Err(Denial::Replay)
            );
            assert!(state.dispatches.is_empty());
        }
    }
    let corrupt = |bytes: &[u8]| {
        let mut b = bytes.to_vec();
        let p = b.iter().rposition(|c| *c == b'.').unwrap() + 1;
        b[p] = if b[p] == b'A' { b'B' } else { b'A' };
        b
    };
    let mut state = Simulation::fresh();
    assert_eq!(
        h.execute(&mut state, &corrupt(issuer), proof, h.credential.clone()),
        Err(Denial::Signature)
    );
    assert!(state.dispatches.is_empty());
    let mut state = Simulation::fresh();
    assert_eq!(
        h.execute(&mut state, issuer, &corrupt(proof), h.credential.clone()),
        Err(Denial::Proof)
    );
    assert_eq!(
        h.execute(&mut state, issuer, proof, h.credential.clone()),
        Err(Denial::Replay)
    );
    assert!(state.dispatches.is_empty());
}
