//! Real portable checks and helper, with fake claimed state and dispatch only.
//! Historical public fixtures, no GitHub client, durable store or native keys.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use vollmacht_core::{
    AgentPublicKey, AssertionRecheckResult, EvidenceRecheckError, EvidenceRecheckRequest,
    EvidenceRechecker, ExecutionContext, ExecutionTime, ExecutionTrust, MandateEnvelope,
    OriginalCredential, PendingExecution, VerificationRuntime, verify_claimed_attempt,
};
use vollmacht_helper_probe::{Coordinator, Launch, Request};
const FIXTURE: &str = include_str!("../../canonicalization/fixtures/candidate-profile-vector.json");
const NOW: u64 = 1_800_000_061;
const SESSION: &str = "abababababababababababababababab";

struct Helper {
    launch: Launch,
    fail: bool,
}
impl EvidenceRechecker for Helper {
    fn recheck(
        &self,
        r: &EvidenceRecheckRequest,
    ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
        if self.fail {
            return Err(EvidenceRecheckError);
        }
        let e = r.envelope().evidence();
        let c = r.credential();
        let request = json!({"version":1,"kind":"verify_assertion","request_id":"abababababababababababababababab","challenge":r.webauthn_challenge(),"rp_id":r.rp_id(),"origin":r.origin(),
            "credential":{"id":r.credential_id(),"public_key":c.public_key,"counter":c.counter,"user_handle":c.user_handle,"backup_eligible":c.backup_eligible},
            "assertion":{"id":e["credential_id"],"raw_id":e["credential_id"],"type":"public-key","client_data_json":e["client_data_json"],"authenticator_data":e["authenticator_data"],"signature":e["signature"],"user_handle":e["user_handle"]}});
        let request = Request::parse(&serde_json::to_vec(&request).unwrap())
            .map_err(|_| EvidenceRecheckError)?;
        let result = Coordinator::new(
            request,
            r.deadline().min(Instant::now() + Duration::from_secs(5)),
        )
        .verify(self.launch.clone())
        .map_err(|_| EvidenceRecheckError)?;
        Ok(AssertionRecheckResult {
            new_counter: result.new_counter,
            backup_eligible: result.backup_eligible,
            backed_up: result.backed_up,
        })
    }
}
struct Harness {
    fixture: Value,
    credential: Value,
    helper: Helper,
    runtime: VerificationRuntime,
    monotonic: Instant,
}
impl Harness {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../simplewebauthn")
            .canonicalize()
            .unwrap();
        let node = PathBuf::from(
            std::env::var_os("VOLLMACHT_TEST_NODE").expect("pinned Node path required"),
        );
        assert!(node.is_absolute() && node.is_file());
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
            context.status.success() && context.stderr.is_empty() && context.stdout.len() <= 8192
        );
        Self {
            fixture: serde_json::from_str(FIXTURE).unwrap(),
            credential: serde_json::from_slice(&context.stdout).unwrap(),
            helper: Helper {
                launch: Launch {
                    executable: node,
                    launcher: PathBuf::from(env!("CARGO_BIN_EXE_vollmacht-helper-launcher")),
                    helper: Some(directory.join("helper.mjs")),
                    directory,
                },
                fail: false,
            },
            runtime: VerificationRuntime::initialize().unwrap(),
            monotonic: Instant::now(),
        }
    }
    fn context(&self, challenge: Option<String>, counter: u32) -> ExecutionContext {
        let a = &self.fixture["approval"];
        let p = &self.fixture["execution"]["payload"];
        let s = |v: &Value, k: &str| v[k].as_str().unwrap().to_owned();
        let public = |name: &str| {
            AgentPublicKey::parse(&serde_json::to_vec(&self.fixture["trusted"][name]).unwrap())
                .unwrap()
        };
        ExecutionContext::new(
            MandateEnvelope::parse_canonical(
                self.fixture["issuer"]["canonical_payload"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap(),
            ExecutionTrust {
                issuer_kid: s(a, "issuer_id"),
                issuer_id: s(a, "issuer_id"),
                principal_id: s(a, "principal_id"),
                credential_id: s(a, "credential_id"),
                agent_jkt: s(a, "agent_jkt"),
                audience: s(a, "audience"),
                crypto_profile: s(a, "crypto_profile"),
                policy_revision: 1,
                registry_revisions: [1, 2, 3, 4],
                enabled: [true; 4],
                session_id: SESSION.into(),
                approval_deadline: self.monotonic + Duration::from_secs(59),
            },
            PendingExecution {
                challenge: challenge.unwrap_or_else(|| s(p, "challenge")),
                mandate_digest: s(p, "mandate_digest"),
                operation_digest: s(p, "operation_digest"),
                envelope_digest: s(p, "envelope_digest"),
                issued_at: p["issued_at"].as_u64().unwrap(),
                expires_at: p["expires_at"].as_u64().unwrap(),
                deadline: self.monotonic + Duration::from_secs(29),
            },
            OriginalCredential {
                public_key: s(&self.credential, "public_key"),
                counter,
                user_handle: s(&self.credential, "user_handle"),
                backup_eligible: false,
                backed_up: false,
                expected_counter: counter + 1,
                expected_backed_up: false,
            },
            &public("issuer_jwk"),
            &public("agent_jwk"),
        )
        .unwrap()
    }
    fn execute(
        &self,
        state: &mut FakeStore,
        context: &ExecutionContext,
        issuer: &[u8],
        proof: &[u8],
        helper: &Helper,
    ) -> Result<(), Denial> {
        if state.claimed || state.reserved {
            return Err(Denial::Replay);
        }
        if !state.approved {
            return Err(Denial::Record);
        }
        // Fake atomic claim: every later error consumes this attempt. No retry.
        state.claimed = true;
        let candidate = verify_claimed_attempt(
            &self.runtime,
            context,
            issuer,
            proof,
            helper,
            ExecutionTime {
                wall_seconds: state.now,
                monotonic: self.monotonic,
                session_id: SESSION.into(),
            },
        )
        .map_err(|_| Denial::Checks)?;
        let captured = candidate.context();
        let trust = captured.trust();
        // Fake final transaction only. A real coordinator must perform these
        // checks against fresh durable state atomically, not copy this harness.
        if !state.enabled
            || state.policy != trust.policy_revision
            || state.revisions != trust.registry_revisions
            || state.session != trust.session_id
            || state.final_monotonic >= trust.approval_deadline
            || state.final_monotonic >= captured.pending().deadline
            || state.final_wall >= captured.pending().expires_at
            || state.final_wall < captured.pending().issued_at
            || state.final_wall >= candidate.proof_expires_at()
            || state.final_wall < candidate.proof_issued_at()
        {
            return Err(Denial::Changed);
        }
        let operation = candidate.operation();
        if operation["constraints"]["expected_head_sha"] != state.expected_head {
            return Err(Denial::Stale);
        }
        state.reserved = true;
        state.dispatches.push(json!({"method":"PUT","repository_id":operation["resource"]["repository_id"],"pull_request_number":operation["resource"]["pull_request_number"],"body":{"sha":operation["constraints"]["expected_head_sha"],"merge_method":operation["constraints"]["merge_method"]}}));
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Denial {
    Replay,
    Record,
    Checks,
    Changed,
    Stale,
}
struct FakeStore {
    approved: bool,
    claimed: bool,
    reserved: bool,
    enabled: bool,
    policy: u64,
    revisions: [u64; 4],
    session: String,
    now: u64,
    final_wall: u64,
    final_monotonic: Instant,
    expected_head: String,
    dispatches: Vec<Value>,
}
impl FakeStore {
    fn fresh(now: Instant) -> Self {
        Self {
            approved: true,
            claimed: false,
            reserved: false,
            enabled: true,
            policy: 1,
            revisions: [1, 2, 3, 4],
            session: SESSION.into(),
            now: NOW,
            final_wall: NOW,
            final_monotonic: now,
            expected_head: "a".repeat(40),
            dispatches: vec![],
        }
    }
}

#[test]
fn reusable_checks_and_real_helper_gate_one_fake_dispatch() {
    let h = Harness::new();
    let context = h.context(None, 0);
    let issuer = h.fixture["issuer"]["jws"].as_str().unwrap().as_bytes();
    let proof = h.fixture["execution"]["jws"].as_str().unwrap().as_bytes();
    let mut good = FakeStore::fresh(h.monotonic);
    assert_eq!(
        h.execute(&mut good, &context, issuer, proof, &h.helper),
        Ok(())
    );
    assert_eq!(
        good.dispatches,
        vec![
            json!({"method":"PUT","repository_id":"12345","pull_request_number":42,"body":{"sha":"a".repeat(40),"merge_method":"squash"}})
        ]
    );
    assert_eq!(
        h.execute(&mut good, &context, issuer, proof, &h.helper),
        Err(Denial::Replay)
    );
    assert_eq!(good.dispatches.len(), 1);
    for change in 0..13 {
        let mut state = FakeStore::fresh(h.monotonic);
        match change {
            0 => state.enabled = false,
            1 => state.policy = 2,
            2 => state.revisions[2] += 1,
            3 => state.session = "cd".repeat(16),
            4 => state.final_wall += 30,
            5 => state.final_monotonic += Duration::from_secs(29),
            6 => state.expected_head = "b".repeat(40),
            7 => state.now += 30,
            8 => state.now = 1_799_999_999,
            _ => {}
        }
        let chosen = match change {
            9 => h.context(Some(B64.encode([13; 32])), 0),
            10 => h.context(None, 1),
            _ => h.context(None, 0),
        };
        let failed_helper = Helper {
            launch: h.helper.launch.clone(),
            fail: true,
        };
        let corrupt = |bytes: &[u8]| {
            let mut b = bytes.to_vec();
            let i = b.iter().rposition(|v| *v == b'.').unwrap() + 1;
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            b
        };
        let bad_issuer = corrupt(issuer);
        let selected_issuer = if change == 12 {
            bad_issuer.as_slice()
        } else {
            issuer
        };
        let helper = if change == 11 {
            &failed_helper
        } else {
            &h.helper
        };
        assert!(
            h.execute(&mut state, &chosen, selected_issuer, proof, helper)
                .is_err(),
            "case {change}"
        );
        assert!(state.claimed && !state.reserved && state.dispatches.is_empty());
        assert_eq!(
            h.execute(&mut state, &context, issuer, proof, &h.helper),
            Err(Denial::Replay)
        );
    }
    let mut no_record = FakeStore::fresh(h.monotonic);
    no_record.approved = false;
    assert_eq!(
        h.execute(&mut no_record, &context, issuer, proof, &h.helper),
        Err(Denial::Record)
    );
    assert!(!no_record.claimed);
    let mut bad_proof = proof.to_vec();
    let i = bad_proof.len() - 5;
    bad_proof[i] = if bad_proof[i] == b'A' { b'B' } else { b'A' };
    let mut state = FakeStore::fresh(h.monotonic);
    assert!(
        h.execute(&mut state, &context, issuer, &bad_proof, &h.helper)
            .is_err()
    );
    assert!(state.claimed && state.dispatches.is_empty());
    // Retained original counter context still succeeds on a different claimed
    // TEST record; no actual credential counter is advanced by rechecking.
    assert!(
        h.execute(
            &mut FakeStore::fresh(h.monotonic),
            &context,
            issuer,
            proof,
            &h.helper
        )
        .is_ok()
    );
}
