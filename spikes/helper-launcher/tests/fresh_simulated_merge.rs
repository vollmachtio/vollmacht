//! Fresh synthetic issuance and execution, entirely test-only. Ephemeral software
//! keys and asserted UV flags are not a human ceremony or native provider.
//! A real attempt ledger uses explicitly seeded test state, not production
//! provisioning. No reservation, network or GitHub client exists in this test.
#[path = "support/attempt_fixture.rs"]
mod attempt_fixture;
use attempt_fixture::{AttemptFixture, request};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
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
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use vollmacht_core::*;
use vollmacht_helper_probe::{Coordinator, HelperResult, Launch, Request};
use vollmacht_state::Ledger;

const NOW: u64 = 1_800_000_000; // Explicit deterministic test clock, not host time.
const PROFILE: &str = "vollmacht-local-es256-v1";

fn attempt<'a>(
    ledger: &mut Ledger,
    runtime: &VerificationRuntime,
    context: &'a ExecutionContext,
    issuer: &[u8],
    proof: &[u8],
    helper: &impl EvidenceRechecker,
    now: u64,
) -> Result<VerifiedExecutionCandidate<'a>, &'static str> {
    let claim = ledger
        .claim_submission(request(context), attempt_fixture::sample(now))
        .map_err(|_| "claim denied")?;
    let s = claim.snapshot();
    let t = context.trust();
    let matching = s.mandate_digest == mandate_digest(context.approved().approval()).unwrap()
        && s.operation_digest == operation_digest(context.approved().approval()).unwrap()
        && s.envelope_digest == envelope_digest(context.approved()).unwrap()
        && B64.encode(s.agent_jkt) == t.agent_jkt
        && s.audience == t.audience
        && s.policy_revision == t.policy_revision
        && s.registry_revisions == t.registry_revisions;
    let result = if matching {
        verify_claimed_attempt(
            runtime,
            context,
            issuer,
            proof,
            helper,
            ExecutionTime {
                wall_seconds: now,
                monotonic: Instant::now(),
                session_id: t.session_id.clone(),
            },
        )
        .map_err(|_| "verification denied")
    } else {
        Err("snapshot denied")
    };
    if result.is_err() {
        ledger
            .finish_rejected(&claim, &id(), attempt_fixture::sample(now))
            .map_err(|_| "rejection failed; stop")?;
    }
    result
}

struct ObservedHelper<'a> {
    helper: &'a Helper,
    fixture: &'a AttemptFixture,
    calls: &'a std::sync::atomic::AtomicUsize,
}
struct RejectionFailure<'a> {
    helper: &'a Helper,
    fixture: &'a AttemptFixture,
    lock: std::cell::RefCell<Option<rusqlite::Connection>>,
}
impl EvidenceRechecker for RejectionFailure<'_> {
    fn recheck(
        &self,
        request: &EvidenceRecheckRequest<'_>,
    ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
        assert_eq!(self.fixture.state(), "claimed");
        self.helper.recheck(request)?;
        let db = self.fixture.sql();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        *self.lock.borrow_mut() = Some(db);
        // Test-only failure after actual cryptographic verification, with an
        // independent writer preventing the terminal rejection transaction.
        Err(EvidenceRecheckError)
    }
}
impl EvidenceRechecker for ObservedHelper<'_> {
    fn recheck(
        &self,
        request: &EvidenceRecheckRequest<'_>,
    ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
        // Independent connection observes the committed claim before helper work.
        assert_eq!(self.fixture.state(), "claimed");
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.helper.recheck(request)
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).unwrap();
    b
}
fn id() -> String {
    random::<16>().iter().map(|b| format!("{b:02x}")).collect()
}
fn key() -> (PKey<Private>, AgentPublicKey) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    ec.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut BigNumContext::new().unwrap())
        .unwrap();
    let jwk = json!({"kty":"EC","crv":"P-256","x":B64.encode(x.to_vec_padded(32).unwrap()),"y":B64.encode(y.to_vec_padded(32).unwrap())});
    (
        PKey::from_ec_key(ec).unwrap(),
        AgentPublicKey::parse(&serde_json::to_vec(&jwk).unwrap()).unwrap(),
    )
}

// This test assembles a synthetic compact fixture, not a reusable JOSE encoder
// or production signing provider. Maintained OpenSSL performs every primitive.
fn sign(
    prepared: &PreparedSigningInput,
    key: &PKey<Private>,
    runtime: &VerificationRuntime,
    calls: &mut usize,
) -> Vec<u8> {
    prepared
        .check_callback_input(prepared.signing_input())
        .unwrap();
    *calls += 1;
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(prepared.signing_input()).unwrap();
    let signature = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
    let raw = [
        signature.r().to_vec_padded(32).unwrap(),
        signature.s().to_vec_padded(32).unwrap(),
    ]
    .concat();
    let mut compact = prepared.signing_input().to_vec();
    compact.push(b'.');
    compact.extend(B64.encode(raw).as_bytes());
    prepared.validate_output(runtime, &compact).unwrap();
    compact
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct BrowserFixture {
    child: Reap,
    lines: mpsc::Receiver<Result<Vec<u8>, ()>>,
    reader: Option<thread::JoinHandle<()>>,
    errors: mpsc::Receiver<Vec<u8>>,
    error_reader: Option<thread::JoinHandle<()>>,
}
impl BrowserFixture {
    fn start(node: &PathBuf, directory: &std::path::Path) -> (Self, Value) {
        let mut child = Command::new(node)
            .arg(directory.join("fresh-simulation-context.mjs"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (error_tx, errors) = mpsc::channel();
        let error_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            if stderr.take(1025).read_to_end(&mut bytes).is_ok() {
                let _ = error_tx.send(bytes);
            }
        });
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            for _ in 0..2 {
                let mut line = Vec::new();
                let result = reader.by_ref().take(16_385).read_until(b'\n', &mut line);
                if result.is_err()
                    || line.is_empty()
                    || line.len() > 16_384
                    || line.last() != Some(&b'\n')
                {
                    let _ = tx.send(Err(()));
                    return;
                }
                if tx.send(Ok(line)).is_err() {
                    return;
                }
            }
            let mut extra = [0];
            let clean = matches!(reader.read(&mut extra), Ok(0));
            let _ = tx.send(if clean { Ok(Vec::new()) } else { Err(()) });
        });
        let this = Self {
            child: Reap(child),
            lines: rx,
            reader: Some(reader),
            errors,
            error_reader: Some(error_reader),
        };
        let first = this.next();
        assert_eq!(first.as_object().unwrap().len(), 1);
        assert_eq!(first["credential"].as_object().unwrap().len(), 5);
        (this, first["credential"].clone())
    }
    fn next(&self) -> Value {
        let bytes = self
            .lines
            .recv_timeout(Duration::from_secs(7))
            .expect("bounded fixture response")
            .expect("bounded fixture frame");
        serde_json::from_slice(&bytes).unwrap()
    }
    fn approve(mut self, challenge: &str) -> Value {
        let mut stdin = self.child.0.stdin.take().unwrap();
        let request = serde_json::to_vec(&json!({"challenge":challenge})).unwrap();
        assert!(request.len() < 256);
        stdin.write_all(&request).unwrap();
        stdin.write_all(b"\n").unwrap();
        drop(stdin);
        let response = self.next();
        assert_eq!(response.as_object().unwrap().len(), 1);
        let assertion = response["assertion"].as_object().unwrap();
        assert_eq!(assertion.len(), 7);
        for field in [
            "id",
            "raw_id",
            "type",
            "client_data_json",
            "authenticator_data",
            "signature",
            "user_handle",
        ] {
            assert!(assertion[field].is_string());
        }
        assert!(
            self.lines
                .recv_timeout(Duration::from_secs(7))
                .unwrap()
                .unwrap()
                .is_empty()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "fixture process exit deadline");
            thread::sleep(Duration::from_millis(5));
        }
        self.reader.take().unwrap().join().unwrap();
        assert!(
            self.errors
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_empty()
        );
        self.error_reader.take().unwrap().join().unwrap();
        response["assertion"].clone()
    }
}
impl Drop for BrowserFixture {
    fn drop(&mut self) {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        if let Some(reader) = self.error_reader.take() {
            reader.join().unwrap();
        }
    }
}

struct Helper {
    launch: Launch,
}
impl Helper {
    fn verify(
        &self,
        envelope: &MandateEnvelope,
        credential: Value,
        challenge: &str,
        deadline: Instant,
    ) -> Result<HelperResult, ()> {
        let e = envelope.evidence();
        SyntaxCheckedClientData::parse(
            &B64.decode(e["client_data_json"].as_str().unwrap())
                .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let request = json!({"version":1,"kind":"verify_assertion","request_id":id(),"challenge":challenge,"rp_id":"localhost","origin":"http://localhost:8374","credential":credential,
            "assertion":{"id":e["credential_id"],"raw_id":e["credential_id"],"type":"public-key","client_data_json":e["client_data_json"],"authenticator_data":e["authenticator_data"],"signature":e["signature"],"user_handle":e["user_handle"]}});
        let request = Request::parse(&serde_json::to_vec(&request).unwrap()).map_err(|_| ())?;
        Coordinator::new(
            request,
            deadline.min(Instant::now() + Duration::from_secs(5)),
        )
        .verify(self.launch.clone())
        .map_err(|_| ())
    }
}
impl EvidenceRechecker for Helper {
    fn recheck(
        &self,
        r: &EvidenceRecheckRequest,
    ) -> Result<AssertionRecheckResult, EvidenceRecheckError> {
        let c = r.credential();
        let credential = json!({"id":r.credential_id(),"public_key":c.public_key,"counter":c.counter,"user_handle":c.user_handle,"backup_eligible":c.backup_eligible});
        let result = self
            .verify(
                r.envelope(),
                credential,
                r.webauthn_challenge(),
                r.deadline(),
            )
            .map_err(|_| EvidenceRecheckError)?;
        Ok(AssertionRecheckResult {
            new_counter: result.new_counter,
            backup_eligible: result.backup_eligible,
            backed_up: result.backed_up,
        })
    }
}

// A test-only approval cancellation/clock gate, not durable pending issuance.
struct Issuance<'a> {
    envelope: &'a MandateEnvelope,
    credential: &'a Value,
    helper: &'a Helper,
    prepared: &'a PreparedSigningInput,
    key: &'a PKey<Private>,
    runtime: &'a VerificationRuntime,
}
impl Issuance<'_> {
    fn issue(
        &self,
        cancelled: bool,
        now: u64,
        commit_acknowledged: bool,
        calls: &mut usize,
    ) -> Option<Vec<u8>> {
        let Self {
            envelope,
            credential,
            helper,
            prepared,
            key,
            runtime,
        } = self;
        let a = envelope.approval().fields();
        if cancelled
            || now < a["issued_at"].as_u64().unwrap()
            || now >= a["expires_at"].as_u64().unwrap()
        {
            return None;
        }
        let challenge = B64.encode(mandate_digest(envelope.approval()).unwrap());
        let result = helper
            .verify(
                envelope,
                (*credential).clone(),
                &challenge,
                Instant::now() + Duration::from_secs(5),
            )
            .ok()?;
        if result.new_counter != 0 || result.backup_eligible || result.backed_up {
            return None;
        }
        let signed = sign(prepared, key, runtime, calls);
        // Fake commit acknowledgement only. A failed/uncertain commit must not
        // release the already-produced signature or enable an approved record.
        commit_acknowledged.then_some(signed)
    }
}

#[test]
fn fresh_synthetic_approval_issuance_and_execution_record_one_candidate() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../simplewebauthn")
        .canonicalize()
        .unwrap();
    let node =
        PathBuf::from(std::env::var_os("VOLLMACHT_TEST_NODE").expect("pinned Node path required"));
    assert!(node.is_absolute());
    let version = Command::new(&node)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(version.stdout, b"v24.21.0\n");
    let helper = Helper {
        launch: Launch {
            executable: node.clone(),
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_vollmacht-helper-launcher")),
            helper: Some(directory.join("helper.mjs")),
            directory: directory.clone(),
        },
    };
    let runtime = VerificationRuntime::initialize().unwrap();
    let (issuer_private, issuer_public) = key();
    let (agent_private, agent_public) = key();
    let agent_jkt = B64.encode(agent_public.thumbprint().unwrap());
    let (browser, credential) = BrowserFixture::start(&node, &directory);
    let issuer_id = id();
    let audience = id();
    let principal = id();
    let session = id();
    let approval = ApprovalPayload::parse(&serde_json::to_vec(&json!({"version":1,"crypto_profile":PROFILE,"mandate_id":id(),"nonce":B64.encode(random::<32>()),"issuer_id":issuer_id,"audience":audience,"principal_id":principal,"credential_id":credential["id"],"agent_jkt":agent_jkt,"policy_revision":1,"issued_at":NOW,"expires_at":NOW+120,"operation":{"action":"github.pull_request.merge","resource":{"host":"github.com","repository_id":"12345","pull_request_number":42},"constraints":{"expected_head_sha":"a".repeat(40),"base_ref":"main","merge_method":"squash"}},"display":{"version":1,"repository":"vollmacht-disposable/example"}})).unwrap()).unwrap();
    let challenge = B64.encode(mandate_digest(&approval).unwrap());
    let assertion = browser.approve(&challenge);
    assert_eq!(assertion["id"], credential["id"]);
    assert_eq!(assertion["raw_id"], credential["id"]);
    assert_eq!(assertion["type"], "public-key");
    let e = json!({"kind":"webauthn.get","credential_id":credential["id"],"client_data_json":assertion["client_data_json"],"authenticator_data":assertion["authenticator_data"],"signature":assertion["signature"],"user_handle":assertion["user_handle"]});
    let envelope = MandateEnvelope::parse_canonical(
        &serde_jcs::to_vec(&json!({"version":1,"payload":approval.fields(),"evidence":e})).unwrap(),
    )
    .unwrap();
    let prepared = PreparedSigningInput::issuer(&envelope, &issuer_id, &issuer_public).unwrap();
    let mut issuer_calls = 0;
    let issuance = Issuance {
        envelope: &envelope,
        credential: &credential,
        helper: &helper,
        prepared: &prepared,
        key: &issuer_private,
        runtime: &runtime,
    };
    assert!(
        issuance
            .issue(true, NOW + 1, true, &mut issuer_calls)
            .is_none()
    );
    assert!(
        issuance
            .issue(false, NOW + 120, true, &mut issuer_calls)
            .is_none()
    );
    assert_eq!(issuer_calls, 0);
    let mut invalid: Value = serde_json::from_slice(envelope.canonical_bytes()).unwrap();
    invalid["evidence"]["signature"] = json!(B64.encode([0; 64]));
    let invalid = MandateEnvelope::parse_canonical(&serde_jcs::to_vec(&invalid).unwrap()).unwrap();
    let invalid_prepared =
        PreparedSigningInput::issuer(&invalid, &issuer_id, &issuer_public).unwrap();
    let bad_issuance = Issuance {
        envelope: &invalid,
        prepared: &invalid_prepared,
        ..issuance
    };
    assert!(
        bad_issuance
            .issue(false, NOW + 1, true, &mut issuer_calls)
            .is_none()
    );
    assert_eq!(issuer_calls, 0);
    // Separate fault-injection scenarios, not a retry of an uncertain durable
    // issuance. This test has no recovery API or persistent pending store.
    assert!(
        issuance
            .issue(false, NOW + 1, false, &mut issuer_calls)
            .is_none()
    );
    assert_eq!(issuer_calls, 1);
    let issuer = issuance
        .issue(false, NOW + 1, true, &mut issuer_calls)
        .unwrap();
    assert_eq!(issuer_calls, 2);
    let execution_challenge = B64.encode(random::<32>());
    assert_ne!(execution_challenge, challenge);
    let md = B64.encode(mandate_digest(envelope.approval()).unwrap());
    let od = B64.encode(operation_digest(envelope.approval()).unwrap());
    let ed = B64.encode(envelope_digest(&envelope).unwrap());
    let proof = ExecutionProofPayload::parse_canonical(&serde_jcs::to_vec(&json!({"version":1,"crypto_profile":PROFILE,"mandate_digest":md,"operation_digest":od,"envelope_digest":ed,"audience":audience,"challenge":execution_challenge,"issued_at":NOW+1,"expires_at":NOW+20})).unwrap()).unwrap();
    let prepared = PreparedSigningInput::execution(&proof, &agent_jkt, &agent_public).unwrap();
    let mut agent_calls = 0;
    assert!(prepared.check_callback_input(b"different input").is_err());
    assert_eq!(agent_calls, 0);
    let proof = sign(&prepared, &agent_private, &runtime, &mut agent_calls);
    assert_eq!(agent_calls, 1);
    let start = Instant::now();
    let context = ExecutionContext::new(
        envelope,
        ExecutionTrust {
            issuer_kid: issuer_id.clone(),
            issuer_id,
            principal_id: principal,
            credential_id: credential["id"].as_str().unwrap().into(),
            agent_jkt,
            audience,
            crypto_profile: PROFILE.into(),
            policy_revision: 1,
            registry_revisions: [1; 4],
            enabled: [true; 4],
            session_id: session.clone(),
            approval_deadline: start + Duration::from_secs(120),
        },
        PendingExecution {
            challenge: execution_challenge,
            mandate_digest: md,
            operation_digest: od,
            envelope_digest: ed,
            issued_at: NOW + 1,
            expires_at: NOW + 30,
            deadline: start + Duration::from_secs(29),
        },
        OriginalCredential {
            public_key: credential["public_key"].as_str().unwrap().into(),
            counter: 0,
            user_handle: "AA".into(),
            backup_eligible: false,
            backed_up: false,
            expected_counter: 0,
            expected_backed_up: false,
        },
        &issuer_public,
        &agent_public,
    )
    .unwrap();
    let helper_calls = std::sync::atomic::AtomicUsize::new(0);
    let calls = || helper_calls.load(std::sync::atomic::Ordering::SeqCst);
    let invoke = |store: &AttemptFixture, ledger: &mut Ledger, bytes: &[u8], now| {
        let observed = ObservedHelper {
            helper: &helper,
            fixture: store,
            calls: &helper_calls,
        };
        attempt(ledger, &runtime, &context, &issuer, bytes, &observed, now)
    };
    let store = AttemptFixture::new(&context, &issuer_public);
    let mut ledger = store.open(NOW + 2);
    let candidate = invoke(&store, &mut ledger, &proof, NOW + 2).unwrap();
    assert_eq!(calls(), 1);
    assert_eq!(store.state(), "claimed");
    // Recording-only candidate event, NOT a reservation or dispatch permit.
    let now = NOW + 2;
    assert!(now >= candidate.proof_issued_at() && now < candidate.proof_expires_at());
    assert!(Instant::now() < candidate.context().pending().deadline);
    let mut recorded = vec![candidate.operation().clone()];
    assert_eq!(
        recorded[0]["constraints"]["expected_head_sha"],
        "a".repeat(40)
    );
    assert!(invoke(&store, &mut ledger, &proof, NOW + 2).is_err());
    drop(ledger);
    assert!(invoke(&store, &mut store.open(NOW + 2), &proof, NOW + 2).is_err());
    assert_eq!(calls(), 1);
    assert_eq!(recorded.len(), 1);
    let mut bad = proof.clone();
    let index = bad.iter().rposition(|b| *b == b'.').unwrap() + 1;
    bad[index] = if bad[index] == b'A' { b'B' } else { b'A' };
    for (bytes, now) in [(&bad, NOW + 2), (&proof, NOW + 20)] {
        let store = AttemptFixture::new(&context, &issuer_public);
        let mut ledger = store.open(now);
        assert!(invoke(&store, &mut ledger, bytes, now).is_err());
        assert_eq!(store.state(), "rejected");
        let transitions: (i64, i64) = store
            .sql()
            .query_row(
                "SELECT (SELECT count(*) FROM operations),(SELECT count(*) FROM audit)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(transitions, (2, 2));
        drop(ledger);
        assert!(invoke(&store, &mut store.open(now), &proof, now).is_err());
    }
    let unrelated = AttemptFixture::new(&context, &issuer_public);
    let mut wrong = request(&context);
    wrong.challenge = B64.encode(random::<32>());
    assert!(
        unrelated
            .open(NOW + 2)
            .claim_submission(wrong, attempt_fixture::sample(NOW + 2))
            .is_err()
    );
    assert_eq!(unrelated.state(), "pending");
    for column in [
        "mandate_digest",
        "operation_digest",
        "envelope_digest",
        "agent_jkt",
    ] {
        let mismatch = AttemptFixture::new(&context, &issuer_public);
        // Fixed test-owned column names, never an artifact-controlled SQL input.
        mismatch
            .sql()
            .execute(&format!("UPDATE mandates SET {column}=?1"), [vec![0u8; 32]])
            .unwrap();
        let before = calls();
        assert!(invoke(&mismatch, &mut mismatch.open(NOW + 2), &proof, NOW + 2).is_err());
        assert_eq!(calls(), before);
        assert_eq!(mismatch.state(), "rejected");
    }
    for update in [
        "UPDATE mandates SET audience='00000000000000000000000000000000'",
        "UPDATE mandates SET policy_revision=2",
        "UPDATE mandates SET credential_revision=2",
    ] {
        let mismatch = AttemptFixture::new(&context, &issuer_public);
        mismatch.sql().execute_batch(update).unwrap();
        let before = calls();
        assert!(invoke(&mismatch, &mut mismatch.open(NOW + 2), &proof, NOW + 2).is_err());
        assert_eq!(calls(), before);
        assert_eq!(mismatch.state(), "pending"); // Denied by the claim transaction.
    }
    let race = AttemptFixture::new(&context, &issuer_public);
    let ledgers = [race.open(NOW + 2), race.open(NOW + 2)];
    let barrier = std::sync::Barrier::new(2);
    let before = calls();
    let winners = thread::scope(|scope| {
        let handles: Vec<_> = ledgers
            .into_iter()
            .map(|mut ledger| {
                let invoke = &invoke;
                let race = &race;
                let barrier = &barrier;
                let proof = &proof;
                scope.spawn(move || {
                    barrier.wait();
                    invoke(race, &mut ledger, proof, NOW + 2).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(winners, 1);
    assert_eq!(calls(), before + 1);
    assert_eq!(race.state(), "claimed");
    let blocked = AttemptFixture::new(&context, &issuer_public);
    let mut ledger = blocked.open(NOW + 2);
    let failing = RejectionFailure {
        helper: &helper,
        fixture: &blocked,
        lock: std::cell::RefCell::new(None),
    };
    assert!(matches!(
        attempt(
            &mut ledger,
            &runtime,
            &context,
            &issuer,
            &proof,
            &failing,
            NOW + 2
        ),
        Err("rejection failed; stop")
    ));
    assert_eq!(blocked.state(), "claimed");
    let lock = failing.lock.borrow_mut().take().unwrap();
    lock.execute_batch("ROLLBACK").unwrap();
    drop(lock);
    drop(ledger);
    let before = calls();
    assert!(invoke(&blocked, &mut blocked.open(NOW + 2), &proof, NOW + 2).is_err());
    assert_eq!(calls(), before);
    // Nothing besides the successful candidate is ever sent to this recorder.
    assert_eq!(
        recorded.pop().unwrap()["action"],
        "github.pull_request.merge"
    );
}
