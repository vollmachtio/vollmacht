//! Explicit test provisioning. This is not an installation/bootstrap API.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rusqlite::{Connection, params};
use std::{path::PathBuf, time::Instant};
use vollmacht_core::{
    AgentPublicKey, ExecutionContext, envelope_digest, mandate_digest, operation_digest,
};
use vollmacht_state::{Binding, ClaimRequest, Ledger, TimeSample};

pub struct AttemptFixture {
    directory: PathBuf,
    path: PathBuf,
    binding: Binding,
}
pub fn sample(wall_seconds: u64) -> TimeSample {
    TimeSample {
        wall_seconds,
        monotonic: Instant::now(),
    }
}
pub fn request(context: &ExecutionContext) -> ClaimRequest {
    ClaimRequest {
        operation_id: super::id(),
        mandate_id: context.approved().approval().fields()["mandate_id"]
            .as_str()
            .unwrap()
            .into(),
        challenge: context.pending().challenge.clone(),
        policy_revision: context.trust().policy_revision,
        registry_revisions: context.trust().registry_revisions,
        deadline: context.pending().deadline,
    }
}
impl AttemptFixture {
    pub fn new(context: &ExecutionContext, issuer: &AgentPublicKey) -> Self {
        let directory =
            std::env::temp_dir().join(format!("vollmacht-fresh-attempt-{}", super::id()));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let path = directory.join("fixture.sqlite");
        let t = context.trust();
        let binding = Binding {
            installation_id: super::id(),
            bootstrap_commit_id: super::id(),
            session_id: t.session_id.clone(),
            issuer_id: t.issuer_id.clone(),
            executor_id: t.audience.clone(),
            principal_id: t.principal_id.clone(),
            issuer_kid: t.issuer_kid.clone(),
            provider_reference: "synthetic-test-only".into(),
            issuer_public_key: issuer.canonical_bytes().to_vec(),
        };
        let f = Self {
            directory,
            path,
            binding,
        };
        let db = f.sql();
        db.execute_batch(include_str!("../../../../crates/state/src/schema.sql"))
            .unwrap();
        let b = &f.binding;
        db.execute(
            "INSERT INTO binding VALUES(1,?,?,?,?,?,?,?,?,?,?)",
            params![
                b.installation_id,
                b.bootstrap_commit_id,
                b.session_id,
                b.issuer_id,
                b.executor_id,
                b.principal_id,
                b.issuer_kid,
                b.provider_reference,
                b.issuer_public_key,
                super::NOW as i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO registry VALUES(1,?,?,?,?,?,1,1,1,1)",
            params![
                t.policy_revision as i64,
                t.registry_revisions[0] as i64,
                t.registry_revisions[1] as i64,
                t.registry_revisions[2] as i64,
                t.registry_revisions[3] as i64
            ],
        )
        .unwrap();
        let a = context.approved().approval();
        db.execute(
            "INSERT INTO mandates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                a.fields()["mandate_id"].as_str().unwrap(),
                t.issuer_id,
                t.session_id,
                "approved",
                a.fields()["issued_at"].as_u64().unwrap() as i64,
                a.fields()["expires_at"].as_u64().unwrap() as i64,
                mandate_digest(a).unwrap().as_slice(),
                operation_digest(a).unwrap().as_slice(),
                envelope_digest(context.approved()).unwrap().as_slice(),
                B64.decode(&t.agent_jkt).unwrap(),
                t.audience,
                t.policy_revision as i64,
                t.registry_revisions[0] as i64,
                t.registry_revisions[1] as i64,
                t.registry_revisions[2] as i64,
                t.registry_revisions[3] as i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,'pending',NULL)",
            params![
                context.pending().challenge,
                a.fields()["mandate_id"].as_str().unwrap(),
                t.session_id,
                context.pending().issued_at as i64,
                context.pending().expires_at as i64
            ],
        )
        .unwrap();
        f
    }
    pub fn open(&self, now: u64) -> Ledger {
        Ledger::open_existing(&self.path, self.binding.clone(), sample(now)).unwrap()
    }
    pub fn sql(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    pub fn state(&self) -> String {
        self.sql()
            .query_row("SELECT state FROM challenges", [], |r| r.get(0))
            .unwrap()
    }
}
impl Drop for AttemptFixture {
    fn drop(&mut self) {
        // Only the unique directory created by this fixture is removed.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
