//! Durable attempt ledger. Not bootstrap provisioning or dispatch authority.
const SCHEMA: &str = include_str!("schema.sql");
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, config::DbConfig, params,
};
use std::{
    collections::BTreeMap,
    fmt,
    path::Path,
    time::{Duration, Instant},
};

/// Version of the private ledger schema; no creation or migration API exists.
pub const SCHEMA_VERSION: u32 = 1;

const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// Executor-configured provenance expectations, never supplied by an artifact.
/// The caller must already hold the qualified executor lease and authenticate
/// the anchor/bootstrap binding. Equality here does not establish that provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    pub installation_id: String,
    pub bootstrap_commit_id: String,
    pub session_id: String,
    pub issuer_id: String,
    pub executor_id: String,
    pub principal_id: String,
    pub issuer_kid: String,
    pub provider_reference: String,
    pub issuer_public_key: Vec<u8>,
}
pub struct TimeSample {
    pub wall_seconds: u64,
    pub monotonic: Instant,
}
pub struct ClaimRequest {
    pub operation_id: String,
    pub mandate_id: String,
    pub challenge: String,
    pub policy_revision: u64,
    pub registry_revisions: [u64; 4],
    /// Original trusted pending deadline, not reconstructed from wall time.
    pub deadline: Instant,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Claimed,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedOperation {
    operation_id: String,
    mandate_id: String,
    challenge: String,
    outcome: Outcome,
}
impl RecordedOperation {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn mandate_id(&self) -> &str {
        &self.mandate_id
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
}
/// Captured record bindings, not a verified artifact or reservation permit.
pub struct ClaimSnapshot {
    pub mandate_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub agent_jkt: [u8; 32],
    pub audience: String,
    pub policy_revision: u64,
    pub registry_revisions: [u64; 4],
}
/// Returned only by an acknowledged claim, never by read-only reconciliation.
/// Not authorization or a dispatch permit; helpers/core verification still follow.
pub struct ClaimReceipt {
    operation: RecordedOperation,
    session_id: String,
    snapshot: ClaimSnapshot,
}
impl ClaimReceipt {
    pub fn operation_id(&self) -> &str {
        self.operation.operation_id()
    }
    pub fn mandate_id(&self) -> &str {
        self.operation.mandate_id()
    }
    pub fn challenge(&self) -> &str {
        self.operation.challenge()
    }
    pub fn snapshot(&self) -> &ClaimSnapshot {
        &self.snapshot
    }
}
impl fmt::Debug for ClaimReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimReceipt { .. }")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    InvalidInput,
    InvalidState,
    Conflict,
    Unavailable,
    Indeterminate { operation_id: String },
    Poisoned,
}
impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attempt ledger operation rejected")
    }
}
impl std::error::Error for LedgerError {}

/// A single process-session ledger. No create, migration, import, raw connection,
/// session rollover, reservation or dispatch APIs are exposed. Filesystem/anchor
/// confinement, rollback detection and actual durability remain deployment gates.
pub struct Ledger {
    connection: Connection,
    binding: Binding,
    last_wall: u64,
    last_monotonic: Instant,
    poisoned: bool,
    #[cfg(test)]
    lose_commit_ack: bool,
}
impl Ledger {
    pub fn open_existing(
        path: &Path,
        binding: Binding,
        time: TimeSample,
    ) -> Result<Self, LedgerError> {
        binding.validate()?;
        if !path.is_absolute() || time.wall_seconds > MAX_INTEGER {
            return Err(LedgerError::InvalidInput);
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| LedgerError::Unavailable)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(LedgerError::InvalidInput);
        }
        // Resolve trusted platform directory aliases (for example /var on
        // macOS) before NOFOLLOW. A symlink as the supplied final file is denied
        // above. This is not filesystem confinement or race qualification.
        let resolved = path.canonicalize().map_err(|_| LedgerError::Unavailable)?;
        let connection = Connection::open_with_flags(
            resolved,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| LedgerError::Unavailable)?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|_| LedgerError::Unavailable)?;
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(|_| LedgerError::Unavailable)?;
        connection
            .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
            .map_err(|_| LedgerError::Unavailable)?;
        // No Rust load_extension feature is enabled; SQLite extension loading is
        // disabled by default. Do not enable it or use unsafe FFI to configure it.
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA journal_mode=DELETE;
                 PRAGMA synchronous=EXTRA;
                 PRAGMA fullfsync=ON;",
            )
            .map_err(|_| LedgerError::Unavailable)?;
        if connection
            .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .map_err(|_| LedgerError::Unavailable)?
            != "delete"
            || pragma(&connection, "synchronous")? != 3
            || pragma(&connection, "foreign_keys")? != 1
            || pragma(&connection, "trusted_schema")? != 0
            || pragma(&connection, "fullfsync")? != 1
            || !connection
                .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
                .map_err(|_| LedgerError::Unavailable)?
        {
            return Err(LedgerError::InvalidState);
        }
        schema(&connection)?;
        let high = binding_matches(&connection, &binding)?;
        if time.wall_seconds < high {
            return Err(LedgerError::Conflict);
        }
        Ok(Self {
            connection,
            binding,
            last_wall: time.wall_seconds,
            last_monotonic: time.monotonic,
            poisoned: false,
            #[cfg(test)]
            lose_commit_ack: false,
        })
    }

    pub fn claim_submission(
        &mut self,
        request: ClaimRequest,
        time: TimeSample,
    ) -> Result<ClaimReceipt, LedgerError> {
        if !valid_id(&request.operation_id)
            || !valid_id(&request.mandate_id)
            || !valid_challenge(&request.challenge)
            || !revision(request.policy_revision)
            || request.registry_revisions.iter().any(|v| !revision(*v))
        {
            return Err(LedgerError::InvalidInput);
        }
        self.sample(&time)?;
        if time.monotonic >= request.deadline {
            return Err(LedgerError::Conflict);
        }
        let binding = self.binding.clone();
        let op = request.operation_id.clone();
        self.write(&op,time.wall_seconds,|tx| {
            let high=binding_matches(tx,&binding)?;
            if time.wall_seconds<high { return Err(LedgerError::Conflict); }
            schema(tx)?;
            if lookup(tx,&request.operation_id)?.is_some() { return Err(LedgerError::Conflict); }
            let current=tx.query_row("SELECT policy_revision,issuer_revision,principal_revision,credential_revision,agent_revision,issuer_enabled,principal_enabled,credential_enabled,agent_enabled FROM registry WHERE singleton=1",[],|r|Ok(([uint(r,0)?,uint(r,1)?,uint(r,2)?,uint(r,3)?,uint(r,4)?],[r.get::<_,u8>(5)?,r.get(6)?,r.get(7)?,r.get(8)?]))).map_err(|_|LedgerError::InvalidState)?;
            if current.0 != [request.policy_revision,request.registry_revisions[0],request.registry_revisions[1],request.registry_revisions[2],request.registry_revisions[3]] || current.1 != [1;4] { return Err(LedgerError::Conflict); }
            let row = pending_row(tx, &request)?;
            if row.issuer_id != binding.issuer_id || row.mandate_session != binding.session_id
                || row.mandate_state != "approved" || row.audience != binding.executor_id
                || row.revisions != current.0 || row.challenge_session != binding.session_id
                || row.challenge_state != "pending" || row.claim_operation_id.is_some()
                || !(1..=300).contains(&row.mandate_expires.saturating_sub(row.mandate_issued))
                || !(1..=30).contains(&row.challenge_expires.saturating_sub(row.challenge_issued))
                || row.challenge_issued < row.mandate_issued || row.challenge_expires > row.mandate_expires
                || time.wall_seconds < row.mandate_issued || time.wall_seconds >= row.mandate_expires
                || time.wall_seconds < row.challenge_issued || time.wall_seconds >= row.challenge_expires
            { return Err(LedgerError::Conflict); }
            let snapshot = ClaimSnapshot { mandate_digest: row.mandate_digest,
                operation_digest: row.operation_digest, envelope_digest: row.envelope_digest,
                agent_jkt: row.agent_jkt, audience: row.audience,
                policy_revision: request.policy_revision, registry_revisions: request.registry_revisions };
            let n=tx.execute("UPDATE challenges SET state='claimed',claim_operation_id=?1 WHERE challenge=?2 AND state='pending' AND claim_operation_id IS NULL",params![request.operation_id,request.challenge]).map_err(|_|LedgerError::Unavailable)?;
            if n!=1 { return Err(LedgerError::Unavailable); }
            let operation=RecordedOperation{operation_id:request.operation_id.clone(),mandate_id:request.mandate_id.clone(),challenge:request.challenge.clone(),outcome:Outcome::Claimed};
            record(tx,&operation,time.wall_seconds)?;
            Ok(ClaimReceipt{operation,session_id:binding.session_id.clone(),snapshot})
        })
    }

    pub fn finish_rejected(
        &mut self,
        claim: &ClaimReceipt,
        operation_id: &str,
        time: TimeSample,
    ) -> Result<RecordedOperation, LedgerError> {
        if !valid_id(operation_id) {
            return Err(LedgerError::InvalidInput);
        }
        self.sample(&time)?;
        if claim.session_id != self.binding.session_id {
            return Err(LedgerError::Conflict);
        }
        let binding = self.binding.clone();
        self.write(operation_id,time.wall_seconds,|tx| {
            if time.wall_seconds<binding_matches(tx,&binding)? { return Err(LedgerError::Conflict); }
            schema(tx)?;
            if lookup(tx,operation_id)?.is_some() { return Err(LedgerError::Conflict); }
            let state=tx.query_row("SELECT state,claim_operation_id,session_id,mandate_id FROM challenges WHERE challenge=?1",[claim.challenge()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))).optional().map_err(|_|LedgerError::InvalidState)?.ok_or(LedgerError::Conflict)?;
            if state.0!="claimed"||state.1.as_deref()!=Some(claim.operation_id())||state.2!=binding.session_id||state.3!=claim.mandate_id()||lookup(tx,claim.operation_id())?.as_ref()!=Some(&claim.operation) { return Err(LedgerError::Conflict); }
            if tx.execute("UPDATE challenges SET state='rejected' WHERE challenge=?1 AND state='claimed' AND claim_operation_id=?2",params![claim.challenge(),claim.operation_id()]).map_err(|_|LedgerError::Unavailable)? !=1 { return Err(LedgerError::Unavailable); }
            let operation=RecordedOperation{operation_id:operation_id.into(),mandate_id:claim.mandate_id().into(),challenge:claim.challenge().into(),outcome:Outcome::Rejected};
            record(tx,&operation,time.wall_seconds)?; Ok(operation)
        })
    }

    /// Read-only correlation information, including after a poisoned write.
    /// A committed record never reconstructs a claim or dispatch capability.
    /// An unresolved transaction cannot provide reconciliation. The coordinator
    /// may inspect a fresh connection under its existing exclusive lease instead.
    pub fn lookup_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<RecordedOperation>, LedgerError> {
        if !valid_id(operation_id) {
            return Err(LedgerError::InvalidInput);
        }
        if !self.connection.is_autocommit() {
            return Err(LedgerError::InvalidState);
        }
        binding_matches(&self.connection, &self.binding)?;
        lookup(&self.connection, operation_id)
    }
    fn sample(&mut self, time: &TimeSample) -> Result<(), LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        if time.wall_seconds > MAX_INTEGER {
            return Err(LedgerError::InvalidInput);
        }
        if time.wall_seconds < self.last_wall || time.monotonic < self.last_monotonic {
            return Err(LedgerError::Conflict);
        }
        self.last_wall = time.wall_seconds;
        self.last_monotonic = time.monotonic;
        Ok(())
    }
    fn write<T>(
        &mut self,
        operation_id: &str,
        wall: u64,
        work: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LedgerError::Unavailable)?;
        let value = match work(&tx) {
            Ok(value) => value,
            Err(error) => {
                let rollback = tx.rollback();
                if rollback.is_ok()
                    && matches!(error, LedgerError::Conflict | LedgerError::InvalidState)
                {
                    return Err(error);
                }
                self.poisoned = true;
                return Err(LedgerError::Indeterminate {
                    operation_id: operation_id.into(),
                });
            }
        };
        if tx
            .execute(
                "UPDATE binding SET wall_high_water=?1 WHERE singleton=1 AND wall_high_water<=?1",
                [i64::try_from(wall).map_err(|_| LedgerError::InvalidInput)?],
            )
            .ok()
            != Some(1)
        {
            let _ = tx.rollback();
            self.poisoned = true;
            return Err(LedgerError::Indeterminate {
                operation_id: operation_id.into(),
            });
        }
        if tx.commit().is_err() {
            self.poisoned = true;
            return Err(LedgerError::Indeterminate {
                operation_id: operation_id.into(),
            });
        }
        #[cfg(test)]
        if self.lose_commit_ack {
            self.poisoned = true;
            return Err(LedgerError::Indeterminate {
                operation_id: operation_id.into(),
            });
        }
        Ok(value)
    }
}

impl Binding {
    fn validate(&self) -> Result<(), LedgerError> {
        if [
            &self.installation_id,
            &self.bootstrap_commit_id,
            &self.session_id,
            &self.issuer_id,
            &self.executor_id,
            &self.principal_id,
            &self.issuer_kid,
        ]
        .iter()
        .any(|v| !valid_id(v))
            || self.provider_reference.is_empty()
            || self.provider_reference.len() > 256
            || !self
                .provider_reference
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b))
            || !(1..=4096).contains(&self.issuer_public_key.len())
        {
            return Err(LedgerError::InvalidInput);
        }
        Ok(())
    }
}
fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && b"AEIMQUYcgkosw048".contains(&value.as_bytes()[42])
}
fn revision(value: u64) -> bool {
    (1..=MAX_INTEGER).contains(&value)
}
fn uint(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    let unsigned =
        u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))?;
    if unsigned > MAX_INTEGER {
        return Err(rusqlite::Error::IntegralValueOutOfRange(index, value));
    }
    Ok(unsigned)
}
fn pragma(connection: &Connection, name: &str) -> Result<u32, LedgerError> {
    connection
        .pragma_query_value(None, name, |r| r.get(0))
        .map_err(|_| LedgerError::InvalidState)
}
fn binding_matches(connection: &Connection, expected: &Binding) -> Result<u64, LedgerError> {
    let (actual,high)=connection.query_row("SELECT installation_id,bootstrap_commit_id,session_id,issuer_id,executor_id,principal_id,issuer_kid,provider_reference,issuer_public_key,wall_high_water FROM binding WHERE singleton=1",[],|r|Ok((Binding{installation_id:r.get(0)?,bootstrap_commit_id:r.get(1)?,session_id:r.get(2)?,issuer_id:r.get(3)?,executor_id:r.get(4)?,principal_id:r.get(5)?,issuer_kid:r.get(6)?,provider_reference:r.get(7)?,issuer_public_key:r.get(8)?},uint(r,9)?))).map_err(|_|LedgerError::InvalidState)?;
    if &actual != expected || high > MAX_INTEGER {
        return Err(LedgerError::InvalidState);
    }
    Ok(high)
}
fn schema(connection: &Connection) -> Result<(), LedgerError> {
    if pragma(connection, "user_version")? != SCHEMA_VERSION {
        return Err(LedgerError::InvalidState);
    }
    let expected: BTreeMap<String, String> = SCHEMA
        .split(';')
        .map(str::trim)
        .filter(|s| s.starts_with("CREATE TABLE ") || s.starts_with("CREATE UNIQUE INDEX "))
        .map(|s| {
            (
                s.split_whitespace()
                    .nth(if s.starts_with("CREATE TABLE ") { 2 } else { 3 })
                    .unwrap()
                    .to_owned(),
                s.to_owned(),
            )
        })
        .collect();
    let mut query = connection
        .prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL")
        .map_err(|_| LedgerError::InvalidState)?;
    let actual = query
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|_| LedgerError::InvalidState)?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .map_err(|_| LedgerError::InvalidState)?;
    if actual != expected {
        return Err(LedgerError::InvalidState);
    }
    Ok(())
}
fn lookup(connection: &Connection, id: &str) -> Result<Option<RecordedOperation>, LedgerError> {
    let row = connection
        .query_row(
            "SELECT mandate_id,challenge,outcome FROM operations WHERE operation_id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LedgerError::Unavailable)?;
    row.map(|(mandate_id, challenge, outcome)| {
        Ok(RecordedOperation {
            operation_id: id.into(),
            mandate_id,
            challenge,
            outcome: match outcome.as_str() {
                "claimed" => Outcome::Claimed,
                "rejected" => Outcome::Rejected,
                _ => return Err(LedgerError::InvalidState),
            },
        })
    })
    .transpose()
}
fn record(
    tx: &rusqlite::Transaction<'_>,
    operation: &RecordedOperation,
    wall: u64,
) -> Result<(), LedgerError> {
    let outcome = match operation.outcome {
        Outcome::Claimed => "claimed",
        Outcome::Rejected => "rejected",
    };
    tx.execute(
        "INSERT INTO operations(operation_id,mandate_id,challenge,outcome) VALUES(?1,?2,?3,?4)",
        params![
            operation.operation_id,
            operation.mandate_id,
            operation.challenge,
            outcome
        ],
    )
    .map_err(|_| LedgerError::Unavailable)?;
    tx.execute(
        "INSERT INTO audit(operation_id,transition,wall_seconds) VALUES(?1,?2,?3)",
        params![
            operation.operation_id,
            outcome,
            i64::try_from(wall).map_err(|_| LedgerError::InvalidInput)?
        ],
    )
    .map_err(|_| LedgerError::Unavailable)?;
    Ok(())
}

struct PendingRow {
    issuer_id: String,
    mandate_session: String,
    mandate_state: String,
    mandate_issued: u64,
    mandate_expires: u64,
    mandate_digest: [u8; 32],
    operation_digest: [u8; 32],
    envelope_digest: [u8; 32],
    agent_jkt: [u8; 32],
    audience: String,
    revisions: [u64; 5],
    challenge_session: String,
    challenge_issued: u64,
    challenge_expires: u64,
    challenge_state: String,
    claim_operation_id: Option<String>,
}
fn bytes32(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(index)?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(
            index,
            "bound digest".into(),
            rusqlite::types::Type::Blob,
        )
    })
}
fn pending_row(connection: &Connection, request: &ClaimRequest) -> Result<PendingRow, LedgerError> {
    connection.query_row(
        "SELECT m.issuer_id,m.session_id,m.state,m.issued_at,m.expires_at,
         m.mandate_digest,m.operation_digest,m.envelope_digest,m.agent_jkt,m.audience,
         m.policy_revision,m.issuer_revision,m.principal_revision,m.credential_revision,m.agent_revision,
         c.session_id,c.issued_at,c.expires_at,c.state,c.claim_operation_id
         FROM mandates m JOIN challenges c ON c.mandate_id=m.mandate_id
         WHERE m.mandate_id=?1 AND c.challenge=?2",
        params![request.mandate_id,request.challenge],
        |r| Ok(PendingRow {
            issuer_id:r.get(0)?,mandate_session:r.get(1)?,mandate_state:r.get(2)?,
            mandate_issued:uint(r,3)?,mandate_expires:uint(r,4)?,
            mandate_digest:bytes32(r,5)?,operation_digest:bytes32(r,6)?,envelope_digest:bytes32(r,7)?,agent_jkt:bytes32(r,8)?,
            audience:r.get(9)?,revisions:[uint(r,10)?,uint(r,11)?,uint(r,12)?,uint(r,13)?,uint(r,14)?],
            challenge_session:r.get(15)?,challenge_issued:uint(r,16)?,challenge_expires:uint(r,17)?,
            challenge_state:r.get(18)?,claim_operation_id:r.get(19)?,
        }),
    ).optional().map_err(|_|LedgerError::InvalidState)?.ok_or(LedgerError::Conflict)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Private in-memory fault tests exercise transaction outcomes, not physical
    // durability. Independent integration tests use real temporary databases.
    fn fixture() -> Ledger {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        let binding = Binding {
            installation_id: "1".repeat(32),
            bootstrap_commit_id: "2".repeat(32),
            session_id: "3".repeat(32),
            issuer_id: "4".repeat(32),
            executor_id: "5".repeat(32),
            principal_id: "6".repeat(32),
            issuer_kid: "7".repeat(32),
            provider_reference: "test-only".into(),
            issuer_public_key: vec![1],
        };
        connection
            .execute(
                "INSERT INTO binding VALUES(1,?,?,?,?,?,?,?,?,?,100)",
                params![
                    binding.installation_id,
                    binding.bootstrap_commit_id,
                    binding.session_id,
                    binding.issuer_id,
                    binding.executor_id,
                    binding.principal_id,
                    binding.issuer_kid,
                    binding.provider_reference,
                    binding.issuer_public_key,
                ],
            )
            .unwrap();
        connection
            .execute_batch("INSERT INTO registry VALUES(1,1,1,1,1,1,1,1,1,1)")
            .unwrap();
        connection
            .execute(
                "INSERT INTO mandates VALUES(?1,?2,?3,'approved',100,200,?4,?4,?4,?4,?5,1,1,1,1,1)",
                params![
                    "8".repeat(32),
                    binding.issuer_id,
                    binding.session_id,
                    vec![0u8; 32],
                    binding.executor_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO challenges VALUES(?1,?2,?3,100,120,'pending',NULL)",
                params!["A".repeat(43), "8".repeat(32), binding.session_id],
            )
            .unwrap();
        Ledger {
            connection,
            binding,
            last_wall: 100,
            last_monotonic: Instant::now(),
            poisoned: false,
            lose_commit_ack: false,
        }
    }

    fn request(now: Instant) -> ClaimRequest {
        ClaimRequest {
            operation_id: "a".repeat(32),
            mandate_id: "8".repeat(32),
            challenge: "A".repeat(43),
            policy_revision: 1,
            registry_revisions: [1; 4],
            deadline: now + Duration::from_secs(10),
        }
    }

    #[test]
    fn lost_commit_ack_is_indeterminate_and_never_returns_a_claim() {
        let mut ledger = fixture();
        ledger.lose_commit_ack = true;
        let now = Instant::now();
        assert_eq!(
            ledger
                .claim_submission(
                    request(now),
                    TimeSample {
                        wall_seconds: 101,
                        monotonic: now
                    }
                )
                .unwrap_err(),
            LedgerError::Indeterminate {
                operation_id: "a".repeat(32)
            }
        );
        assert_eq!(
            ledger
                .lookup_operation(&"a".repeat(32))
                .unwrap()
                .unwrap()
                .outcome(),
            Outcome::Claimed
        );
        let state: String = ledger
            .connection
            .query_row("SELECT state FROM challenges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "claimed");
        let audit: i64 = ledger
            .connection
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(audit, 1);
        assert_eq!(
            binding_matches(&ledger.connection, &ledger.binding).unwrap(),
            101
        );
        assert_eq!(
            ledger
                .claim_submission(
                    request(now),
                    TimeSample {
                        wall_seconds: 101,
                        monotonic: now
                    }
                )
                .unwrap_err(),
            LedgerError::Poisoned
        );
    }

    #[test]
    fn deferred_constraint_commit_failure_poisoned_even_when_rollback_succeeds() {
        let mut ledger = fixture();
        let operation = "b".repeat(32);
        let result = ledger.write(&operation, 101, |tx| {
            tx.execute_batch("PRAGMA defer_foreign_keys=ON").unwrap();
            // The insert succeeds; the missing referenced operation fails COMMIT.
            tx.execute("INSERT INTO audit VALUES(?1,'claimed',101)", [&operation])
                .unwrap();
            Ok(())
        });
        assert_eq!(
            result,
            Err(LedgerError::Indeterminate {
                operation_id: operation.clone()
            })
        );
        assert!(ledger.poisoned);
        assert!(ledger.connection.is_autocommit());
        assert!(ledger.lookup_operation(&operation).unwrap().is_none());
        let audit: i64 = ledger
            .connection
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(audit, 0);
        assert_eq!(
            binding_matches(&ledger.connection, &ledger.binding).unwrap(),
            100
        );
        assert_eq!(
            ledger.sample(&TimeSample {
                wall_seconds: 101,
                monotonic: Instant::now()
            }),
            Err(LedgerError::Poisoned)
        );
    }

    #[test]
    fn unresolved_transaction_cannot_report_an_uncommitted_operation() {
        let mut ledger = fixture();
        let operation = "b".repeat(32);
        ledger.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        ledger
            .connection
            .execute(
                "INSERT INTO operations VALUES(?1,?2,?3,'claimed')",
                params![operation, "8".repeat(32), "A".repeat(43)],
            )
            .unwrap();
        // Model the connection state left after failed rollback attempts without
        // relying on filesystem-specific I/O fault injection.
        ledger.poisoned = true;
        assert!(!ledger.connection.is_autocommit());
        assert!(lookup(&ledger.connection, &operation).unwrap().is_some());
        assert_eq!(
            ledger.lookup_operation(&operation),
            Err(LedgerError::InvalidState)
        );
        ledger.connection.execute_batch("ROLLBACK").unwrap();
        assert!(ledger.lookup_operation(&operation).unwrap().is_none());
        assert!(ledger.poisoned);
    }
}
