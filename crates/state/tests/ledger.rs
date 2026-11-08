//! Independent persistence tests. Fixture SQL is trusted test setup, not bootstrap.
use rusqlite::{Connection, params};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use vollmacht_state::{Binding, ClaimRequest, Ledger, LedgerError, TimeSample};

const WALL: u64 = 1_800_000_061;
fn id(byte: char) -> String {
    byte.to_string().repeat(32)
}
fn binding() -> Binding {
    Binding {
        installation_id: id('1'),
        bootstrap_commit_id: id('2'),
        session_id: id('3'),
        issuer_id: id('4'),
        executor_id: id('5'),
        principal_id: id('6'),
        issuer_kid: id('7'),
        provider_reference: "fixture-provider".into(),
        issuer_public_key: vec![1, 2, 3],
    }
}
fn sample(now: Instant) -> TimeSample {
    TimeSample {
        wall_seconds: WALL,
        monotonic: now,
    }
}
fn claim(now: Instant, operation: char) -> ClaimRequest {
    ClaimRequest {
        operation_id: id(operation),
        mandate_id: id('8'),
        challenge: "DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw".into(),
        policy_revision: 1,
        registry_revisions: [1, 2, 3, 4],
        deadline: now + Duration::from_secs(20),
    }
}
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn seeded() -> Self {
        let f = Self::empty();
        let db = f.sql();
        db.execute_batch(include_str!("../src/schema.sql")).unwrap();
        let b = binding();
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
                1_800_000_061_i64
            ],
        )
        .unwrap();
        db.execute_batch("INSERT INTO registry VALUES(1,1,1,2,3,4,1,1,1,1)")
            .unwrap();
        db.execute(
            "INSERT INTO mandates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                id('8'),
                id('4'),
                id('3'),
                "approved",
                1_800_000_060_i64,
                1_800_000_121_i64,
                vec![1u8; 32],
                vec![2u8; 32],
                vec![3u8; 32],
                vec![4u8; 32],
                id('5'),
                1,
                1,
                2,
                3,
                4
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,?,NULL)",
            params![
                claim(Instant::now(), 'a').challenge,
                id('8'),
                id('3'),
                1_800_000_060_i64,
                1_800_000_081_i64,
                "pending"
            ],
        )
        .unwrap();
        drop(db);
        f
    }
    fn empty() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("vollmacht-ledger-test-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let path = directory.join("fixture.sqlite");
        Self { directory, path }
    }
    fn path(&self) -> &Path {
        &self.path
    }
    fn sql(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    fn state(&self) -> String {
        self.sql()
            .query_row("SELECT state FROM challenges", [], |r| r.get(0))
            .unwrap()
    }
    fn operation_count(&self) -> i64 {
        self.sql()
            .query_row("SELECT count(*) FROM operations", [], |r| r.get(0))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Delete only this randomly named directory that this test created.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn opening_missing_database_never_creates_it() {
    let fixture = Fixture::empty();
    assert!(Ledger::open_existing(fixture.path(), binding(), sample(Instant::now())).is_err());
    assert!(!fixture.path().exists());
}

#[test]
fn two_connections_have_one_durable_claim_winner() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let first = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let second = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .enumerate()
        .map(|(i, mut ledger)| {
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                ledger
                    .claim_submission(claim(now, if i == 0 { 'a' } else { 'b' }), sample(now))
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(f.state(), "claimed");
    assert_eq!(f.operation_count(), 1);
    assert_eq!(
        f.sql()
            .query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn unrelated_submission_cannot_consume_a_matching_challenge() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let mut unrelated = claim(now, 'a');
    unrelated.challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    assert!(ledger.claim_submission(unrelated, sample(now)).is_err());
    assert_eq!(f.state(), "pending");
    assert_eq!(f.operation_count(), 0);
    let mut reopened = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    assert!(
        reopened
            .claim_submission(claim(now, 'b'), sample(now))
            .is_ok()
    );
}

#[test]
fn discarded_acknowledged_receipts_and_rejections_remain_consumed_on_reopen() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let receipt = ledger
        .claim_submission(claim(now, 'a'), sample(now))
        .unwrap();
    assert_eq!(receipt.snapshot().mandate_digest, [1; 32]);
    assert_eq!(receipt.snapshot().operation_digest, [2; 32]);
    assert_eq!(receipt.snapshot().envelope_digest, [3; 32]);
    assert_eq!(receipt.snapshot().registry_revisions, [1, 2, 3, 4]);
    assert!(ledger.lookup_operation(&id('a')).unwrap().is_some());
    ledger
        .finish_rejected(&receipt, &id('b'), sample(now))
        .unwrap();
    drop(ledger);
    drop(receipt);
    let mut reopened = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    assert!(reopened.lookup_operation(&id('a')).unwrap().is_some());
    assert!(reopened.lookup_operation(&id('b')).unwrap().is_some());
    assert!(
        reopened
            .claim_submission(claim(now, 'c'), sample(now))
            .is_err()
    );
    assert_eq!(f.state(), "rejected");
    assert_eq!(f.operation_count(), 2);
    let db = f.sql();
    let mut query = db
        .prepare("SELECT operation_id,transition FROM audit ORDER BY operation_id")
        .unwrap();
    let rows: Vec<(String, String)> = query
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        rows,
        vec![(id('a'), "claimed".into()), (id('b'), "rejected".into())]
    );
    let other = Fixture::seeded();
    let mut ledger = Ledger::open_existing(other.path(), binding(), sample(now)).unwrap();
    drop(
        ledger
            .claim_submission(claim(now, 'd'), sample(now))
            .unwrap(),
    );
    drop(ledger);
    let mut reopened = Ledger::open_existing(other.path(), binding(), sample(now)).unwrap();
    assert!(reopened.lookup_operation(&id('d')).unwrap().is_some());
    assert!(
        reopened
            .claim_submission(claim(now, 'e'), sample(now))
            .is_err()
    );
    assert_eq!(other.state(), "claimed");
}

#[test]
fn failure_after_challenge_update_rolls_back_and_poisons_the_writer() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    // Trusted fault setup only. An orphan audit collision makes record() fail
    // after the claim UPDATE and operation INSERT inside the transaction.
    let db = f.sql();
    db.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    db.execute(
        "INSERT INTO audit VALUES(?,'claimed',?)",
        params![id('a'), 1_800_000_061_i64],
    )
    .unwrap();
    let result = ledger.claim_submission(claim(now, 'a'), sample(now));
    assert!(
        matches!(result,Err(LedgerError::Indeterminate{operation_id}) if operation_id==id('a'))
    );
    assert_eq!(f.state(), "pending");
    assert_eq!(f.operation_count(), 0);
    assert!(ledger.lookup_operation(&id('a')).unwrap().is_none());
    assert!(matches!(
        ledger.claim_submission(claim(now, 'b'), sample(now)),
        Err(LedgerError::Poisoned)
    ));
}

#[test]
fn new_challenge_after_rejection_preserves_history_but_active_duplicates_fail() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let next = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let insert = || {
        f.sql().execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,?,NULL)",
            params![
                next,
                id('8'),
                id('3'),
                1_800_000_060_i64,
                1_800_000_081_i64,
                "pending"
            ],
        )
    };
    assert!(insert().is_err());
    let receipt = ledger
        .claim_submission(claim(now, 'a'), sample(now))
        .unwrap();
    assert!(insert().is_err());
    ledger
        .finish_rejected(&receipt, &id('b'), sample(now))
        .unwrap();
    insert().unwrap();
    let mut new_request = claim(now, 'c');
    new_request.challenge = next.into();
    let new_receipt = ledger.claim_submission(new_request, sample(now)).unwrap();
    assert_ne!(new_receipt.challenge(), receipt.challenge());
    assert!(ledger.lookup_operation(&id('a')).unwrap().is_some());
    assert!(ledger.lookup_operation(&id('b')).unwrap().is_some());
    assert_eq!(
        f.sql()
            .query_row("SELECT count(*) FROM challenges", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(f.operation_count(), 3);
}

#[test]
fn revision_status_session_and_time_mismatches_deny_without_claim() {
    for case in 0..7 {
        let f = Fixture::seeded();
        let now = Instant::now();
        let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
        let mut request = claim(now, 'a');
        let mut time = sample(now);
        match case {
            0 => request.policy_revision += 1,
            1 => request.registry_revisions[2] += 1,
            2 => {
                f.sql()
                    .execute_batch("UPDATE registry SET agent_enabled=0")
                    .unwrap();
            }
            3 => {
                f.sql()
                    .execute("UPDATE challenges SET session_id=?", [id('9')])
                    .unwrap();
            }
            4 => time.wall_seconds = WALL + 20,
            5 => time.monotonic = request.deadline,
            _ => time.wall_seconds = WALL - 1,
        }
        assert!(
            ledger.claim_submission(request, time).is_err(),
            "case {case}"
        );
        assert_eq!(f.state(), "pending");
        assert_eq!(f.operation_count(), 0);
    }
}

#[test]
fn metadata_and_schema_substitution_fail_closed() {
    for case in 0..6 {
        let f = Fixture::seeded();
        let mut b = binding();
        match case {
            0 => b.installation_id = id('9'),
            1 => b.bootstrap_commit_id = id('9'),
            2 => b.issuer_public_key.push(4),
            3 => {
                f.sql().execute_batch("PRAGMA user_version=2").unwrap();
            }
            4 => {
                f.sql()
                    .execute_batch("CREATE TABLE extra(value TEXT)")
                    .unwrap();
            }
            _ => {
                f.sql().execute_batch("DROP TABLE audit").unwrap();
            }
        }
        assert!(
            Ledger::open_existing(f.path(), b, sample(Instant::now())).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn failed_write_transaction_cannot_leave_a_partial_claim() {
    let f = Fixture::seeded();
    let now = Instant::now();
    let mut ledger = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    let blocker = f.sql();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(
        ledger
            .claim_submission(claim(now, 'a'), sample(now))
            .is_err()
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.state(), "pending");
    assert_eq!(f.operation_count(), 0);
    let mut reopened = Ledger::open_existing(f.path(), binding(), sample(now)).unwrap();
    assert!(
        reopened
            .claim_submission(claim(now, 'b'), sample(now))
            .is_ok()
    );
}
