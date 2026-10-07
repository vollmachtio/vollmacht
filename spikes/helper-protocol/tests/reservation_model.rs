//! Candidate state rules only: no database, cryptography, clock or network.
use std::collections::BTreeMap;

type Key = (u8, u8); // Synthetic issuer and mandate IDs, not serialized identities.
type Digests = (u8, u8); // Synthetic payload/envelope fingerprints, not hashes.
const KEY: Key = (1, 1);
const DIGESTS: Digests = (10, 20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Approved,
    Reserved,
    Succeeded,
    Failed,
    Unknown,
    Invalidated,
}

#[derive(Clone, Debug)]
struct Record {
    digests: Digests,
    policy: u8,
    state: State,
    reservations: u8,
    dispatches: u8,
}

#[derive(Clone, Debug)]
struct Model {
    records: BTreeMap<Key, Record>,
    revoked: bool,
    enabled: bool,
    policy: u8,
    deadline_valid: bool,
}

#[derive(Clone, Copy, Debug)]
enum Event {
    Reserve,
    Dispatch,
    Succeed,
    Fail,
    Timeout,
    Revoke,
    Disable,
    ChangePolicy,
    Expire,
    Restart,
    Reapprove,
    AlternateSignature,
    ChangedPayload,
    ChangedEnvelope,
}

impl Model {
    fn new() -> Self {
        let mut model = Self {
            records: BTreeMap::new(),
            revoked: false,
            enabled: true,
            policy: 1,
            deadline_valid: true,
        };
        assert!(model.approve(KEY, DIGESTS, 1));
        model
    }

    fn approve(&mut self, key: Key, digests: Digests, _signature: u8) -> bool {
        // Signature bytes never select a row or make an existing identity fresh.
        if self.records.contains_key(&key) {
            return false;
        }
        self.records.insert(
            key,
            Record {
                digests,
                policy: self.policy,
                state: State::Approved,
                reservations: 0,
                dispatches: 0,
            },
        );
        true
    }

    fn reserve(&mut self, key: Key, expected: Digests) -> bool {
        let Some(record) = self.records.get_mut(&key) else {
            return false;
        };
        // One indivisible modeled transition stands in for a future transaction.
        // A one-use agent challenge is assumed valid here, not verified or stored.
        if record.state != State::Approved
            || record.digests != expected
            || self.revoked
            || !self.enabled
            || record.policy != self.policy
            || !self.deadline_valid
        {
            return false;
        }
        record.state = State::Reserved;
        record.reservations += 1;
        true
    }

    fn apply(&mut self, event: Event) -> bool {
        match event {
            Event::Reserve => return self.reserve(KEY, DIGESTS),
            Event::Reapprove => return self.approve(KEY, DIGESTS, 1),
            Event::AlternateSignature => return self.approve(KEY, DIGESTS, 2),
            Event::ChangedPayload => return self.approve(KEY, (11, 20), 1),
            Event::ChangedEnvelope => return self.approve(KEY, (10, 21), 1),
            Event::Revoke => self.revoked = true,
            Event::Disable => self.enabled = false,
            Event::ChangePolicy => self.policy = 2,
            Event::Expire => self.deadline_valid = false,
            Event::Restart => {
                // Retention is an assumption of this model, not crash persistence.
                for record in self.records.values_mut() {
                    record.state = match record.state {
                        State::Approved => State::Invalidated,
                        State::Reserved => State::Unknown,
                        state => state,
                    };
                }
            }
            Event::Dispatch | Event::Succeed | Event::Fail | Event::Timeout => {
                let record = self.records.get_mut(&KEY).unwrap();
                if record.state != State::Reserved {
                    return false;
                }
                match event {
                    Event::Dispatch => {
                        if record.dispatches != 0 {
                            return false;
                        }
                        if !self.deadline_valid {
                            record.state = State::Failed;
                            return false;
                        }
                        record.dispatches += 1;
                    }
                    Event::Succeed => {
                        if record.dispatches != 1 {
                            return false;
                        }
                        record.state = State::Succeeded;
                    }
                    Event::Fail => record.state = State::Failed,
                    Event::Timeout => record.state = State::Unknown,
                    _ => unreachable!(),
                }
            }
        }
        true
    }
}

#[test]
fn ordered_cutoff_and_terminal_cases() {
    use Event::*;
    let cases: &[(&[Event], State, u8)] = &[
        (&[Revoke, Reserve, Dispatch], State::Approved, 0),
        (&[Disable, Reserve, Dispatch], State::Approved, 0),
        (&[ChangePolicy, Reserve, Dispatch], State::Approved, 0),
        (&[Expire, Reserve, Dispatch], State::Approved, 0),
        (&[Reserve, Revoke, Dispatch, Succeed], State::Succeeded, 1),
        (
            &[Reserve, Disable, ChangePolicy, Dispatch],
            State::Reserved,
            1,
        ),
        (&[Reserve, Expire, Dispatch, Reserve], State::Failed, 0),
        (&[Reserve, Fail, Reserve, Dispatch], State::Failed, 0),
        (&[Reserve, Dispatch, Fail, Dispatch], State::Failed, 1),
        (&[Reserve, Dispatch, Timeout, Succeed], State::Unknown, 1),
        (&[Reserve, Dispatch, Succeed, Dispatch], State::Succeeded, 1),
        (&[Reserve, Reserve, Dispatch, Dispatch], State::Reserved, 1),
        (&[Succeed, Dispatch], State::Approved, 0),
    ];
    for (events, state, dispatches) in cases {
        let mut model = Model::new();
        for event in *events {
            model.apply(*event);
        }
        assert_eq!(model.records[&KEY].state, *state, "{events:?}");
        assert_eq!(model.records[&KEY].dispatches, *dispatches, "{events:?}");
    }
}

#[test]
fn restart_burns_unreserved_approvals_and_preserves_consumption() {
    use Event::*;
    for (prefix, state, dispatches) in [
        (vec![], State::Invalidated, 0),
        (vec![Reserve], State::Unknown, 0),
        (vec![Reserve, Dispatch], State::Unknown, 1),
        (vec![Reserve, Dispatch, Succeed], State::Succeeded, 1),
        (vec![Reserve, Fail], State::Failed, 0),
    ] {
        let mut model = Model::new();
        for event in prefix {
            model.apply(event);
        }
        model.apply(Restart);
        let reservations = model.records[&KEY].reservations;
        for event in [Reapprove, AlternateSignature, Reserve, Dispatch] {
            assert!(!model.apply(event));
        }
        assert_eq!(model.records[&KEY].state, state);
        assert_eq!(model.records[&KEY].dispatches, dispatches);
        assert_eq!(model.records[&KEY].reservations, reservations);
    }
}

#[test]
fn identity_is_issuer_and_mandate_not_signature_or_replacement_digest() {
    let mut model = Model::new();
    for signature in 0..=255 {
        assert!(!model.approve(KEY, DIGESTS, signature));
    }
    for digests in [(11, 20), (10, 21), (11, 21)] {
        assert!(!model.approve(KEY, digests, 1));
        assert!(!model.reserve(KEY, digests));
    }
    assert!(!model.reserve((9, 9), DIGESTS));
    assert_eq!(model.records[&KEY].digests, DIGESTS);
    assert!(model.approve((2, 1), DIGESTS, 1));
    assert!(model.approve((1, 2), DIGESTS, 1));
    for key in [KEY, (2, 1), (1, 2)] {
        assert!(model.reserve(key, DIGESTS));
        assert!(!model.reserve(key, DIGESTS));
    }
    assert_eq!(model.records.len(), 3);
}

#[test]
fn all_short_event_sequences_preserve_one_consumption_and_no_terminal_escape() {
    use Event::*;
    const EVENTS: [Event; 14] = [
        Reserve,
        Dispatch,
        Succeed,
        Fail,
        Timeout,
        Revoke,
        Disable,
        ChangePolicy,
        Expire,
        Restart,
        Reapprove,
        AlternateSignature,
        ChangedPayload,
        ChangedEnvelope,
    ];

    fn explore(model: &Model, depth: usize, checked: &mut usize) {
        if depth == 0 {
            return;
        }
        for event in EVENTS {
            let mut next = model.clone();
            next.apply(event);
            let before = &model.records[&KEY];
            let after = &next.records[&KEY];
            assert_eq!(next.records.len(), model.records.len(), "{event:?}");
            assert_eq!(after.digests, before.digests, "{event:?}");
            assert!(after.reservations <= 1 && after.dispatches <= after.reservations);
            assert!(
                after.reservations >= before.reservations && after.dispatches >= before.dispatches
            );
            if before.state != State::Approved {
                assert_ne!(after.state, State::Approved, "{event:?}");
            }
            if matches!(
                before.state,
                State::Succeeded | State::Failed | State::Unknown | State::Invalidated
            ) {
                assert_eq!(after.state, before.state, "{event:?}");
                assert_eq!(after.dispatches, before.dispatches, "{event:?}");
            }
            *checked += 1;
            explore(&next, depth - 1, checked);
        }
    }
    let mut checked = 0;
    explore(&Model::new(), 4, &mut checked);
    assert_eq!(
        checked,
        14 + 14_usize.pow(2) + 14_usize.pow(3) + 14_usize.pow(4)
    );
}
