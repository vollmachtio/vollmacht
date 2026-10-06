//! Proposed time rules only. Not a production validator, clock or state store.
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy)]
struct Window {
    issued: u64,
    expires: u64,
}

impl Window {
    fn valid(self, maximum_ttl: u64) -> bool {
        self.issued <= MAX_INTEGER
            && self.expires <= MAX_INTEGER
            && self
                .expires
                .checked_sub(self.issued)
                .is_some_and(|ttl| ttl > 0 && ttl <= maximum_ttl)
    }

    fn contains(self, other: Self) -> bool {
        self.issued <= other.issued && other.expires <= self.expires
    }

    fn current(self, wall: u64) -> bool {
        self.issued <= wall && wall < self.expires
    }
}

// All fields here represent trusted local observations, not agent input.
// Ticks use arbitrary units; the fixture assumes deadlines were safely capped
// when created. This model does not implement that clock conversion.
#[derive(Clone, Copy)]
struct Local {
    original_session: u64,
    current_session: u64,
    wall_high_water: u64,
    wall_now: u64,
    monotonic_start: u64,
    monotonic_now: u64,
    monotonic_deadline: u64,
}

fn eligible(mandate: Window, pending: Window, proof: Window, local: Local) -> bool {
    mandate.valid(300)
        && pending.valid(30)
        && proof.valid(30)
        && mandate.contains(pending)
        && pending.contains(proof)
        && mandate.current(local.wall_now)
        && pending.current(local.wall_now)
        && proof.current(local.wall_now)
        && local.original_session == local.current_session
        && local.wall_now >= local.wall_high_water
        && local.monotonic_start <= local.monotonic_now
        && local.monotonic_now < local.monotonic_deadline
}

fn fixture() -> (Window, Window, Window, Local) {
    (
        Window {
            issued: 1_000,
            expires: 1_120,
        },
        Window {
            issued: 1_060,
            expires: 1_090,
        },
        Window {
            issued: 1_060,
            expires: 1_090,
        },
        Local {
            original_session: 7,
            current_session: 7,
            wall_high_water: 1_060,
            wall_now: 1_060,
            monotonic_start: 500,
            monotonic_now: 500,
            monotonic_deadline: 530,
        },
    )
}

#[test]
fn mandate_ttl_boundaries_are_literal_not_wrapping_arithmetic() {
    for (issued, expires, expected) in [
        (0, 1, true),
        (0, 300, true),
        (0, 301, false),
        (1_000, 1_000, false),
        (1_000, 999, false),
        (MAX_INTEGER - 300, MAX_INTEGER, true),
        (MAX_INTEGER, MAX_INTEGER + 1, false),
        (u64::MAX, 0, false),
        (u64::MAX - 1, u64::MAX, false),
    ] {
        assert_eq!(Window { issued, expires }.valid(300), expected);
    }
}

#[test]
fn proof_start_is_inclusive_expiry_is_exclusive_without_grace() {
    let (mandate, pending, proof, local) = fixture();
    for (wall_now, expected) in [
        (1_059, false),
        (1_060, true),
        (1_089, true),
        (1_090, false),
        (1_091, false),
    ] {
        assert_eq!(
            eligible(mandate, pending, proof, Local { wall_now, ..local }),
            expected
        );
    }
}

#[test]
fn every_window_requires_positive_bounded_lifetime() {
    let (mandate, pending, proof, local) = fixture();
    for invalid in [
        Window {
            issued: 1_060,
            expires: 1_060,
        },
        Window {
            issued: 1_060,
            expires: 1_059,
        },
        Window {
            issued: 1_060,
            expires: 1_091,
        },
        Window {
            issued: MAX_INTEGER,
            expires: MAX_INTEGER + 1,
        },
    ] {
        assert!(!eligible(mandate, invalid, proof, local));
        assert!(!eligible(mandate, pending, invalid, local));
    }
    assert!(!eligible(
        Window {
            issued: 1_000,
            expires: 1_301
        },
        pending,
        proof,
        local
    ));
}

#[test]
fn proof_subwindow_may_shorten_but_cannot_extend_pending_window() {
    let (mandate, pending, _, local) = fixture();
    for (issued, expires, expected) in [
        (1_060, 1_090, true),
        (1_065, 1_080, true),
        (1_059, 1_080, false),
        (1_065, 1_091, false),
    ] {
        assert_eq!(
            eligible(
                mandate,
                pending,
                Window { issued, expires },
                Local {
                    wall_now: 1_070,
                    ..local
                }
            ),
            expected
        );
    }
    // A proof that has not begun is denied despite a current pending window.
    assert!(!eligible(
        mandate,
        pending,
        Window {
            issued: 1_061,
            expires: 1_080
        },
        local
    ));
}

#[test]
fn pending_window_cannot_escape_mandate_even_with_current_proof() {
    let (_, pending, proof, local) = fixture();
    for mandate in [
        Window {
            issued: 1_061,
            expires: 1_120,
        },
        Window {
            issued: 1_000,
            expires: 1_089,
        },
    ] {
        assert!(!eligible(
            mandate,
            pending,
            proof,
            Local {
                wall_now: 1_070,
                ..local
            }
        ));
    }
    let mandate = Window {
        issued: 1_000,
        expires: 1_090,
    };
    assert!(eligible(mandate, pending, proof, local));
    assert!(!eligible(
        mandate,
        pending,
        proof,
        Local {
            wall_now: 1_090,
            ..local
        }
    ));
}

#[test]
fn trusted_monotonic_expiry_denies_even_if_wall_time_remains_current() {
    let (mandate, pending, proof, local) = fixture();
    for (monotonic_now, expected) in [
        (499, false),
        (500, true),
        (529, true),
        (530, false),
        (531, false),
    ] {
        assert_eq!(
            eligible(
                mandate,
                pending,
                proof,
                Local {
                    monotonic_now,
                    ..local
                }
            ),
            expected
        );
    }
    assert!(!eligible(
        mandate,
        pending,
        proof,
        Local {
            monotonic_deadline: 500,
            ..local
        }
    ));
}

#[test]
fn restart_and_observed_wall_rollback_deny_without_extending_deadlines() {
    let (mandate, pending, proof, local) = fixture();
    assert!(eligible(mandate, pending, proof, local));
    assert!(!eligible(
        mandate,
        pending,
        proof,
        Local {
            current_session: 8,
            ..local
        }
    ));
    assert!(!eligible(
        mandate,
        pending,
        proof,
        Local {
            wall_high_water: 1_061,
            ..local
        }
    ));
    // Forward jumps also cannot add grace to the proof's signed expiry.
    assert!(!eligible(
        mandate,
        pending,
        proof,
        Local {
            wall_now: u64::MAX,
            ..local
        }
    ));
}

#[test]
fn exhaustive_small_windows_match_half_open_interval_membership() {
    for issued in 0..8 {
        for expires in 0..8 {
            let window = Window { issued, expires };
            for now in 0..9 {
                let expected = (issued..expires).contains(&now);
                assert_eq!(window.valid(30) && window.current(now), expected);
            }
        }
    }
}
