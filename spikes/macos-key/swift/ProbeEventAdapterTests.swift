@main
struct ProbeEventAdapterTests {
    enum Failure: Error { case assertion(Int) }
    static func check(_ value: Bool, line: Int = #line) throws {
        guard value else { throw Failure.assertion(line) }
    }

    @MainActor
    static func state(at stage: Int) -> (ProbeOperationState, UInt64) {
        let state = ProbeOperationState()
        let id = state.prepareDiagnostic()!
        if stage >= 1 { state.acknowledge(.prepared, token: id) }
        if stage >= 2 { state.arm(token: id) }
        if stage >= 3 { state.acknowledge(.armed, token: id) }
        if stage >= 4 { state.cancel(token: id) }
        return (state, id)
    }

    static let summary = "inconclusive_lock_state;record=succeeded;lookup=denied;sign=failed_-25308;timing=withinWindow"

    @MainActor
    static func main() throws {
        let phases: [DelayedDiagnosticPhase] = [.idle, .prepared, .armed, .attempting, .cancelled, .finished, .failed]
        let fixtures: [(DelayedDiagnosticPhase, String, Set<Int>)] = [
            (.prepared, "existing_key_prepared", [0]),
            (.failed, "preparation_failed", [0]),
            (.armed, "one_attempt_scheduled", [2]),
            (.failed, "clock_invalid", [2]), (.failed, "window_overflow", [2]), (.failed, "session_arm_failed", [2]),
            (.cancelled, "cancelled_before_attempt", [4]), (.failed, "session_cancel_failed", [4]),
            (.failed, "attempt_binding_mismatch", [2, 3, 4]),
            (.failed, "unexpected_lock_evidence", [2, 3, 4]),
            (.failed, "attempt_failed_no_retry", [2, 3, 4]),
            (.finished, "inconclusive_callback_outside_window", [2, 3, 4]),
            (.finished, summary, [2, 3, 4]),
        ]
        // Every known event paired with every controller phase and UI lifecycle.
        for (expectedPhase, label, allowed) in fixtures {
            for phase in phases {
                for stage in 0...4 {
                    let (owner, id) = state(at: stage)
                    let before = owner.phase
                    try check(!ProbeEventAdapter.apply(.init(runID: id + 1, phase: phase, result: label), to: owner))
                    try check(owner.phase == before)
                    let accepted = ProbeEventAdapter.apply(.init(runID: id, phase: phase, result: label), to: owner)
                    try check(accepted == (phase == expectedPhase && allowed.contains(stage)))
                    if !accepted { try check(owner.phase == before) }
                }
            }
        }
        let rejectionLabels = ["duplicate_prepare_rejected", "arm_rejected", "cancellation_not_applied", "stale_callback_ignored", "unknown", ""]
        for phase in phases {
            for label in rejectionLabels {
                let (owner, id) = state(at: 4)
                try check(!ProbeEventAdapter.apply(.init(runID: id, phase: phase, result: label), to: owner))
                try check(owner.phase == .cancelPending(id))
                try check(owner.beginLegacy(.create) == nil && owner.beginLegacy(.open) == nil)
            }
        }
        let outcomes = ["not_attempted", "succeeded", "denied", "missing", "ambiguous", "pin_mismatch",
                        "failed_0", "failed_-2147483648", "failed_2147483647"]
        for outcome in outcomes {
            for timing in ["withinWindow", "late", "discontinuous"] {
                let (owner, id) = state(at: 2)
                let value = "inconclusive_lock_state;record=\(outcome);lookup=\(outcome);sign=\(outcome);timing=\(timing)"
                try check(ProbeEventAdapter.apply(.init(runID: id, phase: .finished, result: value), to: owner))
                try check(owner.phase == .terminal(id, .completedInconclusive))
                try check(!ProbeEventAdapter.apply(.init(runID: id, phase: .armed, result: "one_attempt_scheduled"), to: owner))
                try check(!ProbeEventAdapter.apply(.init(runID: id, phase: .finished, result: value), to: owner))
            }
        }
        let malformed = [summary + ";", summary + "\n", String(repeating: "x", count: 257),
                         "inconclusive_lock_state", "verified_lock_state;record=succeeded;lookup=succeeded;sign=succeeded;timing=withinWindow",
                         "inconclusive_lock_state;lookup=succeeded;record=succeeded;sign=succeeded;timing=withinWindow"]
        let badOutcomes = ["failed_+1", "failed_01", "failed_-0", "failed_2147483648", "failed_-2147483649", "failed_", "failed_1x", "failed_١", "yes", "", "succeeded;extra=x"]
        for value in malformed + badOutcomes.map({ "inconclusive_lock_state;record=\($0);lookup=succeeded;sign=succeeded;timing=withinWindow" }) +
            ["inconclusive_lock_state;record=succeeded;lookup=succeeded;sign=succeeded;timing=verified"] {
            let (owner, id) = state(at: 4)
            try check(!ProbeEventAdapter.apply(.init(runID: id, phase: .finished, result: value), to: owner))
            try check(owner.phase == .cancelPending(id))
            try check(owner.beginLegacy(.open) == nil)
        }
        // Idle and old-operation states cannot consume a diagnostic event.
        let owner = ProbeOperationState()
        for (_, label, _) in fixtures {
            try check(!ProbeEventAdapter.apply(.init(runID: 1, phase: .finished, result: label), to: owner))
        }
        let old = owner.beginLegacy(.open)!
        try check(!ProbeEventAdapter.apply(.init(runID: old, phase: .finished, result: summary), to: owner))
        try check(owner.phase == .legacy(old, .open))
        print("PASS: exact controller event adapter; fake-only, no UI or native operations.")
    }
}
