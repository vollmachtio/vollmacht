// Standalone policy tests. No controller, timer, UI, Security or native backend.
@main
struct ProbeOperationStateTests {
    enum Failure: Error { case assertion(Int) }
    static func check(_ value: Bool, line: Int = #line) throws {
        guard value else { throw Failure.assertion(line) }
    }

    @MainActor
    static func main() throws {
        typealias State = ProbeOperationState
        // Two views sharing one reference cannot start overlapping old/new work.
        let owner = State(), secondView = owner
        let first = owner.beginLegacy(.create)!
        try check(secondView.beginLegacy(.open) == nil)
        try check(secondView.prepareDiagnostic() == nil)
        try check(!owner.finishLegacy(token: first + 1))
        try check(owner.phase == .legacy(first, .create))
        try check(secondView.finishLegacy(token: first))
        let second = owner.beginLegacy(.open)!
        try check(second != first)
        try check(!owner.finishLegacy(token: first))
        try check(owner.finishLegacy(token: second))
        try check(!owner.finishLegacy(token: second))

        // Exhaust every acknowledgement at each reachable diagnostic stage.
        // Stale token controls use otherwise-valid event shapes, not malformed data.
        for stage in 0...4 {
            for event in State.Acknowledgement.allCases {
                let state = State()
                let id = state.prepareDiagnostic()!
                if stage >= 1 { try check(state.acknowledge(.prepared, token: id)) }
                if stage >= 2 { try check(state.arm(token: id)) }
                if stage >= 3 { try check(state.acknowledge(.armed, token: id)) }
                if stage >= 4 { try check(state.cancel(token: id)) }
                let before = state.phase
                try check(state.beginLegacy(.create) == nil && state.beginLegacy(.open) == nil)
                try check(state.prepareDiagnostic() == nil)
                try check(!state.arm(token: id + 1) && !state.cancel(token: id + 1))
                try check(!state.acknowledge(event, token: id + 1))
                try check(state.phase == before)
                let allowed: Bool
                switch stage {
                case 0: allowed = event == .prepared || event == .preparationFailed
                case 1: allowed = false
                case 2: allowed = [.armed, .armFailed, .completed, .attemptFailed].contains(event)
                case 3: allowed = [.completed, .attemptFailed].contains(event)
                default: allowed = [.cancellationAccepted, .cancellationTerminalFailure, .completed, .attemptFailed].contains(event)
                }
                try check(state.acknowledge(event, token: id) == allowed)
                if !allowed { try check(state.phase == before) }
            }
        }

        for terminal in [State.Acknowledgement.completed, .attemptFailed, .cancellationAccepted, .cancellationTerminalFailure] {
            let state = State()
            let id = state.prepareDiagnostic()!
            try check(state.acknowledge(.prepared, token: id))
            try check(state.arm(token: id))
            try check(!state.arm(token: id))
            try check(!state.cancel(token: id)) // Wait for arm acknowledgement.
            try check(state.acknowledge(.armed, token: id))
            try check(state.cancel(token: id))
            try check(state.phase == .cancelPending(id)) // Not yet cancelled.
            try check(!state.cancel(token: id))
            try check(!state.acknowledge(.cancellationNotApplied, token: id))
            try check(state.phase == .cancelPending(id))
            try check(state.beginLegacy(.create) == nil && state.beginLegacy(.open) == nil)
            try check(state.acknowledge(terminal, token: id))
            let expected: State.Outcome = terminal == .completed ? .completedInconclusive :
                (terminal == .cancellationAccepted ? .cancelled : .failed)
            try check(state.phase == .terminal(id, expected))
            for event in State.Acknowledgement.allCases {
                try check(!state.acknowledge(event, token: id))
            }
            try check(state.prepareDiagnostic() == nil && !state.arm(token: id) && !state.cancel(token: id))
            let legacy = state.beginLegacy(.open)!
            try check(!state.acknowledge(.completed, token: id))
            try check(state.phase == .legacy(legacy, .open))
            try check(state.finishLegacy(token: legacy))
            try check(state.diagnosticSpent && state.prepareDiagnostic() == nil)
        }

        // Failed preparation spends the one diagnostic without permitting retry.
        let failed = State()
        let failedID = failed.prepareDiagnostic()!
        try check(failed.acknowledge(.preparationFailed, token: failedID))
        try check(failed.prepareDiagnostic() == nil)
        try check(failed.beginLegacy(.open) != nil)

        // Completion before an armed acknowledgement must not reopen the gate.
        let reordered = State()
        let id = reordered.prepareDiagnostic()!
        try check(reordered.acknowledge(.prepared, token: id))
        try check(reordered.arm(token: id))
        try check(reordered.acknowledge(.completed, token: id))
        try check(!reordered.acknowledge(.armed, token: id))
        try check(reordered.phase == .terminal(id, .completedInconclusive))
        print("PASS: shared probe operation policy; no native work or UI integration.")
    }
}
