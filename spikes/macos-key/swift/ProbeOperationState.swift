// Fake-testable ownership policy only. A future app must retain ONE instance
// across all windows for the process lifetime. No UI or native work starts here.
@MainActor
final class ProbeOperationState {
    enum Legacy: Equatable { case create, open }
    enum Outcome: Equatable { case failed, cancelled, completedInconclusive }
    enum Phase: Equatable {
        case idle
        case legacy(UInt64, Legacy)
        case preparing(UInt64), prepared(UInt64), arming(UInt64), armed(UInt64), cancelPending(UInt64)
        case terminal(UInt64, Outcome)
    }
    // A future bridge must translate exact trusted controller acknowledgements,
    // not just their phase. Rejection/stale-callback labels are NOT completion.
    // The controller's completion can never establish a verified lock interval.
    enum Acknowledgement: CaseIterable {
        case prepared, preparationFailed, armed, armFailed
        // Only the controller's terminal failed/session_cancel_failed event maps
        // here. cancellation_not_applied must NEVER release the operation gate.
        case cancellationAccepted, cancellationTerminalFailure, cancellationNotApplied
        case completed, attemptFailed
    }

    private(set) var phase: Phase = .idle
    private(set) var diagnosticSpent = false
    private var nextToken: UInt64 = 1

    private var available: Bool {
        switch phase { case .idle, .terminal: return true; default: return false }
    }

    private func allocate() -> UInt64? {
        let (next, overflow) = nextToken.addingReportingOverflow(1)
        guard !overflow else { return nil }
        let token = nextToken
        nextToken = next
        return token
    }

    func beginLegacy(_ operation: Legacy) -> UInt64? {
        guard available, let token = allocate() else { return nil }
        phase = .legacy(token, operation)
        return token
    }

    @discardableResult
    func finishLegacy(token: UInt64) -> Bool {
        guard case .legacy(let active, _) = phase, active == token else { return false }
        phase = .idle
        return true
    }

    func prepareDiagnostic() -> UInt64? {
        guard available, !diagnosticSpent, let token = allocate() else { return nil }
        diagnosticSpent = true // Even failed preparation cannot be retried here.
        phase = .preparing(token)
        return token
    }

    @discardableResult
    func arm(token: UInt64) -> Bool {
        guard phase == .prepared(token) else { return false }
        phase = .arming(token)
        return true
    }

    @discardableResult
    func cancel(token: UInt64) -> Bool {
        guard phase == .armed(token) else { return false }
        phase = .cancelPending(token)
        return true
    }

    @discardableResult
    func acknowledge(_ event: Acknowledgement, token: UInt64) -> Bool {
        let next: Phase
        switch (phase, event) {
        case (.preparing(token), .prepared): next = .prepared(token)
        case (.preparing(token), .preparationFailed): next = .terminal(token, .failed)
        case (.arming(token), .armed): next = .armed(token)
        case (.arming(token), .armFailed): next = .terminal(token, .failed)
        case (.cancelPending(token), .cancellationAccepted): next = .terminal(token, .cancelled)
        case (.cancelPending(token), .cancellationTerminalFailure): next = .terminal(token, .failed)
        // A main-actor hop can deliver completion before the earlier armed
        // notification. Completion wins; later acknowledgements cannot reopen it.
        case (.arming(token), .completed), (.armed(token), .completed), (.cancelPending(token), .completed):
            next = .terminal(token, .completedInconclusive)
        case (.arming(token), .attemptFailed), (.armed(token), .attemptFailed), (.cancelPending(token), .attemptFailed):
            next = .terminal(token, .failed)
        default: return false
        }
        phase = next
        return true
    }
}
