// In-process adapter for the trusted controller, not an external event parser or
// proof of execution. Future UI wiring must preserve observer provenance and
// dispatch onto the main actor before calling this adapter.
@MainActor
enum ProbeEventAdapter {
    @discardableResult
    static func apply(_ event: DelayedDiagnosticEvent, to state: ProbeOperationState) -> Bool {
        let acknowledgement: ProbeOperationState.Acknowledgement
        switch (event.phase, event.result) {
        case (.prepared, "existing_key_prepared"): acknowledgement = .prepared
        case (.failed, "preparation_failed"): acknowledgement = .preparationFailed
        case (.armed, "one_attempt_scheduled"): acknowledgement = .armed
        case (.failed, "clock_invalid"), (.failed, "window_overflow"), (.failed, "session_arm_failed"):
            acknowledgement = .armFailed
        case (.cancelled, "cancelled_before_attempt"): acknowledgement = .cancellationAccepted
        case (.failed, "session_cancel_failed"): acknowledgement = .cancellationTerminalFailure
        case (.failed, "attempt_binding_mismatch"), (.failed, "unexpected_lock_evidence"), (.failed, "attempt_failed_no_retry"):
            acknowledgement = .attemptFailed
        case (.finished, "inconclusive_callback_outside_window"): acknowledgement = .completed
        case (.finished, let summary) where validSummary(summary): acknowledgement = .completed
        default: return false
        }
        return state.acknowledge(acknowledgement, token: event.runID)
    }

    private static func validSummary(_ value: String) -> Bool {
        // Exact bounded controller grammar. Unknown/reordered/extra fields and
        // malformed status values must not turn a message into terminal evidence.
        guard value.utf8.count <= 256, value.utf8.allSatisfy({ $0 < 128 }) else { return false }
        let parts = value.split(separator: ";", omittingEmptySubsequences: false)
        guard parts.count == 5, parts[0] == "inconclusive_lock_state" else { return false }
        for (field, name) in zip(parts[1...3], ["record=", "lookup=", "sign="]) {
            guard field.hasPrefix(name), validOutcome(field.dropFirst(name.count)) else { return false }
        }
        return ["timing=withinWindow", "timing=late", "timing=discontinuous"].contains(parts[4])
    }

    private static func validOutcome(_ value: Substring) -> Bool {
        if ["not_attempted", "succeeded", "denied", "missing", "ambiguous", "pin_mismatch"].contains(value) {
            return true
        }
        guard value.hasPrefix("failed_"), let code = Int32(value.dropFirst(7)) else { return false }
        return value == "failed_\(code)"
    }
}
