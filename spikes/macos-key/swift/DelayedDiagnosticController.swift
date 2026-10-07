// Delayed diagnostic plumbing. No native backend construction, UI or lock evidence.
import Foundation
import Dispatch
import Synchronization

protocol DelayedDiagnosticClock: DiagnosticClock, Sendable {
    func checkedNow() -> DiagnosticInstant?
}

struct ContinuousDiagnosticClock: DelayedDiagnosticClock {
    private let origin = ContinuousClock.now

    static func milliseconds(seconds: Int64, attoseconds: Int64) -> UInt64? {
        guard seconds >= 0, attoseconds >= 0, attoseconds < 1_000_000_000_000_000_000,
              let seconds = UInt64(exactly: seconds) else { return nil }
        let (whole, overflow) = seconds.multipliedReportingOverflow(by: 1000)
        guard !overflow else { return nil }
        let (total, additionOverflow) = whole.addingReportingOverflow(UInt64(attoseconds / 1_000_000_000_000_000))
        return additionOverflow ? nil : total
    }

    func checkedNow() -> DiagnosticInstant? {
        let elapsed = origin.duration(to: ContinuousClock.now).components
        guard let value = Self.milliseconds(seconds: elapsed.seconds, attoseconds: elapsed.attoseconds) else { return nil }
        // ContinuousClock includes sleep. Constant continuity is not evidence
        // that suspension did not occur; completion never certifies screen lock.
        return DiagnosticInstant(milliseconds: value, continuity: 1)
    }

    mutating func now() -> DiagnosticInstant {
        checkedNow() ?? DiagnosticInstant(milliseconds: UInt64.max, continuity: UInt64.max)
    }
}

protocol DelayedDiagnosticScheduling: Sendable {
    // Production implementations must dispatch asynchronously to one non-UI
    // serial worker. Never invoke callbacks inline or reentrantly.
    func enqueue(_ operation: @escaping @Sendable () -> Void)
    func after(milliseconds: UInt64, _ operation: @escaping @Sendable () -> Void)
}

final class SerialDiagnosticScheduler: DelayedDiagnosticScheduling {
    private let queue = DispatchQueue(label: "io.vollmacht.experimental.diagnostic-worker")
    func enqueue(_ operation: @escaping @Sendable () -> Void) { queue.async(execute: operation) }
    func after(milliseconds: UInt64, _ operation: @escaping @Sendable () -> Void) {
        // Controller supplies only the fixed 15-second delay.
        guard let bounded = Int(exactly: milliseconds), bounded <= 120_000 else { return }
        queue.asyncAfter(deadline: .now() + .milliseconds(bounded), execute: operation)
    }
}

protocol DelayedDiagnosticDriving {
    mutating func arm(notBefore: UInt64, deadline: UInt64) throws
    mutating func cancel() throws
    mutating func attempt() throws -> DiagnosticAttempt
    mutating func complete(runID: UInt64) throws -> DiagnosticReport
}

private struct SessionClock: DiagnosticClock {
    let clock: any DelayedDiagnosticClock
    mutating func now() -> DiagnosticInstant {
        clock.checkedNow() ?? DiagnosticInstant(milliseconds: UInt64.max, continuity: UInt64.max)
    }
}

struct OwnedSessionDriver<B: RuntimeBackend>: DelayedDiagnosticDriving {
    private let session: DiagnosticSession<B, SessionClock>
    // Must be called by the controller's worker factory, not prepared on the UI
    // thread and handed over. Factory must not retain mutable reference aliases.
    init(request: KeyRequest, expectedPublic: Data, runID: UInt64, backend: B, clock: any DelayedDiagnosticClock) throws {
        session = try DiagnosticSession(request: request, expectedPublic: expectedPublic,
                                        runID: runID, backend: backend, clock: SessionClock(clock: clock))
    }
    mutating func arm(notBefore: UInt64, deadline: UInt64) throws { try session.arm(notBefore: notBefore, deadline: deadline) }
    mutating func cancel() throws { try session.cancel() }
    mutating func attempt() throws -> DiagnosticAttempt { try session.attempt() }
    mutating func complete(runID: UInt64) throws -> DiagnosticReport { try session.complete(runID: runID) }
}

enum DelayedDiagnosticPhase: String, Sendable {
    case idle, prepared, armed, attempting, cancelled, finished, failed
}

struct DelayedDiagnosticEvent: Sendable {
    let runID: UInt64
    let phase: DelayedDiagnosticPhase
    // Bounded protocol labels, never raw error descriptions or key bytes.
    let result: String
}

private struct DelayedState {
    var phase: DelayedDiagnosticPhase = .idle
    var driver: (any DelayedDiagnosticDriving)?
    var notBefore: UInt64 = 0
    var deadline: UInt64 = 0
    var continuity: UInt64 = 0
}

// Factories, drivers and clocks run while private state is locked. They must not
// synchronously reenter the controller or retain/return its owned session. Only
// observers execute outside the lock and may enqueue follow-up commands.
final class DelayedDiagnosticController: Sendable {
    private let state = Mutex(DelayedState())
    private let runID: UInt64
    private let clock: any DelayedDiagnosticClock
    private let scheduler: any DelayedDiagnosticScheduling
    private let factory: @Sendable (UInt64, any DelayedDiagnosticClock) throws -> any DelayedDiagnosticDriving
    private let observer: @Sendable (DelayedDiagnosticEvent) -> Void

    init(runID: UInt64, clock: any DelayedDiagnosticClock, scheduler: any DelayedDiagnosticScheduling = SerialDiagnosticScheduler(),
         factory: @escaping @Sendable (UInt64, any DelayedDiagnosticClock) throws -> any DelayedDiagnosticDriving,
         observer: @escaping @Sendable (DelayedDiagnosticEvent) -> Void) {
        self.runID = runID
        self.clock = clock
        self.scheduler = scheduler
        self.factory = factory
        self.observer = observer
    }

    private func event(_ phase: DelayedDiagnosticPhase, _ result: String) -> DelayedDiagnosticEvent {
        DelayedDiagnosticEvent(runID: runID, phase: phase, result: result)
    }

    func prepare() {
        scheduler.enqueue { [self] in
            let value = state.withLock { state in
                guard state.phase == .idle else { return event(state.phase, "duplicate_prepare_rejected") }
                do {
                    state.driver = try factory(runID, clock)
                    state.phase = .prepared
                    return event(.prepared, "existing_key_prepared")
                } catch {
                    state.phase = .failed
                    return event(.failed, "preparation_failed")
                }
            }
            observer(value) // Never call observers while holding private state.
        }
    }

    func arm() {
        scheduler.enqueue { [self] in
            let value = state.withLock { state in
                guard state.phase == .prepared else { return event(state.phase, "arm_rejected") }
                guard let now = clock.checkedNow() else { state.phase = .failed; return event(.failed, "clock_invalid") }
                let (start, firstOverflow) = now.milliseconds.addingReportingOverflow(15_000)
                let (end, secondOverflow) = start.addingReportingOverflow(5_000)
                guard !firstOverflow && !secondOverflow else { state.phase = .failed; return event(.failed, "window_overflow") }
                do { try state.driver?.arm(notBefore: start, deadline: end) }
                catch { state.phase = .failed; return event(.failed, "session_arm_failed") }
                state.notBefore = start
                state.deadline = end
                state.continuity = now.continuity
                state.phase = .armed
                return event(.armed, "one_attempt_scheduled")
            }
            if value.phase == .armed && value.result == "one_attempt_scheduled" {
                let scheduledID = runID
                scheduler.after(milliseconds: 15_000) { [self] in fire(runID: scheduledID) }
            }
            observer(value)
        }
    }

    func cancel() {
        scheduler.enqueue { [self] in
            let value = state.withLock { state in
                guard state.phase == .armed else { return event(state.phase, "cancellation_not_applied") }
                do { try state.driver?.cancel() }
                catch { state.phase = .failed; return event(.failed, "session_cancel_failed") }
                state.phase = .cancelled
                return event(.cancelled, "cancelled_before_attempt")
            }
            observer(value)
        }
    }

    private func fire(runID scheduledID: UInt64) {
        let value = state.withLock { state in
            guard scheduledID == runID, state.phase == .armed else { return event(state.phase, "stale_callback_ignored") }
            state.phase = .attempting // Consumed before any driver operation.
            guard let now = clock.checkedNow(), now.continuity == state.continuity,
                  now.milliseconds >= state.notBefore, now.milliseconds <= state.deadline else {
                // A late callback cannot start the driver. An already entered
                // synchronous operation cannot be interrupted and may finish
                // after the deadline; all reported lock states stay inconclusive.
                // No rescheduling, retries or claims that operations aborted.
                state.phase = .finished
                return event(.finished, "inconclusive_callback_outside_window")
            }
            do {
                guard let attempt = try state.driver?.attempt(), attempt.runID == runID else {
                    state.phase = .failed
                    return event(.failed, "attempt_binding_mismatch")
                }
                guard let report = try state.driver?.complete(runID: runID), !report.intervalConclusive,
                      report.attempt.runID == runID, report.attempt == attempt else {
                    state.phase = .failed
                    return event(.failed, "unexpected_lock_evidence")
                }
                state.phase = .finished
                return event(.finished, "inconclusive_lock_state;" + Self.summary(report.attempt))
            } catch {
                state.phase = .failed
                return event(.failed, "attempt_failed_no_retry")
            }
        }
        observer(value)
    }

    private static func summary(_ attempt: DiagnosticAttempt) -> String {
        func label(_ outcome: DiagnosticOutcome?) -> String {
            switch outcome {
            case nil: return "not_attempted"
            case .succeeded: return "succeeded"
            case .denied: return "denied"
            case .missing: return "missing"
            case .ambiguous: return "ambiguous"
            case .pinMismatch: return "pin_mismatch"
            case .failed(let code): return "failed_\(code)"
            }
        }
        return "record=\(label(attempt.recordRead));lookup=\(label(attempt.keyLookup));sign=\(label(attempt.pinnedSign));timing=\(attempt.timing)"
    }
}
