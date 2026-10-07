// Pure diagnostic sequencing only. No native backend, timer, UI or key operations.
import Foundation

enum DiagnosticError: Error, Equatable {
    case invalidIdentity, invalidWindow, invalidState, notDue, staleCompletion
}

struct DiagnosticIdentity: Equatable {
    let identifier: String
    let accessGroup: String
    let publicPin: Data

    init(identifier: String, accessGroup: String, publicPin: Data) throws {
        guard [identifier, accessGroup].allSatisfy({
            !$0.isEmpty && $0.utf8.count <= 256 && !$0.utf8.contains(0)
        }), publicPin.count == 65, publicPin.first == 4 else {
            throw DiagnosticError.invalidIdentity
        }
        // Shape only: native wiring must obtain this pin from trusted enrollment
        // and validate the actual public key before arming.
        self.identifier = identifier
        self.accessGroup = accessGroup
        self.publicPin = publicPin
    }
}

enum DiagnosticMessage {
    static let bytes = Data("vollmacht:macos-durable-key-probe:v1\0fixed-test-message-not-a-mandate".utf8)
}

struct DiagnosticInstant: Equatable {
    let milliseconds: UInt64
    // A trusted future clock adapter must change this on observed suspension or
    // loss of timing continuity. It is evidence supplied by the adapter, not an
    // OS sleep detector implemented by this pure model.
    let continuity: UInt64
}

protocol DiagnosticClock {
    mutating func now() -> DiagnosticInstant
}

enum DiagnosticOutcome: Equatable {
    case succeeded, denied, missing, ambiguous, pinMismatch
    case failed(Int32)
}

protocol DiagnosticBackend {
    associatedtype Handle
    mutating func readRecord(identity: DiagnosticIdentity) -> DiagnosticOutcome
    mutating func lookupKey(identity: DiagnosticIdentity) -> DiagnosticOutcome
    mutating func signPinned(handle: Handle, identity: DiagnosticIdentity, message: Data) -> DiagnosticOutcome
}

struct DiagnosticLockedInterval {
    let start: DiagnosticInstant
    let end: DiagnosticInstant
    let verified: Bool
}

enum DiagnosticTiming: Equatable {
    case withinWindow, late, discontinuous
}

struct DiagnosticAttempt: Equatable {
    let runID: UInt64
    let start: DiagnosticInstant
    let end: DiagnosticInstant
    let timing: DiagnosticTiming
    // nil means the probe was not attempted, not that access was denied.
    let recordRead: DiagnosticOutcome?
    let keyLookup: DiagnosticOutcome?
    let pinnedSign: DiagnosticOutcome?
}

struct DiagnosticReport: Equatable {
    let attempt: DiagnosticAttempt
    // This only describes whether supplied screen-lock evidence brackets the
    // attempt. It never means the Keychain was locked or the key was protected.
    let intervalConclusive: Bool
}

enum DiagnosticState: Equatable {
    case idle, armed, attempting, attempted, cancelled, complete
}

struct DiagnosticPlan<Handle> {
    let identity: DiagnosticIdentity
    let runID: UInt64
    private let pinnedHandle: Handle
    private(set) var state: DiagnosticState = .idle
    private var armedAt: DiagnosticInstant?
    private var lastObserved: DiagnosticInstant?
    private var notBefore: UInt64 = 0
    private var deadline: UInt64 = 0
    private var pending: DiagnosticAttempt?

    init(identity: DiagnosticIdentity, runID: UInt64, pinnedHandle: Handle) {
        self.identity = identity
        self.runID = runID
        self.pinnedHandle = pinnedHandle
    }

    mutating func arm<C: DiagnosticClock>(notBefore: UInt64, deadline: UInt64, clock: inout C) throws {
        guard state == .idle else { throw DiagnosticError.invalidState }
        let now = clock.now()
        guard notBefore >= now.milliseconds, deadline > notBefore,
              deadline - now.milliseconds <= 120_000 else { throw DiagnosticError.invalidWindow }
        self.notBefore = notBefore
        self.deadline = deadline
        armedAt = now
        lastObserved = now
        state = .armed
    }

    mutating func cancel() throws {
        guard state == .armed else { throw DiagnosticError.invalidState }
        state = .cancelled
    }

    private func timing(_ instant: DiagnosticInstant, previous: DiagnosticInstant) -> DiagnosticTiming {
        guard instant.continuity == armedAt?.continuity,
              instant.milliseconds >= previous.milliseconds else { return .discontinuous }
        return instant.milliseconds <= deadline ? .withinWindow : .late
    }

    mutating func attempt<B: DiagnosticBackend, C: DiagnosticClock>(
        backend: inout B, clock: inout C
    ) throws -> DiagnosticAttempt where B.Handle == Handle {
        guard state == .armed, let previous = lastObserved else { throw DiagnosticError.invalidState }
        let start = clock.now()
        var status = timing(start, previous: previous)
        // Early polls also establish observed time. Losing that observation
        // would permit a later clock rollback to appear monotonic from arm time.
        lastObserved = start
        if status == .withinWindow && start.milliseconds < notBefore { throw DiagnosticError.notDue }
        state = .attempting // Consumed before any backend call; never retry failures.
        var end = start
        var record: DiagnosticOutcome?
        var lookup: DiagnosticOutcome?
        var sign: DiagnosticOutcome?
        if status == .withinWindow {
            record = backend.readRecord(identity: identity)
            end = clock.now()
            status = timing(end, previous: start)
        }
        if status == .withinWindow {
            lookup = backend.lookupKey(identity: identity)
            let previous = end
            end = clock.now()
            status = timing(end, previous: previous)
        }
        if status == .withinWindow {
            // Uses the handle pinned before arming, never the lookup's result.
            sign = backend.signPinned(handle: pinnedHandle, identity: identity, message: DiagnosticMessage.bytes)
            let previous = end
            end = clock.now()
            status = timing(end, previous: previous)
        }
        let result = DiagnosticAttempt(runID: runID, start: start, end: end, timing: status,
                                       recordRead: record, keyLookup: lookup, pinnedSign: sign)
        pending = result
        state = .attempted
        return result
    }

    mutating func complete(runID: UInt64, lockedInterval: DiagnosticLockedInterval?) throws -> DiagnosticReport {
        guard runID == self.runID else { throw DiagnosticError.staleCompletion }
        guard state == .attempted, let result = pending else { throw DiagnosticError.invalidState }
        let conclusive: Bool
        if let interval = lockedInterval {
            conclusive = interval.verified && result.timing == .withinWindow
                && interval.start.continuity == result.start.continuity
                && interval.end.continuity == result.end.continuity
                && interval.start.milliseconds <= result.start.milliseconds
                && interval.end.milliseconds >= result.end.milliseconds
        } else { conclusive = false }
        state = .complete
        pending = nil
        return DiagnosticReport(attempt: result, intervalConclusive: conclusive)
    }
}
