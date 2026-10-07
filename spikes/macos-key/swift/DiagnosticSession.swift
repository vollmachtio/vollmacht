// Synchronous diagnostic ownership only. No scheduler, UI or native construction.
import Foundation

// Reserved model failures, distinct from a claim that access was denied. Actual
// RuntimeFailure.status values are preserved verbatim in DiagnosticOutcome.failed.
enum DiagnosticSessionCode: Int32 {
    case unexpected = -2147483648
    case pending = -2147483647
    case invalidRecord = -2147483646
    case invalidKey = -2147483645
    case existingKey = -2147483644
    case nativeFailure = -2147483643
    case bindingMismatch = -2147483642
}

private func diagnosticOutcome(_ operation: () throws -> Void) -> DiagnosticOutcome {
    do {
        try operation()
        return .succeeded
    } catch let error as RuntimeFailure {
        switch error {
        case .missing: return .missing
        case .ambiguous: return .ambiguous
        case .pinMismatch: return .pinMismatch
        case .status(let status): return .failed(status)
        case .pending: return .failed(DiagnosticSessionCode.pending.rawValue)
        case .invalidRecord: return .failed(DiagnosticSessionCode.invalidRecord.rawValue)
        case .invalidKey: return .failed(DiagnosticSessionCode.invalidKey.rawValue)
        case .existingKey: return .failed(DiagnosticSessionCode.existingKey.rawValue)
        case .nativeFailure: return .failed(DiagnosticSessionCode.nativeFailure.rawValue)
        }
    } catch {
        return .failed(DiagnosticSessionCode.unexpected.rawValue)
    }
}

private struct SessionDiagnosticBackend<B: RuntimeBackend>: DiagnosticBackend {
    // The pure plan never receives the real key handle. Only this private bridge
    // can use the prepared key, and fresh lookup cannot replace it.
    typealias Handle = Void
    private var backend: B
    private let prepared: PreparedPersistentKey<B.Handle>
    private let identity: DiagnosticIdentity

    init(backend: B, prepared: PreparedPersistentKey<B.Handle>, identity: DiagnosticIdentity) {
        self.backend = backend
        self.prepared = prepared
        self.identity = identity
    }

    mutating func readRecord(identity: DiagnosticIdentity) -> DiagnosticOutcome {
        guard identity == self.identity else { return .failed(DiagnosticSessionCode.bindingMismatch.rawValue) }
        return diagnosticOutcome { try diagnosePreparedRecord(prepared, using: &backend) }
    }

    mutating func lookupKey(identity: DiagnosticIdentity) -> DiagnosticOutcome {
        guard identity == self.identity else { return .failed(DiagnosticSessionCode.bindingMismatch.rawValue) }
        return diagnosticOutcome { try diagnosePreparedLookup(prepared, using: &backend) }
    }

    mutating func signPinned(handle: Void, identity: DiagnosticIdentity, message: Data) -> DiagnosticOutcome {
        guard identity == self.identity, message == RuntimeProfile.message else {
            return .failed(DiagnosticSessionCode.bindingMismatch.rawValue)
        }
        return diagnosticOutcome { _ = try diagnosePreparedSigning(prepared, using: &backend) }
    }
}

// Reference ownership prevents accidental value-copy replays of an armed plan.
// Callers must serialize access. Generic reference dependencies are not deep-copied
// or isolated from aliases that existed before initialization.
final class DiagnosticSession<B: RuntimeBackend, C: DiagnosticClock> {
    private var bridge: SessionDiagnosticBackend<B>
    private var clock: C
    private var plan: DiagnosticPlan<Void>

    var state: DiagnosticState { plan.state }

    init(request: KeyRequest, expectedPublic: Data, runID: UInt64, backend: B, clock: C) throws {
        var retainedBackend = backend
        let prepared = try preparePersistent(request, expectedPublic: expectedPublic, using: &retainedBackend)
        let identity = try DiagnosticIdentity(identifier: prepared.request.identifier,
                                              accessGroup: prepared.request.accessGroup,
                                              publicPin: prepared.publicPin)
        bridge = SessionDiagnosticBackend(backend: retainedBackend, prepared: prepared, identity: identity)
        self.clock = clock
        plan = DiagnosticPlan(identity: identity, runID: runID, pinnedHandle: ())
    }

    func arm(notBefore: UInt64, deadline: UInt64) throws {
        try plan.arm(notBefore: notBefore, deadline: deadline, clock: &clock)
    }

    func cancel() throws { try plan.cancel() }

    func attempt() throws -> DiagnosticAttempt {
        try plan.attempt(backend: &bridge, clock: &clock)
    }

    func complete(runID: UInt64) throws -> DiagnosticReport {
        // No caller API can supply or assert a machine-verified lock interval.
        try plan.complete(runID: runID, lockedInterval: nil)
    }
}
