import Combine

enum ProbeFailureDisplay {
    static func label(_ error: Error) -> String {
        guard let error = error as? RuntimeFailure else { return "unexpected_failure" }
        switch error {
        case .status(let status): return "os_status_\(status)"
        case .nativeFailure: return "native_failure"
        case .missing: return "missing"
        case .pending: return "pending"
        case .ambiguous: return "ambiguous"
        case .existingKey: return "existing_key"
        case .invalidKey: return "invalid_key"
        case .pinMismatch: return "pin_mismatch"
        case .invalidRecord: return "invalid_record"
        }
    }
}

@MainActor
protocol ProbeDiagnosticCommands: AnyObject {
    func prepare()
    func arm()
    func cancel()
}

extension DelayedDiagnosticController: ProbeDiagnosticCommands {}

// One shared production instance is configured by ProbeView. Injected instances
// are for fake tests. Never replace the production owner when a window closes.
@MainActor
final class ProbeModel: ObservableObject {
    typealias Observer = @Sendable (DelayedDiagnosticEvent) -> Void
    typealias Completion = @Sendable (String) -> Void
    typealias LegacyWork = (Bool, @escaping Completion) -> Void
    typealias Factory = (UInt64, @escaping Observer) -> any ProbeDiagnosticCommands

    private let state = ProbeOperationState()
    private let legacyWork: LegacyWork
    private let factory: Factory
    private var controller: (any ProbeDiagnosticCommands)?
    @Published private(set) var phase: ProbeOperationState.Phase = .idle
    @Published private(set) var message = "No Keychain operations have run in this app session."

    init(legacyWork: @escaping LegacyWork, factory: @escaping Factory) {
        self.legacyWork = legacyWork
        self.factory = factory
    }

    var canRunLegacy: Bool {
        switch phase { case .idle, .terminal: return true; default: return false }
    }
    var canPrepare: Bool { canRunLegacy && !state.diagnosticSpent }
    var canArm: Bool { if case .prepared = phase { return true }; return false }
    var canCancel: Bool { if case .armed = phase { return true }; return false }

    func perform(create: Bool) {
        guard let token = state.beginLegacy(create ? .create : .open) else { return }
        publish("Working. Do not repeat the operation.")
        legacyWork(create) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self, self.state.finishLegacy(token: token) else { return }
                self.publish(result)
            }
        }
    }

    func prepare() {
        guard let token = state.prepareDiagnostic() else { return }
        publish("Preparing the existing pinned key. No signature is requested yet.")
        let owned = factory(token) { [weak self] event in
            Task { @MainActor [weak self] in
                guard let self, ProbeEventAdapter.apply(event, to: self.state) else { return }
                self.publish(event.result)
            }
        }
        controller = owned // Retain before enqueueing preparation.
        owned.prepare()
    }

    func arm() {
        guard case .prepared(let token) = phase, state.arm(token: token) else { return }
        publish("Arming requested. Wait for one_attempt_scheduled, then lock the screen promptly.")
        controller?.arm()
    }

    func cancel() {
        guard case .armed(let token) = phase, state.cancel(token: token) else { return }
        publish("Cancellation requested, not yet confirmed. An entered operation cannot be interrupted.")
        controller?.cancel()
    }

    private func publish(_ text: String) {
        phase = state.phase
        message = text
    }
}
