import Foundation

@main
struct ProbeModelTests {
    enum Failure: Error { case assertion(Int), timedOut }
    static func check(_ value: Bool, line: Int = #line) throws {
        guard value else { throw Failure.assertion(line) }
    }
    @MainActor
    final class Commands: ProbeDiagnosticCommands {
        var calls: [String] = []
        func prepare() { calls.append("prepare") }
        func arm() { calls.append("arm") }
        func cancel() { calls.append("cancel") }
    }
    @MainActor
    final class Harness {
        let commands = Commands()
        var factories = 0
        var observer: ProbeModel.Observer?
        var token: UInt64 = 0
        var completions: [ProbeModel.Completion] = []
        var creates: [Bool] = []
        func model() -> ProbeModel {
            ProbeModel(legacyWork: { create, completion in
                self.creates.append(create); self.completions.append(completion)
            }, factory: { token, observer in
                self.factories += 1; self.token = token; self.observer = observer
                return self.commands
            })
        }
        func emit(_ phase: DelayedDiagnosticPhase, _ result: String, stale: Bool = false) {
            observer?(.init(runID: token + (stale ? 1 : 0), phase: phase, result: result))
        }
    }
    @MainActor
    static func eventually(_ predicate: @MainActor () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(5)
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failure.timedOut }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    @MainActor
    static func main() async throws {
        let fake = Harness()
        let model = fake.model(), otherView = model
        try check(fake.factories == 0 && fake.creates.isEmpty && fake.commands.calls.isEmpty)
        try check(model.canRunLegacy && model.canPrepare && !model.canArm && !model.canCancel)
        model.perform(create: true)
        otherView.perform(create: false); otherView.prepare(); otherView.arm(); otherView.cancel()
        try check(fake.creates == [true] && fake.factories == 0)
        fake.completions[0]("created")
        try await eventually { model.message == "created" }
        otherView.perform(create: false)
        fake.completions[0]("stale creation result")
        fake.completions[1]("opened")
        try await eventually { model.message == "opened" }
        try check(fake.creates == [true, false] && model.canPrepare)
        model.prepare(); otherView.prepare(); model.perform(create: false)
        try check(fake.factories == 1 && fake.commands.calls == ["prepare"] && fake.creates.count == 2)
        fake.emit(.prepared, "existing_key_prepared", stale: true)
        fake.emit(.prepared, "existing_key_prepared")
        try await eventually { model.canArm }
        try check(!model.canRunLegacy && !model.canPrepare && !model.canCancel)
        model.arm(); model.arm(); model.cancel()
        try check(fake.commands.calls == ["prepare", "arm"])
        fake.emit(.armed, "one_attempt_scheduled")
        try await eventually { model.canCancel }
        model.cancel(); model.cancel()
        try check(fake.commands.calls == ["prepare", "arm", "cancel"])
        try check(!model.canRunLegacy && !model.canCancel)
        fake.emit(.finished, "cancellation_not_applied")
        fake.emit(.finished, "inconclusive_callback_outside_window")
        try await eventually { model.canRunLegacy }
        try check(model.phase == .terminal(fake.token, .completedInconclusive))
        let result = model.message
        fake.emit(.armed, "one_attempt_scheduled")
        fake.emit(.cancelled, "cancelled_before_attempt")
        model.prepare(); model.arm(); model.cancel()
        try check(fake.factories == 1 && fake.commands.calls.count == 3 && !model.canPrepare)
        model.perform(create: false)
        fake.completions[2]("final open")
        try await eventually { model.message == "final open" }
        try check(result == "inconclusive_callback_outside_window" && !model.canPrepare)

        for (phase, label) in [(DelayedDiagnosticPhase.failed, "preparation_failed")] {
            let failure = Harness(), owner = failure.model()
            owner.prepare(); failure.emit(phase, label)
            try await eventually { owner.canRunLegacy }
            try check(!owner.canPrepare && failure.commands.calls == ["prepare"])
            owner.prepare(); try check(failure.factories == 1)
        }
        // A view reference disappears; the app owner still retains its controller.
        let cancelled = Harness(), owner = cancelled.model()
        var temporaryView: ProbeModel? = owner
        temporaryView?.prepare(); temporaryView = nil
        cancelled.emit(.prepared, "existing_key_prepared")
        try await eventually { owner.canArm }
        owner.arm(); cancelled.emit(.armed, "one_attempt_scheduled")
        try await eventually { owner.canCancel }
        owner.cancel(); cancelled.emit(.cancelled, "cancelled_before_attempt")
        try await eventually { owner.canRunLegacy }
        try check(owner.phase == .terminal(cancelled.token, .cancelled))
        try check(cancelled.commands.calls == ["prepare", "arm", "cancel"])

        let errors: [RuntimeFailure] = [.status(-25308), .nativeFailure, .missing, .pending, .ambiguous,
                                        .existingKey, .invalidKey, .pinMismatch, .invalidRecord]
        let labels = ["os_status_-25308", "native_failure", "missing", "pending", "ambiguous", "existing_key",
                      "invalid_key", "pin_mismatch", "invalid_record"]
        for (error, label) in zip(errors, labels) { try check(ProbeFailureDisplay.label(error) == label) }
        try check(ProbeFailureDisplay.label(Failure.timedOut) == "unexpected_failure")
        print("PASS: shared UI model fake orchestration; no native operations or app launch.")
    }
}
