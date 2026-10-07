// Software/fake-only integration. NativeKeyBackend is never instantiated.
import Foundation
import CryptoKit

private enum TestFailure: Error { case assertion(String), unexpected }
private func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw TestFailure.assertion(message) }
}
private func rejects<E: Error & Equatable>(_ expected: E, _ operation: () throws -> Void) throws {
    do { try operation() }
    catch let error as E { try check(error == expected, "unexpected error"); return }
    throw TestFailure.assertion("expected failure")
}

private final class TestHandle {}
private final class TestContext {}
private final class Store {
    let key: P256.Signing.PrivateKey
    let original = TestHandle()
    let context = TestContext()
    var record: Data?
    var handles: [TestHandle] = []
    var publicOverride: Data?
    var badSignature = false
    var failures: [String: Error] = [:]
    var calls: [String] = []
    var contexts: [ObjectIdentifier] = []
    var signed: [TestHandle] = []
    var requests: [KeyRequest] = []
    init() throws {
        var scalar = Data(repeating: 0, count: 32)
        scalar[31] = 1
        key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        record = RuntimeProfile.readyPrefix + key.publicKey.x963Representation
        handles = [original]
    }
    func resetLog() { calls = []; contexts = []; signed = []; requests = [] }
}

private struct Backend: RuntimeBackend {
    let store: Store
    let context: TestContext
    init(_ store: Store) { self.store = store; context = store.context }
    func step(_ name: String) throws {
        store.calls.append(name)
        store.contexts.append(ObjectIdentifier(context))
        if let error = store.failures[name] { throw error }
    }
    mutating func reserve(_ request: KeyRequest) throws { try step("forbidden-reserve") }
    mutating func commit(_ request: KeyRequest, record: Data) throws { try step("forbidden-commit") }
    mutating func create(_ request: KeyRequest) throws -> TestHandle { try step("forbidden-create"); return TestHandle() }
    mutating func readRecord(_ request: KeyRequest) throws -> Data {
        try step("read")
        store.requests.append(request)
        guard let record = store.record else { throw RuntimeFailure.missing }
        return record
    }
    mutating func keys(_ request: KeyRequest) throws -> [TestHandle] {
        try step("keys")
        store.requests.append(request)
        return store.handles
    }
    mutating func publicBytes(_ handle: TestHandle) throws -> Data {
        try step("public")
        return store.publicOverride ?? store.key.publicKey.x963Representation
    }
    mutating func signFixed(_ handle: TestHandle) throws -> Data {
        try step("sign")
        store.signed.append(handle)
        return store.badSignature ? Data([0]) : try store.key.signature(for: RuntimeProfile.message).derRepresentation
    }
}

private struct Clock: DiagnosticClock {
    var ticks: [DiagnosticInstant]
    mutating func now() -> DiagnosticInstant {
        precondition(!ticks.isEmpty, "unexpected clock read")
        return ticks.removeFirst()
    }
}
private func tick(_ value: UInt64, _ continuity: UInt64 = 1) -> DiagnosticInstant {
    DiagnosticInstant(milliseconds: value, continuity: continuity)
}

@main
struct DiagnosticSessionTests {
    private static func request() throws -> KeyRequest {
        try KeyRequest(suffix: "0123456789abcdef0123456789abcdef", accessGroup: "TESTTEAM.io.vollmacht.test")
    }
    private static func session(_ store: Store, ticks: [DiagnosticInstant] = [100, 110, 111, 112, 113].map { tick($0) }) throws -> DiagnosticSession<Backend, Clock> {
        try DiagnosticSession(request: request(), expectedPublic: store.key.publicKey.x963Representation,
                              runID: 7, backend: Backend(store), clock: Clock(ticks: ticks))
    }
    static func main() throws {
        let store = try Store()
        let subject = try session(store)
        try check(store.calls == ["read", "keys", "public"], "construction only prepares")
        try check(store.contexts.allSatisfy { $0 == ObjectIdentifier(store.context) }, "preparation context changed")
        store.resetLog()
        store.handles = [TestHandle()] // Fresh lookup sees another handle for the same public key.
        try subject.arm(notBefore: 110, deadline: 120)
        try rejects(DiagnosticError.invalidState) { try subject.arm(notBefore: 110, deadline: 120) }
        let result = try subject.attempt()
        try check(result.recordRead == .succeeded && result.keyLookup == .succeeded && result.pinnedSign == .succeeded,
                  "successful probes")
        try check(store.calls == ["read", "keys", "public", "sign"], "probe ordering or writes")
        try check(store.signed.count == 1 && store.signed[0] === store.original, "original handle replaced")
        try check(store.contexts.allSatisfy { $0 == ObjectIdentifier(store.context) }, "retained context changed")
        let expectedRequest = try request()
        try check(store.requests.allSatisfy { $0.identifier == expectedRequest.identifier && $0.accessGroup == expectedRequest.accessGroup },
                  "caller identity substituted")
        let alias = subject
        try rejects(DiagnosticError.invalidState) { _ = try alias.attempt() }
        try rejects(DiagnosticError.staleCompletion) { _ = try subject.complete(runID: 8) }
        let report = try subject.complete(runID: 7)
        try check(!report.intervalConclusive && subject.state == .complete, "session must not certify screen lock")
        try rejects(DiagnosticError.invalidState) { _ = try subject.complete(runID: 7) }

        let cases: [(RuntimeFailure, DiagnosticOutcome)] = [
            (.missing, .missing), (.ambiguous, .ambiguous), (.pinMismatch, .pinMismatch),
            (.status(-25293), .failed(-25293)), (.status(-25308), .failed(-25308)),
            (.pending, .failed(DiagnosticSessionCode.pending.rawValue)),
            (.invalidRecord, .failed(DiagnosticSessionCode.invalidRecord.rawValue)),
            (.invalidKey, .failed(DiagnosticSessionCode.invalidKey.rawValue)),
            (.existingKey, .failed(DiagnosticSessionCode.existingKey.rawValue)),
            (.nativeFailure, .failed(DiagnosticSessionCode.nativeFailure.rawValue)),
        ]
        for (failure, expected) in cases {
            let data = try Store()
            let candidate = try session(data)
            data.resetLog()
            data.failures["read"] = failure
            try candidate.arm(notBefore: 110, deadline: 120)
            let observed = try candidate.attempt()
            try check(observed.recordRead == expected && observed.keyLookup == .succeeded && observed.pinnedSign == .succeeded,
                      "record failure must not gate other probes or change error")
            try check(data.calls == ["read", "keys", "public", "sign"], "failure retry or skipped independent probe")
        }
        for mode in ["missing", "ambiguous", "mismatch", "denied", "unexpected", "bad-signature", "sign-denied"] {
            let data = try Store()
            let candidate = try session(data)
            data.resetLog()
            var expectedLookup: DiagnosticOutcome = .succeeded
            var expectedSign: DiagnosticOutcome = .succeeded
            var expectedCalls = ["read", "keys", "public", "sign"]
            switch mode {
            case "missing": data.handles = []; expectedLookup = .missing; expectedCalls = ["read", "keys", "sign"]
            case "ambiguous": data.handles = [TestHandle(), TestHandle()]; expectedLookup = .ambiguous; expectedCalls = ["read", "keys", "sign"]
            case "mismatch": data.publicOverride = Data([0]); expectedLookup = .pinMismatch
            case "denied": data.failures["public"] = RuntimeFailure.status(-25308); expectedLookup = .failed(-25308)
            case "unexpected": data.failures["keys"] = TestFailure.unexpected; expectedLookup = .failed(DiagnosticSessionCode.unexpected.rawValue); expectedCalls = ["read", "keys", "sign"]
            case "bad-signature": data.badSignature = true; expectedSign = .failed(DiagnosticSessionCode.invalidKey.rawValue)
            default: data.failures["sign"] = RuntimeFailure.status(-25293); expectedSign = .failed(-25293)
            }
            try candidate.arm(notBefore: 110, deadline: 120)
            let observed = try candidate.attempt()
            try check(observed.recordRead == .succeeded && observed.keyLookup == expectedLookup && observed.pinnedSign == expectedSign,
                      "independent lookup/sign failure mapping")
            try check(data.calls == expectedCalls, "unexpected calls after failure")
        }
        for failure in [RuntimeFailure.missing, .pending, .invalidRecord, .pinMismatch, .status(-25308)] {
            let data = try Store()
            data.failures["read"] = failure
            try rejects(failure) { _ = try session(data) }
            try check(data.calls == ["read"], "failed preparation cannot sign or create")
        }
        let cancelledStore = try Store()
        let cancelled = try session(cancelledStore, ticks: [tick(100)])
        cancelledStore.resetLog()
        try cancelled.arm(notBefore: 110, deadline: 120)
        try cancelled.cancel()
        try rejects(DiagnosticError.invalidState) { _ = try cancelled.attempt() }
        try rejects(DiagnosticError.invalidState) { try cancelled.arm(notBefore: 110, deadline: 120) }
        try check(cancelledStore.calls.isEmpty && cancelled.state == .cancelled, "cancel must prevent probes")
        for last in [tick(105), tick(110, 2), tick(121)] {
            let data = try Store()
            let candidate = try session(data, ticks: [tick(100), tick(109), last])
            data.resetLog()
            try candidate.arm(notBefore: 110, deadline: 120)
            try rejects(DiagnosticError.notDue) { _ = try candidate.attempt() }
            let observed = try candidate.attempt()
            try check(observed.timing == (last.milliseconds == 121 ? .late : .discontinuous), "clock observation lost")
            try check(data.calls.isEmpty && observed.recordRead == nil && observed.keyLookup == nil && observed.pinnedSign == nil,
                      "late/discontinuous attempt must not touch backend")
            try rejects(DiagnosticError.invalidState) { _ = try candidate.attempt() }
            let completed = try candidate.complete(runID: 7)
            try check(!completed.intervalConclusive, "invalid timing became verified")
        }
        try check(DiagnosticMessage.bytes == RuntimeProfile.message, "fixed diagnostic messages diverged")
        print("PASS: owned diagnostic session fake tests; no native backend or lock verification.")
    }
}
