// Fake-only tests: NativeKeyBackend is compiled but never instantiated or called.
import Foundation
import CryptoKit

enum RuntimeTestFailure: Error { case failed(String) }
func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw RuntimeTestFailure.failed(message) }
}
func rejects(_ expected: RuntimeFailure, _ operation: () throws -> Void) throws {
    do { try operation() }
    catch let actual as RuntimeFailure {
        try require(actual == expected, "unexpected failure")
        return
    }
    throw RuntimeTestFailure.failed("expected rejection")
}

struct FakeRuntime: RuntimeBackend {
    typealias Handle = Int
    let softwareKey: P256.Signing.PrivateKey
    var record: Data?
    var handles: [Int] = []
    var calls: [String] = []
    var failAt: String?
    var invalidPublic = false
    var badSignature = false
    var wrongMessage = false
    var publicHandles: [Int] = []
    var signedHandles: [Int] = []
    var publicOverride: Data?

    init() throws {
        var scalar = Data(repeating: 0, count: 32)
        scalar[31] = 1 // Publicly known test scalar, never a deployed credential.
        softwareKey = try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }
    mutating func step(_ name: String) throws {
        calls.append(name)
        if failAt == name { throw RuntimeFailure.status(-1) }
    }
    mutating func reserve(_ request: KeyRequest) throws {
        try step("reserve")
        guard record == nil else { throw RuntimeFailure.status(-25299) }
        record = RuntimeProfile.pending
    }
    mutating func readRecord(_ request: KeyRequest) throws -> Data {
        try step("read")
        guard let record else { throw RuntimeFailure.missing }
        return record
    }
    mutating func commit(_ request: KeyRequest, record: Data) throws {
        try step("commit")
        self.record = record
    }
    mutating func keys(_ request: KeyRequest) throws -> [Int] { try step("keys"); return handles }
    mutating func create(_ request: KeyRequest) throws -> Int { try step("create"); handles = [1]; return 1 }
    mutating func publicBytes(_ handle: Int) throws -> Data {
        try step("public")
        publicHandles.append(handle)
        if let publicOverride { return publicOverride }
        return invalidPublic ? Data(repeating: 0, count: 65) : softwareKey.publicKey.x963Representation
    }
    mutating func signFixed(_ handle: Int) throws -> Data {
        try step("sign")
        signedHandles.append(handle)
        return badSignature ? Data([0]) : try softwareKey.signature(for: wrongMessage ? Data("changed".utf8) : RuntimeProfile.message).derRepresentation
    }
}

@main
struct RuntimeTests {
    static func preparationTests(request: KeyRequest, publicPin: Data, otherPin: Data) throws {
        var ready = try FakeRuntime()
        ready.record = RuntimeProfile.readyPrefix + publicPin
        ready.handles = [73]
        let originalRecord = ready.record
        let prepared = try preparePersistent(request, expectedPublic: publicPin, using: &ready)
        try require(prepared.request.identifier == request.identifier
                    && prepared.request.accessGroup == request.accessGroup, "prepared identity preserved")
        try require(prepared.publicPin == publicPin && prepared.handle == 73, "exact pin and handle retained")
        try require(ready.publicHandles == [73] && ready.signedHandles.isEmpty, "prepare cannot sign")
        try require(ready.calls == ["read", "keys", "public"], "prepare is read-only")
        try require(ready.record == originalRecord && ready.handles == [73], "prepare cannot change storage")
        ready.handles = [99]
        ready.record = RuntimeProfile.pending
        try require(prepared.handle == 73 && prepared.publicPin == publicPin,
                    "prepared result must not follow later lookup state")

        let malformed: [(Data?, RuntimeFailure)] = [
            (nil, .missing), (RuntimeProfile.pending, .pending), (Data(), .invalidRecord),
            (RuntimeProfile.readyPrefix, .invalidRecord),
            (RuntimeProfile.readyPrefix + publicPin.dropLast(), .invalidRecord),
            (RuntimeProfile.readyPrefix + publicPin + Data([0]), .invalidRecord),
            (Data(repeating: 0, count: RuntimeProfile.readyPrefix.count + 65), .invalidRecord),
            (RuntimeProfile.readyPrefix + otherPin, .pinMismatch),
        ]
        for (record, expected) in malformed {
            var failing = try FakeRuntime()
            failing.record = record
            failing.handles = [73]
            try rejects(expected) { _ = try preparePersistent(request, expectedPublic: publicPin, using: &failing) }
            try require(failing.calls == ["read"] && failing.record == record && failing.handles == [73],
                        "bad record cannot proceed or mutate storage")
        }
        for handles in [[], [73], [73, 74], [73, 73], [73, 74, 75]] {
            var failing = try FakeRuntime()
            failing.record = originalRecord
            failing.handles = handles
            let prepare = {
                _ = try preparePersistent(request, expectedPublic: publicPin, using: &failing)
            }
            if handles.count == 1 {
                // Positive control for this exact lookup-cardinality matrix:
                // an implementation that rejects every lookup must fail here.
                try prepare()
            } else {
                try rejects(handles.isEmpty ? .missing : .ambiguous, prepare)
            }
            let expectedCalls = handles.count == 1 ? ["read", "keys", "public"] : ["read", "keys"]
            try require(failing.calls == expectedCalls && failing.handles == handles
                        && failing.record == originalRecord, "lookup cardinality control changed storage or calls")
        }
        let invalidPoints = [Data(), Data([4]), Data(repeating: 0, count: 65),
                             Data([4] + Array(repeating: 0, count: 64)), publicPin + Data([0])]
        for point in invalidPoints {
            var failing = try FakeRuntime()
            failing.record = RuntimeProfile.readyPrefix + point
            failing.publicOverride = point
            failing.handles = [73]
            try rejects(.invalidKey) { _ = try preparePersistent(request, expectedPublic: point, using: &failing) }
            try require(failing.calls.isEmpty, "invalid retained point must fail before backend access")
        }
        for actual in invalidPoints + [otherPin] {
            var failing = try FakeRuntime()
            failing.record = originalRecord
            failing.handles = [73]
            failing.publicOverride = actual
            try rejects(.pinMismatch) { _ = try preparePersistent(request, expectedPublic: publicPin, using: &failing) }
            try require(failing.calls == ["read", "keys", "public"], "substitution cannot sign or repair")
        }
        for (stage, expectedCalls) in [("read", ["read"]), ("keys", ["read", "keys"]),
                                       ("public", ["read", "keys", "public"])] {
            var failing = try FakeRuntime()
            failing.record = originalRecord
            failing.handles = [73]
            failing.failAt = stage
            try rejects(.status(-1)) { _ = try preparePersistent(request, expectedPublic: publicPin, using: &failing) }
            try require(failing.calls == expectedCalls && failing.record == originalRecord
                        && failing.handles == [73], "prepare denial cannot retry or mutate")
        }
        var reopened = try FakeRuntime()
        reopened.record = originalRecord
        reopened.handles = [73]
        let evidence = try openPersistent(request, expectedPublic: publicPin, using: &reopened)
        try require(evidence.publicKey == publicPin && reopened.publicHandles == [73]
                    && reopened.signedHandles == [73], "open signs exactly the prepared handle")
        try require(reopened.calls == ["read", "keys", "public", "sign"], "open still signs once")
        for wrongMessage in [false, true] {
            var failing = try FakeRuntime()
            failing.record = originalRecord
            failing.handles = [73]
            failing.badSignature = !wrongMessage
            failing.wrongMessage = wrongMessage
            try rejects(.invalidKey) { _ = try openPersistent(request, expectedPublic: publicPin, using: &failing) }
            try require(failing.calls == ["read", "keys", "public", "sign"], "open retains signature verification")
        }
    }

    static func main() throws {
        let request = try KeyRequest(suffix: "0123456789abcdef0123456789abcdef", accessGroup: "TESTTEAM.io.vollmacht.test")
        var backend = try FakeRuntime()
        let created = try createPersistent(request, using: &backend)
        try require(backend.calls == ["reserve", "keys", "create", "public", "sign", "commit"], "create order")
        try require(backend.record == RuntimeProfile.readyPrefix + created.publicKey, "pinned ready record")
        backend.calls = []
        let reopened = try openPersistent(request, expectedPublic: created.publicKey, using: &backend)
        try require(reopened.publicKey == created.publicKey, "same public pin")
        try require(backend.calls == ["read", "keys", "public", "sign"], "open cannot create")
        var restarted = try FakeRuntime()
        restarted.record = backend.record
        restarted.handles = backend.handles
        let afterRestart = try openPersistent(request, expectedPublic: created.publicKey, using: &restarted)
        try require(afterRestart.publicKey == created.publicKey, "restored fake storage preserves pin")
        try require(restarted.calls == ["read", "keys", "public", "sign"], "restart cannot recreate")
        backend.calls = []
        try rejects(.status(-25299)) { _ = try createPersistent(request, using: &backend) }
        try require(backend.calls == ["reserve"], "duplicate never generates")

        for stage in ["reserve", "keys", "create", "public", "sign", "commit"] {
            var failing = try FakeRuntime()
            failing.failAt = stage
            try rejects(.status(-1)) { _ = try createPersistent(request, using: &failing) }
            try require(failing.calls.last == stage, "no retry or fallback")
            if stage != "reserve" { try require(failing.record == RuntimeProfile.pending, "preserve partial reservation") }
        }
        for (record, expected) in [(nil, RuntimeFailure.missing), (RuntimeProfile.pending, .pending), (Data(), .invalidRecord)] as [(Data?, RuntimeFailure)] {
            var failing = try FakeRuntime()
            failing.record = record
            try rejects(expected) { _ = try openPersistent(request, expectedPublic: created.publicKey, using: &failing) }
            try require(failing.calls == ["read"], "bad record cannot access key")
        }
        for handles in [[], [1, 2]] {
            var failing = backend
            failing.calls = []
            failing.handles = handles
            try rejects(handles.isEmpty ? .missing : .ambiguous) { _ = try openPersistent(request, expectedPublic: created.publicKey, using: &failing) }
            try require(failing.calls == ["read", "keys"], "ambiguous or missing cannot sign")
        }
        var orphan = try FakeRuntime()
        orphan.handles = [1]
        try rejects(.existingKey) { _ = try createPersistent(request, using: &orphan) }
        try require(orphan.calls == ["reserve", "keys"], "orphan cannot be replaced")
        try require(orphan.record == RuntimeProfile.pending, "orphan blocks retry")

        var wrongScalar = Data(repeating: 0, count: 32)
        wrongScalar[31] = 2
        let wrongPublic = try P256.Signing.PrivateKey(rawRepresentation: wrongScalar).publicKey.x963Representation
        try preparationTests(request: request, publicPin: created.publicKey, otherPin: wrongPublic)
        backend.calls = []
        try rejects(.pinMismatch) { _ = try openPersistent(request, expectedPublic: wrongPublic, using: &backend) }
        try require(backend.calls == ["read"], "wrong retained pin cannot reach key")
        var substituted = backend
        substituted.calls = []
        substituted.record = RuntimeProfile.readyPrefix + wrongPublic
        try rejects(.pinMismatch) { _ = try openPersistent(request, expectedPublic: wrongPublic, using: &substituted) }
        try require(substituted.calls == ["read", "keys", "public"], "wrong actual key cannot sign")
        for (invalidPublic, badSignature, wrongMessage) in [(true, false, false), (false, true, false), (false, false, true)] {
            var failing = try FakeRuntime()
            failing.invalidPublic = invalidPublic
            failing.badSignature = badSignature
            failing.wrongMessage = wrongMessage
            try rejects(.invalidKey) { _ = try createPersistent(request, using: &failing) }
            try require(failing.record == RuntimeProfile.pending, "invalid key or signature cannot commit")
        }
        for stage in ["read", "keys", "public", "sign"] {
            var failing = backend
            failing.calls = []
            failing.failAt = stage
            try rejects(.status(-1)) { _ = try openPersistent(request, expectedPublic: created.publicKey, using: &failing) }
            try require(failing.calls.last == stage, "open denial cannot fall back")
        }
        print("PASS: durable runtime fake tests; no native Keychain operation executed.")
    }
}
