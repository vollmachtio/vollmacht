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
        return invalidPublic ? Data(repeating: 0, count: 65) : softwareKey.publicKey.x963Representation
    }
    mutating func signFixed(_ handle: Int) throws -> Data {
        try step("sign")
        return badSignature ? Data([0]) : try softwareKey.signature(for: wrongMessage ? Data("changed".utf8) : RuntimeProfile.message).derRepresentation
    }
}

@main
struct RuntimeTests {
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
