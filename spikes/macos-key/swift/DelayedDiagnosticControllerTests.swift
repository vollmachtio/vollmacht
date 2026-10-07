// Deterministic scheduling tests; no waits, native construction or Keychain APIs.
import Foundation
import Synchronization
import CryptoKit
import Dispatch

private enum Failure: Error { case test }
private func check(_ value: @autoclosure () -> Bool) throws { if !value() { throw Failure.test } }
private typealias Work = @Sendable () -> Void

private final class Scheduler: DelayedDiagnosticScheduling {
    private let ready = Mutex<[Work]>([])
    private let timers = Mutex<[Work]>([])
    let delays = Mutex<[UInt64]>([])
    func enqueue(_ operation: @escaping Work) { ready.withLock { $0.append(operation) } }
    func after(milliseconds: UInt64, _ operation: @escaping Work) {
        delays.withLock { $0.append(milliseconds) }
        timers.withLock { $0.append(operation) }
    }
    func drain() {
        while let next = ready.withLock({ $0.isEmpty ? nil : $0.removeFirst() }) { next() }
    }
    func fire() { let callback = timers.withLock { $0[0] }; callback() }
}

private final class Time: Sendable {
    let value = Mutex<DiagnosticInstant?>(DiagnosticInstant(milliseconds: 100, continuity: 1))
    func set(_ milliseconds: UInt64, continuity: UInt64 = 1) {
        value.withLock { $0 = DiagnosticInstant(milliseconds: milliseconds, continuity: continuity) }
    }
}
private struct Clock: DelayedDiagnosticClock {
    let time: Time
    func checkedNow() -> DiagnosticInstant? {
        time.value.withLock { value in
            guard let value else { return nil }
            return DiagnosticInstant(milliseconds: value.milliseconds, continuity: value.continuity)
        }
    }
    mutating func now() -> DiagnosticInstant {
        checkedNow() ?? DiagnosticInstant(milliseconds: UInt64.max, continuity: UInt64.max)
    }
}
private final class Log: Sendable {
    let calls = Mutex<[String]>([])
    let events = Mutex<[DelayedDiagnosticEvent]>([])
    let hook = Mutex<Work?>(nil)
    func call(_ value: String) { calls.withLock { $0.append(value) } }
    func last() -> String { events.withLock { $0.last!.result } }
}
private struct Driver: DelayedDiagnosticDriving {
    let log: Log
    let fail: String
    mutating func arm(notBefore: UInt64, deadline: UInt64) throws {
        log.call("arm")
        try check(notBefore == 15100 && deadline == 20100)
        if fail == "arm" { throw Failure.test }
    }
    mutating func cancel() throws { log.call("cancel"); if fail == "cancel" { throw Failure.test } }
    mutating func attempt() throws -> DiagnosticAttempt {
        log.call("attempt")
        let hook = log.hook.withLock { $0 }
        hook?()
        if fail == "attempt" { throw Failure.test }
        return result(runID: fail == "wrong-attempt-id" ? 9 : 7)
    }
    mutating func complete(runID: UInt64) throws -> DiagnosticReport {
        log.call("complete")
        if fail == "complete" { throw Failure.test }
        return DiagnosticReport(attempt: result(runID: fail == "wrong-report-id" ? 9 : 7,
                                                changed: fail == "changed-report"), intervalConclusive: fail == "lock")
    }
    func result(runID: UInt64 = 7, changed: Bool = false) -> DiagnosticAttempt {
        let now = DiagnosticInstant(milliseconds: 15100, continuity: 1)
        return DiagnosticAttempt(runID: runID, start: now, end: now, timing: .withinWindow,
                                 recordRead: .failed(-25308), keyLookup: .missing, pinnedSign: changed ? .denied : .succeeded)
    }
}

private struct SoftwareBackend: RuntimeBackend {
    let key: P256.Signing.PrivateKey
    let log: Log
    mutating func reserve(_ request: KeyRequest) throws { throw Failure.test }
    mutating func create(_ request: KeyRequest) throws -> Int { throw Failure.test }
    mutating func commit(_ request: KeyRequest, record: Data) throws { throw Failure.test }
    mutating func readRecord(_ request: KeyRequest) throws -> Data { log.call("read"); return RuntimeProfile.readyPrefix + key.publicKey.x963Representation }
    mutating func keys(_ request: KeyRequest) throws -> [Int] { log.call("keys"); return [73] }
    mutating func publicBytes(_ handle: Int) throws -> Data { try check(handle == 73); log.call("public"); return key.publicKey.x963Representation }
    mutating func signFixed(_ handle: Int) throws -> Data {
        try check(handle == 73)
        log.call("sign")
        return try key.signature(for: RuntimeProfile.message).derRepresentation
    }
}

@main
struct DelayedDiagnosticControllerTests {
    static func main() throws {
        for mode in ["success", "prepare", "arm", "cancel", "attempt", "complete", "lock", "early", "late", "continuity", "clock", "overflow", "cancel-first", "in-flight", "wrong-attempt-id", "wrong-report-id", "changed-report"] {
            let scheduler = Scheduler(), time = Time(), log = Log()
            let controller = DelayedDiagnosticController(runID: 7, clock: Clock(time: time), scheduler: scheduler, factory: { _, _ in
                log.call("prepare")
                if mode == "prepare" { throw Failure.test }
                return Driver(log: log, fail: mode)
            }, observer: { event in log.events.withLock { $0.append(event) } })
            controller.prepare()
            try check(log.calls.withLock { $0.isEmpty }) // Preparation is queued, never inline.
            scheduler.drain()
            controller.prepare()
            scheduler.drain()
            try check(log.calls.withLock { $0.filter { $0 == "prepare" }.count == 1 })
            if mode == "clock" { time.value.withLock { $0 = nil } }
            if mode == "overflow" { time.set(UInt64.max - 100) }
            controller.arm()
            scheduler.drain()
            if ["prepare", "arm", "clock", "overflow"].contains(mode) {
                try check(scheduler.delays.withLock { $0.isEmpty })
                continue
            }
            controller.arm()
            scheduler.drain()
            try check(scheduler.delays.withLock { $0 == [15000] })
            if mode == "cancel" || mode == "cancel-first" { controller.cancel(); scheduler.drain() }
            time.set(mode == "early" ? 15099 : mode == "late" ? 20101 : 15100,
                     continuity: mode == "continuity" ? 2 : 1)
            if mode == "in-flight" { log.hook.withLock { $0 = { controller.cancel() } } }
            scheduler.fire()
            let first = log.last()
            scheduler.drain()
            if mode == "in-flight" { try check(log.last() == "cancellation_not_applied") }
            scheduler.fire() // Duplicate callbacks cannot attempt or prepare again.
            scheduler.drain()
            let count = log.calls.withLock { $0.filter { $0 == "attempt" }.count }
            if ["early", "late", "continuity", "cancel", "cancel-first"].contains(mode) {
                try check(count == 0)
            } else {
                try check(count == 1)
            }
            if mode == "success" { try check(first.contains("record=failed_-25308;lookup=missing;sign=succeeded")) }
            if mode == "lock" { try check(first == "unexpected_lock_evidence") }
            if mode == "wrong-attempt-id" {
                try check(first == "attempt_binding_mismatch")
                try check(log.calls.withLock { !$0.contains("complete") })
            }
            if mode == "wrong-report-id" || mode == "changed-report" { try check(first == "unexpected_lock_evidence") }
            controller.arm(); controller.prepare(); scheduler.drain()
            try check(log.calls.withLock { $0.filter { $0 == "prepare" }.count == 1 })
            log.hook.withLock { $0 = nil }
        }
        // Real owned-session bridge, with a software-only backend created inside
        // the queued factory. All preparation and signature calls stay deferred.
        let scheduler = Scheduler(), time = Time(), log = Log()
        let owned = DelayedDiagnosticController(runID: 8, clock: Clock(time: time), scheduler: scheduler, factory: { id, clock in
            var scalar = Data(repeating: 0, count: 32); scalar[31] = 1
            let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
            let request = try KeyRequest(suffix: "0123456789abcdef0123456789abcdef", accessGroup: "TEST.io.vollmacht.test")
            return try OwnedSessionDriver(request: request, expectedPublic: key.publicKey.x963Representation,
                                          runID: id, backend: SoftwareBackend(key: key, log: log), clock: clock)
        }, observer: { event in log.events.withLock { $0.append(event) } })
        owned.prepare(); try check(log.calls.withLock { $0.isEmpty }); scheduler.drain()
        try check(log.calls.withLock { $0 == ["read", "keys", "public"] })
        owned.arm(); scheduler.drain(); time.set(15100); scheduler.fire()
        try check(log.calls.withLock { $0 == ["read", "keys", "public", "read", "keys", "public", "sign"] })
        try check(log.last().hasPrefix("inconclusive_lock_state;"))
        try check(ContinuousDiagnosticClock.milliseconds(seconds: 1, attoseconds: 999_000_000_000_000_000) == 1999)
        try check(ContinuousDiagnosticClock.milliseconds(seconds: -1, attoseconds: 0) == nil)
        try check(ContinuousDiagnosticClock.milliseconds(seconds: 1, attoseconds: -1) == nil)
        try check(ContinuousDiagnosticClock.milliseconds(seconds: Int64.max, attoseconds: 0) == nil)
        try check(ContinuousDiagnosticClock.milliseconds(seconds: 0, attoseconds: 1_000_000_000_000_000_000) == nil)
        // Actual worker check uses only immediate queue commands, never a timed
        // native attempt. A bounded drain proves non-UI factory execution and
        // observer reentry without holding the controller mutex.
        let done = DispatchSemaphore(value: 0)
        let reference = Mutex<DelayedDiagnosticController?>(nil)
        let workerChecks = Mutex<[Bool]>([])
        let real = DelayedDiagnosticController(runID: 7, clock: Clock(time: Time()), factory: { _, _ in
            workerChecks.withLock { $0.append(!Thread.isMainThread) }
            return Driver(log: Log(), fail: "")
        }, observer: { event in
            workerChecks.withLock { $0.append(!Thread.isMainThread) }
            if event.result == "existing_key_prepared" {
                let controller = reference.withLock { $0 }
                controller?.cancel()
            } else if event.result == "cancellation_not_applied" { done.signal() }
        })
        reference.withLock { $0 = real }
        real.prepare()
        try check(done.wait(timeout: .now() + 5) == .success)
        try check(workerChecks.withLock { $0.count == 3 && $0.allSatisfy { $0 } })
        reference.withLock { $0 = nil }
        print("PASS: delayed diagnostic controller and owned-session software tests; no native operations.")
    }
}
