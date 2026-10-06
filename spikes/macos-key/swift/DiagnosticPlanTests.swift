// Fake-only sequencing tests. No Security, LocalAuthentication or real key APIs.
import Foundation

enum DiagnosticTestFailure: Error { case failed(String) }

private func check(_ value: @autoclosure () -> Bool, _ label: String) throws {
    guard value() else { throw DiagnosticTestFailure.failed(label) }
}

private func rejects(_ expected: DiagnosticError, _ operation: () throws -> Void) throws {
    do { try operation() }
    catch let actual as DiagnosticError {
        try check(actual == expected, "wrong error")
        return
    }
    throw DiagnosticTestFailure.failed("expected rejection")
}

private func instant(_ value: UInt64, _ continuity: UInt64 = 1) -> DiagnosticInstant {
    DiagnosticInstant(milliseconds: value, continuity: continuity)
}

private struct FakeClock: DiagnosticClock {
    var instants: [DiagnosticInstant]
    mutating func now() -> DiagnosticInstant {
        precondition(!instants.isEmpty, "unexpected clock read")
        return instants.removeFirst()
    }
}

private struct FakeBackend: DiagnosticBackend {
    typealias Handle = Int
    var outcomes: [DiagnosticOutcome] = [.succeeded, .succeeded, .succeeded]
    var calls: [String] = []
    var identities: [DiagnosticIdentity] = []
    var signedHandle: Int?
    var signedMessage: Data?
    mutating func readRecord(identity: DiagnosticIdentity) -> DiagnosticOutcome {
        calls.append("record")
        identities.append(identity)
        return outcomes[0]
    }
    mutating func lookupKey(identity: DiagnosticIdentity) -> DiagnosticOutcome {
        calls.append("lookup")
        identities.append(identity)
        return outcomes[1]
    }
    mutating func signPinned(handle: Int, identity: DiagnosticIdentity, message: Data) -> DiagnosticOutcome {
        calls.append("sign")
        identities.append(identity)
        signedHandle = handle
        signedMessage = message
        return outcomes[2]
    }
}

private func identity() throws -> DiagnosticIdentity {
    try DiagnosticIdentity(identifier: "fixed-test-identifier", accessGroup: "test.group",
                           publicPin: Data([4] + Array(repeating: 0, count: 64)))
}

private func plan() throws -> DiagnosticPlan<Int> {
    DiagnosticPlan(identity: try identity(), runID: 7, pinnedHandle: 42)
}

private func interval(_ start: UInt64 = 105, _ end: UInt64 = 120,
                      verified: Bool = true, continuity: UInt64 = 1) -> DiagnosticLockedInterval {
    DiagnosticLockedInterval(start: instant(start, continuity), end: instant(end, continuity), verified: verified)
}

@main
struct DiagnosticPlanTests {
    static func main() throws {
        // Each outcome combination remains independent, including sign after
        // denied record access and failed fresh lookup with a retained handle.
        let outcomes: [DiagnosticOutcome] = [.succeeded, .denied, .missing, .ambiguous, .pinMismatch, .failed(-1)]
        for first in outcomes {
            for second in outcomes {
                for third in outcomes {
                    var subject = try plan()
                    var clock = FakeClock(instants: [100, 110, 111, 112, 113].map { instant($0) })
                    var backend = FakeBackend(outcomes: [first, second, third])
                    try subject.arm(notBefore: 110, deadline: 120, clock: &clock)
                    let result = try subject.attempt(backend: &backend, clock: &clock)
                    try check(result.recordRead == first && result.keyLookup == second && result.pinnedSign == third,
                              "independent outcomes lost")
                    try check(backend.calls == ["record", "lookup", "sign"], "unexpected probe order")
                    try check(backend.identities == Array(repeating: subject.identity, count: 3), "identity changed")
                    try check(backend.signedHandle == 42, "lookup replaced pinned handle")
                    try check(backend.signedMessage == DiagnosticMessage.bytes, "message changed")
                    let report = try subject.complete(runID: 7, lockedInterval: interval())
                    try check(report.intervalConclusive && subject.state == .complete, "valid interval rejected")
                    try rejects(.invalidState) { _ = try subject.attempt(backend: &backend, clock: &clock) }
                    try rejects(.invalidState) { _ = try subject.complete(runID: 7, lockedInterval: interval()) }
                }
            }
        }

        var subject = try plan()
        var clock = FakeClock(instants: [instant(100), instant(109), instant(110), instant(111), instant(112), instant(113)])
        var backend = FakeBackend()
        try rejects(.invalidState) { _ = try subject.attempt(backend: &backend, clock: &clock) }
        try subject.arm(notBefore: 110, deadline: 120, clock: &clock)
        try rejects(.invalidState) { try subject.arm(notBefore: 110, deadline: 120, clock: &clock) }
        try rejects(.notDue) { _ = try subject.attempt(backend: &backend, clock: &clock) }
        try check(backend.calls.isEmpty && subject.state == .armed, "early attempt performed work")
        _ = try subject.attempt(backend: &backend, clock: &clock)
        try rejects(.staleCompletion) { _ = try subject.complete(runID: 6, lockedInterval: interval()) }
        try check(subject.state == .attempted, "stale completion consumed result")
        _ = try subject.complete(runID: 7, lockedInterval: nil)

        for next in [instant(105), instant(109, 2)] {
            var candidate = try plan()
            var timer = FakeClock(instants: [instant(100), instant(109), next])
            var fake = FakeBackend()
            try candidate.arm(notBefore: 110, deadline: 120, clock: &timer)
            try rejects(.notDue) { _ = try candidate.attempt(backend: &fake, clock: &timer) }
            let result = try candidate.attempt(backend: &fake, clock: &timer)
            try check(result.timing == .discontinuous && fake.calls.isEmpty,
                      "early poll lost rollback or continuity evidence")
            try check(result.recordRead == nil && result.keyLookup == nil && result.pinnedSign == nil,
                      "discontinuous early polling attempted work")
            try rejects(.invalidState) { _ = try candidate.attempt(backend: &fake, clock: &timer) }
            let report = try candidate.complete(runID: 7, lockedInterval: interval(0, 1000))
            try check(!report.intervalConclusive, "early poll discontinuity became conclusive")
        }
        var polled = try plan()
        var pollClock = FakeClock(instants: [100, 105, 109, 110, 111, 112, 120].map { instant($0) })
        var pollBackend = FakeBackend()
        try polled.arm(notBefore: 110, deadline: 120, clock: &pollClock)
        for _ in 0..<2 {
            try rejects(.notDue) { _ = try polled.attempt(backend: &pollBackend, clock: &pollClock) }
        }
        try check(pollBackend.calls.isEmpty, "valid early polls performed work")
        let boundary = try polled.attempt(backend: &pollBackend, clock: &pollClock)
        try check(boundary.start.milliseconds == 110 && boundary.end.milliseconds == 120
                  && boundary.timing == .withinWindow, "inclusive timing boundaries changed")
        let boundaryReport = try polled.complete(runID: 7, lockedInterval: interval(110, 120))
        try check(boundaryReport.intervalConclusive, "valid repeated polls failed")

        var cancelled = try plan()
        var cancelClock = FakeClock(instants: [instant(100)])
        try cancelled.arm(notBefore: 110, deadline: 120, clock: &cancelClock)
        try cancelled.cancel()
        try check(cancelled.state == .cancelled, "cancel lost")
        try rejects(.invalidState) { try cancelled.cancel() }
        try rejects(.invalidState) { try cancelled.arm(notBefore: 110, deadline: 120, clock: &cancelClock) }
        try rejects(.invalidState) { _ = try cancelled.attempt(backend: &backend, clock: &cancelClock) }
        try rejects(.invalidState) { _ = try cancelled.complete(runID: 7, lockedInterval: interval()) }

        let timingCases: [([DiagnosticInstant], DiagnosticTiming, [String])] = [
            ([instant(100), instant(121)], .late, []),
            ([instant(100), instant(99)], .discontinuous, []),
            ([instant(100), instant(110, 2)], .discontinuous, []),
            ([instant(100), instant(110), instant(121)], .late, ["record"]),
            ([instant(100), instant(110), instant(111), instant(112, 2)], .discontinuous, ["record", "lookup"]),
            ([instant(100), instant(110), instant(111), instant(112), instant(111)], .discontinuous, ["record", "lookup", "sign"]),
            ([instant(100), instant(110), instant(111), instant(112), instant(121)], .late, ["record", "lookup", "sign"]),
        ]
        for (ticks, expected, calls) in timingCases {
            var candidate = try plan()
            var timer = FakeClock(instants: ticks)
            var fake = FakeBackend()
            try candidate.arm(notBefore: 110, deadline: 120, clock: &timer)
            let result = try candidate.attempt(backend: &fake, clock: &timer)
            try check(result.timing == expected && fake.calls == calls, "bad timing classification")
            try check((result.recordRead != nil) == calls.contains("record"), "record skip hidden")
            try check((result.keyLookup != nil) == calls.contains("lookup"), "lookup skip hidden")
            try check((result.pinnedSign != nil) == calls.contains("sign"), "sign skip hidden")
            let report = try candidate.complete(runID: 7, lockedInterval: interval(0, 1000))
            try check(!report.intervalConclusive, "late or suspended run reported conclusive")
            try rejects(.invalidState) { _ = try candidate.attempt(backend: &fake, clock: &timer) }
        }

        let badIntervals: [DiagnosticLockedInterval?] = [nil, interval(verified: false), interval(111, 120),
                                                       interval(105, 112), interval(continuity: 2), interval(120, 105)]
        for evidence in badIntervals {
            var candidate = try plan()
            var timer = FakeClock(instants: [100, 110, 111, 112, 113].map { instant($0) })
            var fake = FakeBackend()
            try candidate.arm(notBefore: 110, deadline: 120, clock: &timer)
            _ = try candidate.attempt(backend: &fake, clock: &timer)
            let report = try candidate.complete(runID: 7, lockedInterval: evidence)
            try check(!report.intervalConclusive, "unverified lock interval accepted")
        }
        for (notBefore, deadline) in [(99, 120), (110, 110), (110, 109), (110, 120101)] as [(UInt64, UInt64)] {
            var candidate = try plan()
            var timer = FakeClock(instants: [instant(100)])
            try rejects(.invalidWindow) { try candidate.arm(notBefore: notBefore, deadline: deadline, clock: &timer) }
            try check(candidate.state == .idle, "invalid arm changed state")
        }
        try rejects(.invalidIdentity) {
            _ = try DiagnosticIdentity(identifier: "", accessGroup: "test", publicPin: Data(repeating: 4, count: 65))
        }
        try rejects(.invalidIdentity) {
            _ = try DiagnosticIdentity(identifier: "test", accessGroup: "test", publicPin: Data([4]))
        }
        print("Diagnostic plan fake tests passed: 216 outcome combinations plus lifecycle, timing and evidence negatives.")
    }
}
