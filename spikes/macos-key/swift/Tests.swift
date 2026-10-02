import Foundation
import Security

// No native backend, lookup, key generation or signing in these tests.
enum TestFailure: Error { case failed(String) }

func check(_ condition: @autoclosure () -> Bool, _ label: String) throws {
    if !condition() { throw TestFailure.failed(label) }
}

func fails<E: Error & Equatable>(_ expected: E, _ operation: () throws -> Void) throws {
    do {
        try operation()
    } catch let actual as E {
        try check(actual == expected, "unexpected typed error")
        return
    }
    throw TestFailure.failed("expected failure")
}

func request() throws -> KeyRequest {
    try KeyRequest(suffix: "0123456789abcdef0123456789abcdef", accessGroup: "TESTTEAM.io.vollmacht.test")
}

struct FakeBackend: CreationBackend {
    var calls: [String] = []
    var pending = false
    var reservationError: BackendFailure?
    var creationError: BackendFailure?

    mutating func reserve(_ request: KeyRequest) throws {
        calls.append("reserve:" + request.identifier)
        if let error = reservationError { throw error }
        if pending { throw BackendFailure.duplicate }
        pending = true
    }

    mutating func create(_ request: KeyRequest) throws -> Int {
        calls.append("create:" + request.identifier)
        if let error = creationError { throw error }
        return 1
    }
}

@main
struct Tests {
    static func main() throws {
        try identifierTests()
        try profileTests()
        try lifecycleTests()
        print("PASS: Swift profile and fake lifecycle checks; no native persistence exercised.")
    }

    static func identifierTests() throws {
        let valid = try request()
        try check(valid.identifier == "io.vollmacht.experimental.issuer.v1.0123456789abcdef0123456789abcdef", "namespaced ID")
        for suffix in ["", "*", String(repeating: "a", count: 31), String(repeating: "a", count: 33),
                       String(repeating: "A", count: 32), String(repeating: "é", count: 32),
                       String(repeating: "a", count: 31) + "\0"] {
            try fails(ProfileError.invalidIdentifier) {
                _ = try KeyRequest(suffix: suffix, accessGroup: valid.accessGroup)
            }
        }
        for group in ["", "*", "TEST.*", ".test", "test.", "test..group", "test/group", "test\0group", "é", String(repeating: "a", count: 256)] {
            try fails(ProfileError.invalidAccessGroup) {
                _ = try KeyRequest(suffix: "0123456789abcdef0123456789abcdef", accessGroup: group)
            }
        }
    }

    static func profileTests() throws {
        let input = try request()
        let create = try NativeProfile.creation(input)
        try check(create.count == 7, "exact creation field count")
        try check(create[kSecUseDataProtectionKeychain as String] as? Bool == true, "creation DP")
        try check(create[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String, "EC type")
        try check(create[kSecAttrKeySizeInBits as String] as? Int == 256, "P256 size")
        try check(create[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String, "hardware token")
        try check(create[kSecAttrAccessGroup as String] as? String == input.accessGroup, "creation group")
        try check(create[kSecAttrSynchronizable as String] as? Bool == false, "creation sync disabled")
        guard let attrs = create[kSecPrivateKeyAttrs as String] as? [String: Any] else {
            throw TestFailure.failed("private attributes missing")
        }
        try check(attrs.count == 3, "exact private field count")
        try check(attrs[kSecAttrIsPermanent as String] as? Bool == true, "permanent private key")
        try check(attrs[kSecAttrApplicationTag as String] as? Data == Data(input.identifier.utf8), "exact private tag")
        guard let control = attrs[kSecAttrAccessControl as String] else {
            throw TestFailure.failed("access control missing")
        }
        try check(CFGetTypeID(control as CFTypeRef) == SecAccessControlGetTypeID(), "access-control object type")

        let lookup = NativeProfile.lookup(input)
        try check(lookup.count == 9, "exact lookup field count")
        try check(lookup[kSecUseDataProtectionKeychain as String] as? Bool == true, "lookup DP")
        try check(lookup[kSecClass as String] as? String == kSecClassKey as String, "key class")
        try check(lookup[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String, "private only")
        try check(lookup[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String, "lookup EC")
        try check(lookup[kSecAttrApplicationTag as String] as? Data == Data(input.identifier.utf8), "lookup exact tag")
        try check(lookup[kSecAttrAccessGroup as String] as? String == input.accessGroup, "lookup group")
        try check(lookup[kSecAttrSynchronizable as String] as? Bool == false, "lookup nonsynchronized")
        try check(lookup[kSecReturnRef as String] as? Bool == true, "return reference")
        try check(lookup[kSecMatchLimit as String] as? Int == 2, "bounded ambiguity detection")

        let reservation = NativeProfile.reservation(input)
        try check(reservation.count == 8, "exact reservation field count")
        try check(reservation[kSecUseDataProtectionKeychain as String] as? Bool == true, "reservation DP")
        try check(reservation[kSecClass as String] as? String == kSecClassGenericPassword as String, "reservation class")
        try check(reservation[kSecAttrService as String] as? String == NativeProfile.reservationService, "reservation service")
        try check(reservation[kSecAttrAccount as String] as? String == input.identifier, "reservation ID")
        try check(reservation[kSecAttrAccessGroup as String] as? String == input.accessGroup, "reservation group")
        try check(reservation[kSecAttrSynchronizable as String] as? Bool == false, "reservation nonsynchronized")
        try check(reservation[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String, "reservation protection")
        try check(reservation[kSecValueData as String] as? Data == Data("pending:v1".utf8), "bounded pending marker")
    }

    static func lifecycleTests() throws {
        let input = try request()
        var good = FakeBackend()
        let result = try reserveAndCreate(input, using: &good)
        try check(good.calls == ["reserve:" + input.identifier, "create:" + input.identifier], "reserve before creation")
        try check(good.pending && result.handle == 1, "result stays pending")
        try check(result.request.identifier == input.identifier, "bound request")
        try fails(BackendFailure.duplicate) { _ = try reserveAndCreate(input, using: &good) }
        try check(good.calls.count == 3, "duplicate never generates a second key")

        for error in [BackendFailure.duplicate, .denied, .locked, .cancelled, .unavailable] {
            var before = FakeBackend(reservationError: error)
            try fails(error) { _ = try reserveAndCreate(input, using: &before) }
            try check(before.calls == ["reserve:" + input.identifier], "reservation failure stops creation")
            var after = FakeBackend(creationError: error)
            try fails(error) { _ = try reserveAndCreate(input, using: &after) }
            try check(after.pending, "creation failure retains reservation")
            try check(after.calls.count == 2, "creation failure never retries")
            var restarted = FakeBackend(pending: after.pending)
            try fails(BackendFailure.duplicate) { _ = try reserveAndCreate(input, using: &restarted) }
            try check(restarted.calls.count == 1, "pending restart requires explicit recovery")
        }
    }
}
