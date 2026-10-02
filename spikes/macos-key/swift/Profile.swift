import Foundation
import Security

// Compile-only native API assessment. No SecItem or SecKey operation is invoked.
enum ProfileError: Error, Equatable {
    case invalidIdentifier
    case invalidAccessGroup
    case accessControl
}

struct KeyRequest {
    let identifier: String
    let accessGroup: String

    init(suffix: String, accessGroup: String) throws {
        let hex = suffix.utf8
        guard hex.count == 32,
              hex.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw ProfileError.invalidIdentifier
        }
        let group = accessGroup.utf8
        // Trusted configuration only. Syntax is not entitlement authorization.
        guard !group.isEmpty, group.count <= 255,
              group.allSatisfy({ (48...57).contains($0) || (65...90).contains($0)
                  || (97...122).contains($0) || $0 == 45 || $0 == 46 }),
              group.first != 46, group.last != 46,
              !accessGroup.contains("..") else {
            throw ProfileError.invalidAccessGroup
        }
        self.identifier = "io.vollmacht.experimental.issuer.v1." + suffix
        self.accessGroup = accessGroup
    }
}

enum NativeProfile {
    static let reservationService = "io.vollmacht.experimental.issuer-reservation.v1"

    static func creation(_ request: KeyRequest) throws -> [String: Any] {
        // This constructs an in-memory policy object; it does not access Keychain.
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
        ) else {
            _ = error?.takeRetainedValue()
            throw ProfileError.accessControl
        }
        return [
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: request.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(request.identifier.utf8),
                kSecAttrAccessControl as String: control,
            ],
        ]
    }

    static func lookup(_ request: KeyRequest) -> [String: Any] {
        [
            kSecUseDataProtectionKeychain as String: true,
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(request.identifier.utf8),
            kSecAttrAccessGroup as String: request.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecReturnRef as String: true,
            // Two results suffice to detect ambiguity; no unbounded result array.
            kSecMatchLimit as String: 2,
        ]
    }

    static func reservation(_ request: KeyRequest) -> [String: Any] {
        [
            kSecUseDataProtectionKeychain as String: true,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: reservationService,
            kSecAttrAccount as String: request.identifier,
            kSecAttrAccessGroup as String: request.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: Data("pending:v1".utf8),
        ]
    }
}

enum BackendFailure: Error, Equatable {
    case duplicate, denied, locked, cancelled, unavailable
}

// No native implementation: only the test fake conforms to this interface.
protocol CreationBackend {
    associatedtype Handle
    mutating func reserve(_ request: KeyRequest) throws
    mutating func create(_ request: KeyRequest) throws -> Handle
}

// A returned handle is NOT enrolled or usable authorization. Reservation stays pending
// until a future protected registry transaction validates and commits the public key.
struct PendingKey<Handle> {
    let handle: Handle
    let request: KeyRequest
}

func reserveAndCreate<B: CreationBackend>(
    _ request: KeyRequest, using backend: inout B
) throws -> PendingKey<B.Handle> {
    try backend.reserve(request)
    return PendingKey(handle: try backend.create(request), request: request)
}
