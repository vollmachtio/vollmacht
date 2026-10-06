// Explicit native experiment API. No entry point or automatic Keychain operation.
import Foundation
import Security
import CryptoKit
import LocalAuthentication

enum RuntimeFailure: Error, Equatable {
    case status(Int32)
    case nativeFailure, missing, pending, ambiguous, existingKey
    case invalidKey, pinMismatch, invalidRecord
}

enum RuntimeProfile {
    static let message = Data("vollmacht:macos-durable-key-probe:v1\0fixed-test-message-not-a-mandate".utf8)
    static let pending = Data("pending:v1".utf8)
    static let readyPrefix = Data("ready:v1:".utf8)
}

struct RuntimeEvidence {
    let publicKey: Data
    let signature: Data
}

protocol RuntimeBackend {
    associatedtype Handle
    mutating func reserve(_ request: KeyRequest) throws
    mutating func readRecord(_ request: KeyRequest) throws -> Data
    mutating func commit(_ request: KeyRequest, record: Data) throws
    mutating func keys(_ request: KeyRequest) throws -> [Handle]
    mutating func create(_ request: KeyRequest) throws -> Handle
    mutating func publicBytes(_ handle: Handle) throws -> Data
    mutating func signFixed(_ handle: Handle) throws -> Data
}

private func validatePublic(_ bytes: Data) throws -> P256.Signing.PublicKey {
    guard bytes.count == 65, bytes.first == 4 else { throw RuntimeFailure.invalidKey }
    do { return try P256.Signing.PublicKey(x963Representation: bytes) }
    catch { throw RuntimeFailure.invalidKey }
}

private func evidence<B: RuntimeBackend>(_ handle: B.Handle, publicBytes: Data, using backend: inout B) throws -> RuntimeEvidence {
    let publicKey = try validatePublic(publicBytes)
    let signature = try backend.signFixed(handle)
    guard signature.count <= 72 else { throw RuntimeFailure.invalidKey }
    do {
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        guard parsed.derRepresentation == signature,
              publicKey.isValidSignature(parsed, for: RuntimeProfile.message) else {
            throw RuntimeFailure.invalidKey
        }
    } catch { throw RuntimeFailure.invalidKey }
    return RuntimeEvidence(publicKey: publicBytes, signature: signature)
}

func createPersistent<B: RuntimeBackend>(_ request: KeyRequest, using backend: inout B) throws -> RuntimeEvidence {
    // The atomic add is the exclusive claim, not the following key lookup.
    try backend.reserve(request)
    guard try backend.keys(request).isEmpty else { throw RuntimeFailure.existingKey }
    let handle = try backend.create(request)
    let publicBytes = try backend.publicBytes(handle)
    let result = try evidence(handle, publicBytes: publicBytes, using: &backend)
    try backend.commit(request, record: RuntimeProfile.readyPrefix + publicBytes)
    return result
}

func openPersistent<B: RuntimeBackend>(_ request: KeyRequest, expectedPublic: Data, using backend: inout B) throws -> RuntimeEvidence {
    _ = try validatePublic(expectedPublic)
    let record = try backend.readRecord(request)
    if record == RuntimeProfile.pending { throw RuntimeFailure.pending }
    guard record.count == RuntimeProfile.readyPrefix.count + 65,
          record.starts(with: RuntimeProfile.readyPrefix) else { throw RuntimeFailure.invalidRecord }
    guard record == RuntimeProfile.readyPrefix + expectedPublic else { throw RuntimeFailure.pinMismatch }
    let matches = try backend.keys(request)
    guard !matches.isEmpty else { throw RuntimeFailure.missing }
    guard matches.count == 1 else { throw RuntimeFailure.ambiguous }
    let publicBytes = try backend.publicBytes(matches[0])
    guard publicBytes == expectedPublic else { throw RuntimeFailure.pinMismatch }
    return try evidence(matches[0], publicBytes: publicBytes, using: &backend)
}

// Only an explicitly invoked application action should instantiate and call this.
// Tests use a fake implementation and never call these methods.
struct NativeKeyBackend: RuntimeBackend {
    typealias Handle = SecKey
    private let context: LAContext = {
        let value = LAContext()
        value.interactionNotAllowed = true
        return value
    }()

    private func status(_ value: OSStatus) throws {
        guard value == errSecSuccess else { throw RuntimeFailure.status(value) }
    }

    private func recordQuery(_ request: KeyRequest) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: NativeProfile.reservationService,
         kSecAttrAccount as String: request.identifier,
         kSecAttrAccessGroup as String: request.accessGroup,
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true,
         kSecUseAuthenticationContext as String: context]
    }

    mutating func reserve(_ request: KeyRequest) throws {
        var query = NativeProfile.reservation(request)
        query[kSecUseAuthenticationContext as String] = context
        try status(SecItemAdd(query as CFDictionary, nil))
    }

    mutating func readRecord(_ request: KeyRequest) throws -> Data {
        var query = recordQuery(request)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let code = SecItemCopyMatching(query as CFDictionary, &result)
        if code == errSecItemNotFound { throw RuntimeFailure.missing }
        try status(code)
        guard let result, CFGetTypeID(result) == CFDataGetTypeID(),
              let bytes = result as? Data,
              bytes.count <= RuntimeProfile.readyPrefix.count + 65 else { throw RuntimeFailure.invalidRecord }
        return bytes
    }

    mutating func commit(_ request: KeyRequest, record: Data) throws {
        // Only the creator that successfully reserved may reach this operation.
        guard record.count == RuntimeProfile.readyPrefix.count + 65,
              record.starts(with: RuntimeProfile.readyPrefix),
              try readRecord(request) == RuntimeProfile.pending else { throw RuntimeFailure.invalidRecord }
        try status(SecItemUpdate(recordQuery(request) as CFDictionary,
                                [kSecValueData as String: record] as CFDictionary))
        guard try readRecord(request) == record else { throw RuntimeFailure.invalidRecord }
    }

    mutating func keys(_ request: KeyRequest) throws -> [SecKey] {
        var query = NativeProfile.lookup(request)
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let code = SecItemCopyMatching(query as CFDictionary, &result)
        if code == errSecItemNotFound { return [] }
        try status(code)
        guard let result, CFGetTypeID(result) == CFArrayGetTypeID(),
              let values = result as? [Any], values.count <= 2,
              values.allSatisfy({ CFGetTypeID($0 as CFTypeRef) == SecKeyGetTypeID() }),
              let keys = values as? [SecKey] else { throw RuntimeFailure.invalidKey }
        return keys
    }

    mutating func create(_ request: KeyRequest) throws -> SecKey {
        var error: Unmanaged<CFError>?
        var attributes = try NativeProfile.creation(request)
        attributes[kSecUseAuthenticationContext as String] = context
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error { throw RuntimeFailure.status(Int32(clamping: CFErrorGetCode(error.takeRetainedValue()))) }
            throw RuntimeFailure.nativeFailure
        }
        return key
    }

    mutating func publicBytes(_ key: SecKey) throws -> Data {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256 else { throw RuntimeFailure.invalidKey }
        var error: Unmanaged<CFError>?
        let privateExport = SecKeyCopyExternalRepresentation(key, &error)
        _ = error?.takeRetainedValue()
        guard privateExport == nil, let publicKey = SecKeyCopyPublicKey(key) else { throw RuntimeFailure.invalidKey }
        error = nil
        guard let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            _ = error?.takeRetainedValue()
            throw RuntimeFailure.invalidKey
        }
        return bytes as Data
    }

    mutating func signFixed(_ key: SecKey) throws -> Data {
        guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else { throw RuntimeFailure.invalidKey }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                   RuntimeProfile.message as CFData, &error) else {
            if let error { throw RuntimeFailure.status(Int32(clamping: CFErrorGetCode(error.takeRetainedValue()))) }
            throw RuntimeFailure.nativeFailure
        }
        return signature as Data
    }
}
