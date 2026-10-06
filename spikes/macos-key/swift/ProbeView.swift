import Foundation
import Security
import SwiftUI

// Manual experiment only. Opening this view performs no Keychain operation.
// This identifier stays fixed across launches and builds. Do not randomize it.
enum ProbeConfiguration {
    static let suffix = "896741d19f374c3abee480b894bbfb02"
    static let pinPreference = "vollmacht.experimental.restart.public-pin.v1"

    static func request() throws -> KeyRequest {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            throw RuntimeFailure.nativeFailure
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { throw RuntimeFailure.nativeFailure }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information
        ) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let identifier = entitlements["com.apple.application-identifier"] as? String else {
            throw RuntimeFailure.nativeFailure
        }
        // The OS still enforces access. Reading an entitlement is not an access test.
        return try KeyRequest(suffix: suffix, accessGroup: identifier)
    }
}

struct ProbeView: View {
    @State private var busy = false
    @State private var message = "No Keychain operations have run in this window."

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Vollmacht native-key experiment").font(.title2)
            Text("Create adds one dedicated Secure Enclave key and one reservation record. Nothing is deleted. This does not enroll a production issuer.")
            Text("After creation, quit the app completely, reopen it, then choose Open and verify. The public-key pin is local test evidence, not a protected trust registry.")
            HStack {
                Button("Create experimental key") { perform(create: true) }
                Button("Open and verify") { perform(create: false) }
            }
            .disabled(busy)
            Text(message).font(.system(.body, design: .monospaced)).textSelection(.enabled)
            Text("No biometric requirement is added. Human approval remains a separate WebAuthn ceremony.")
                .font(.footnote)
        }
        .padding(24)
        .frame(minWidth: 640, minHeight: 320)
    }

    private func perform(create: Bool) {
        guard !busy else { return }
        busy = true
        message = "Working. Do not repeat the operation."
        DispatchQueue.global(qos: .userInitiated).async {
            let result: String
            do {
                let request = try ProbeConfiguration.request()
                let preferences = UserDefaults.standard
                var backend = NativeKeyBackend()
                let evidence: RuntimeEvidence
                if create {
                    guard preferences.object(forKey: ProbeConfiguration.pinPreference) == nil else {
                        throw RuntimeFailure.existingKey
                    }
                    evidence = try createPersistent(request, using: &backend)
                    // Only public bytes are persisted here. A crash or lost preference
                    // must fail closed on reopen, never adopt or regenerate a key.
                    preferences.set(evidence.publicKey, forKey: ProbeConfiguration.pinPreference)
                } else {
                    guard let pin = preferences.data(forKey: ProbeConfiguration.pinPreference),
                          pin.count == 65 else { throw RuntimeFailure.pinMismatch }
                    evidence = try openPersistent(request, expectedPublic: pin, using: &backend)
                }
                result = "PASS: \(create ? "created" : "reopened") and verified a fixed-message signature.\nPublic key: \(evidence.publicKey.base64EncodedString())\n\(create ? "Now quit and reopen the app." : "Compare this public key with the creation result.")"
            } catch {
                result = "STOP: \(String(describing: error))\nNo automatic retry, replacement or cleanup. Report this result."
            }
            DispatchQueue.main.async {
                message = result
                busy = false
            }
        }
    }
}
