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

@MainActor
struct ProbeView: View {
    @StateObject private var model = ProbeModel.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Vollmacht native-key experiment").font(.title2)
            Text("Create adds one dedicated Secure Enclave key and one reservation record. Nothing is deleted. This does not enroll a production issuer.")
            Text("After creation, quit the app completely, reopen it, then choose Open and verify. The public-key pin is local test evidence, not a protected trust registry.")
            HStack {
                Button("Create experimental key") { model.perform(create: true) }
                Button("Open and verify") { model.perform(create: false) }
            }
            .disabled(!model.canRunLegacy)
            HStack {
                Button("Prepare existing key diagnostic") { model.prepare() }.disabled(!model.canPrepare)
                Button("Arm one delayed attempt") { model.arm() }.disabled(!model.canArm)
                Button("Request cancellation") { model.cancel() }.disabled(!model.canCancel)
            }
            Text("One diagnostic per app launch. Arm schedules one attempt after 15 seconds with a five-second start window. A prepared diagnostic can be armed or abandoned by quitting. Closing a window does not cancel it.")
            Text("Screen lock is not proof that Keychain is locked. Results remain inconclusive; an entered operation can finish after the window. No automatic retry or cleanup.")
            Text(model.message).font(.system(.body, design: .monospaced)).textSelection(.enabled)
            Text("No biometric requirement is added. Human approval remains a separate WebAuthn ceremony.")
                .font(.footnote)
        }
        .padding(24)
        .frame(minWidth: 640, minHeight: 320)
    }

}

extension ProbeModel {
    // Lazy app-lifetime owner. Constructing it only stores closures; signing
    // identity, preferences and native backend are accessed on workers on demand.
    static let shared = ProbeModel(legacyWork: { create, completion in
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
                result = "STOP: \(ProbeFailureDisplay.label(error))\nNo automatic retry, replacement or cleanup. Report this result."
            }
            completion(result)
        }
    }, factory: { token, observer in
        DelayedDiagnosticController(runID: token, clock: ContinuousDiagnosticClock(), factory: { id, clock in
            let request = try ProbeConfiguration.request()
            guard let pin = UserDefaults.standard.data(forKey: ProbeConfiguration.pinPreference), pin.count == 65 else {
                throw RuntimeFailure.pinMismatch
            }
            return try OwnedSessionDriver(request: request, expectedPublic: pin, runID: id,
                                          backend: NativeKeyBackend(), clock: clock)
        }, observer: observer)
    })
}
