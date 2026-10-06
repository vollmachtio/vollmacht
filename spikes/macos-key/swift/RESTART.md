# Manual signed restart experiment

Experimental P04b slice, 2026-10-05. This is not issuer enrollment or a production storage implementation. Build and fake tests do not exercise native persistence. Actual hardware results must be recorded separately.

## Scope and controls

The manual view has two explicit actions. Nothing accesses Keychain on app startup or in a preview.

1. **Create experimental key** reserves one dedicated identity, checks for an existing tagged key, creates a permanent Secure Enclave P-256 key, verifies a signature over a fixed test message with CryptoKit, and stores its public bytes in the reservation record and app preferences.
2. **Open and verify** requires the original preference pin and matching ready record, retrieves exactly one tagged private key, compares public bytes, and verifies a fresh fixed-message signature. It never creates or replaces a key.

The source contains one fixed experimental suffix. Do not change it to work around a failure. Creation adds a key and a small generic-password reservation record. There is no delete action, software fallback, arbitrary-message signing endpoint, network endpoint or production registration. Private key bytes are never logged or persisted by this code. The adapter checks hardware-key attributes and expects private-key export to fail.

The access group is the running app's signed application identifier. The OS, not this string lookup, enforces access. Keep the same bundle ID and signing team across both launches. Empty explicit Keychain Sharing groups are not assumed to prohibit the app's own default group.

The key uses `WhenUnlockedThisDeviceOnly` with `privateKeyUsage`, not a biometric access-control requirement. Do not expect an additional Touch ID prompt from this experiment. Human authorization remains a separate WebAuthn ceremony.

## Local Xcode integration

Use a dedicated macOS SwiftUI app target with the maintainer's local development signing. Keep its personal signing settings out of the repository. Add copies of `Profile.swift`, `Runtime.swift` and `ProbeView.swift` to that target, then make its existing `ContentView` return `ProbeView()`. Do not add either test entry point to the app target.

Before running, compile and run the fake-only assessment with `python3 spikes/macos-key/swift/run.py`. Have the actual native source and UI independently reviewed. A build alone must not be recorded as a successful hardware test.

## Manual sequence

1. Build and run the app in Xcode. Confirm the experimental warning and two buttons.
2. Click **Create experimental key** once. It may add one key and one reservation. Stop on any error; do not reset preferences or keep retrying.
3. Save the displayed public key and successful fixed-message verification result.
4. Quit the app completely with Command-Q. Restart it from Xcode without changing signing or bundle identity.
5. Click **Open and verify**. Compare its public key with the saved creation result. Both must match exactly and verification must pass.
6. Report both results, OS/Xcode versions and whether any unexpected system prompt appeared. A missing pin or failed lookup is a failure, not permission to adopt another key.

No Keychain cleanup is included. A failure after reservation can leave a pending record or orphan key. Recovery or exact-item cleanup requires a separate reviewed action and explicit approval.

## Limits

The local preference pin is test evidence, not a protected registry. Preferences can be lost or changed by local code. The Keychain ready record and preferences do not form an atomic transaction. If the app crashes before retaining its pin, reopening must fail closed; do not infer durable enrollment from a successful create call. Concurrent cooperative creates are guarded by an exclusive reservation add, but this does not protect against malicious same-access-group code changing or deleting records.

This test does not establish denial under another signing identity, locked-device behavior, concurrent native result behavior, application update continuity, full crash recovery, production packaging or all P04b gates. A local Personal Team profile can expire. No certificate/profile changes or account purchases are performed by this code.
