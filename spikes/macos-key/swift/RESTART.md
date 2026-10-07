# Manual signed restart experiment

Experimental P04b slice, 2026-10-05. This is not issuer enrollment or a production storage implementation. Build and fake tests do not exercise native persistence. Actual hardware results must be recorded separately.

## Scope and controls

The manual view retains two original explicit actions and adds a separately armed diagnostic. Nothing accesses Keychain on app startup or in a preview. A shared app-lifetime owner prevents overlapping operations across windows.

1. **Create experimental key** reserves one dedicated identity, checks for an existing tagged key, creates a permanent Secure Enclave P-256 key, verifies a signature over a fixed test message with CryptoKit, and stores its public bytes in the reservation record and app preferences.
2. **Open and verify** requires the original preference pin and matching ready record, retrieves exactly one tagged private key, compares public bytes, and verifies a fresh fixed-message signature. It never creates or replaces a key.

The source contains one fixed experimental suffix. Do not change it to work around a failure. Creation adds a key and a small generic-password reservation record. There is no delete action, software fallback, arbitrary-message signing endpoint, network endpoint or production registration. Private key bytes are never logged or persisted by this code. The adapter checks hardware-key attributes and expects private-key export to fail.

The access group is the running app's signed application identifier. The OS, not this string lookup, enforces access. Keep the same bundle ID and signing team across both launches. Empty explicit Keychain Sharing groups are not assumed to prohibit the app's own default group.

The key uses `WhenUnlockedThisDeviceOnly` with `privateKeyUsage`, not a biometric access-control requirement. Do not expect an additional Touch ID prompt from this experiment. Human authorization remains a separate WebAuthn ceremony.

## Local Xcode integration

Use the existing dedicated macOS SwiftUI app target with the maintainer's local development signing. Keep its personal signing settings out of the repository. Include these nine source files in that target: `Profile.swift`, `Runtime.swift`, `DiagnosticPlan.swift`, `DiagnosticSession.swift`, `DelayedDiagnosticController.swift`, `ProbeOperationState.swift`, `ProbeEventAdapter.swift`, `ProbeModel.swift` and `ProbeView.swift`. Its existing `ContentView` should return `ProbeView()`. Do not add any test entry point to the app target. Updating these source copies is a manual task; automation must not edit the personal Xcode project or change signing, entitlements, the bundle ID, key suffix or preference pin.

Before running, compile and run the fake-only assessment with `python3 spikes/macos-key/swift/run.py`. Have the actual native source and UI independently reviewed. A build alone must not be recorded as a successful hardware test.

## Original creation and restart sequence

For a previously successful restart test, do not repeat creation. Preserve that key and its saved public pin. The sequence below is for a new, explicitly approved experiment only; existing-key diagnostics are described separately.

1. Build and run the app in Xcode. Confirm the experimental warning and original Create/Open buttons. Do not use the diagnostic controls during this sequence.
2. Click **Create experimental key** once. It may add one key and one reservation. Stop on any error; do not reset preferences or keep retrying.
3. Save the displayed public key and successful fixed-message verification result.
4. Quit the app completely with Command-Q. Restart it from Xcode without changing signing or bundle identity.
5. Click **Open and verify**. Compare its public key with the saved creation result. Both must match exactly and verification must pass.
6. Report both results, OS/Xcode versions and whether any unexpected system prompt appeared. A missing pin or failed lookup is a failure, not permission to adopt another key.

No Keychain cleanup is included. A failure after reservation can leave a pending record or orphan key. Recovery or exact-item cleanup requires a separate reviewed action and explicit approval.

## Existing-key diagnostic handoff

Only the maintainer should perform these steps after the integrated source is reviewed and CI passes. No unattended native test is authorized. This is not a repeat of key creation.

1. Quit the experiment with Command-Q. Update the nine source copies above without changing the existing target identity or signing configuration. Build first; stop and report any error instead of changing entitlements or recreating the project.
2. Launch the app. Confirm no startup operation occurs. Do not click **Create experimental key**. Click **Prepare existing key diagnostic** once. It checks the existing pin, reservation record and matching key, retaining that exact key handle without signing. Stop on `preparation_failed`; do not reset the pin, replace the key or retry automatically.
3. After `existing_key_prepared`, click **Arm one delayed attempt**. Wait for `one_attempt_scheduled`. One callback is scheduled after 15 seconds, with a five-second window in which it may start. Record the observed scheduling, screen-lock and unlock times separately. Keep the app running; closing its window does not cancel work. Do not deliberately put the Mac to sleep.
4. For a screen-lock observation, lock the screen promptly after the scheduled acknowledgement and unlock after the start window has passed. This does not establish that Keychain was locked or that the callback ran while locked. A delayed callback is rejected; an entered operation may finish after the window. Every displayed completion remains explicitly inconclusive about lock state.
5. Report the complete bounded diagnostic result, observed times, OS/Xcode versions and any unexpected prompts. Record, lookup and fixed-message signing outcomes are separate observations. Success is not proof of locked-device protection; a denied or missing result must not trigger replacement or cleanup.

Cancellation is a separate optional run after a full quit/relaunch: prepare, arm and promptly choose **Request cancellation**. Only `cancelled_before_attempt` confirms cancellation before entry. A request may lose the race with execution and cannot interrupt an entered call. There is one diagnostic allocation per app launch; preparation failure also consumes it. Prepared-but-unarmed work may be armed or abandoned by quitting, not reset. New windows share the same owner.

These observations do not satisfy the remaining protected locked-state or other-signing-identity gates on their own. There is no built-in trusted lock-state observer, Keychain lock command or verified interval attestation.

## Limits

The local preference pin is test evidence, not a protected registry. Preferences can be lost or changed by local code. The Keychain ready record and preferences do not form an atomic transaction. If the app crashes before retaining its pin, reopening must fail closed; do not infer durable enrollment from a successful create call. Concurrent cooperative creates are guarded by an exclusive reservation add, but this does not protect against malicious same-access-group code changing or deleting records.

This test does not establish denial under another signing identity, locked-device behavior, concurrent native result behavior, application update continuity, full crash recovery, production packaging or all P04b gates. A local Personal Team profile can expire. No certificate/profile changes or account purchases are performed by this code.
