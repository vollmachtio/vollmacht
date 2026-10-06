# P04b manual native restart experiment review

Reviewed 2026-10-05 by independent reviewer `adversarial_p02`, separate from runtime author `durable_key_contract` and root UI/integration author.

## Findings and resolution

The initial UI failed compilation because `SecCodeCopySigningInformation` requires `SecStaticCode`, while the code supplied `SecCode`. The author added checked `SecCodeCopyStaticCode` conversion; subsequent UI typechecking passed. A documentation statement implying all runtime code was unexecuted was corrected to distinguish generic functions exercised with fakes from uninvoked `NativeKeyBackend` methods.

No remaining blockers found for the explicit manual experiment. This is not approval of a production key store, unrestricted native run or automatic cleanup.

## Reviewed security boundaries

Creation performs an exclusive reservation add before key lookup or generation. Existing reservation/key state stops creation without replacement. Failures after reservation retain partial state; there is no delete or retry API. Reopening requires the original public preference pin, matching ready record and exactly one tagged key. Public bytes must match before fixed-message signing. Key attributes and unavailable private export are checked, and CryptoKit verifies the returned DER signature over the fixed message.

The native profile remains explicit Data Protection Keychain, Secure Enclave P-256 and WhenUnlockedThisDeviceOnly with privateKeyUsage. Authentication context disallows interaction. No software/file-keychain fallback, arbitrary-message input or network endpoint is introduced. These are requested native settings, not proof that all API behavior has succeeded on hardware.

The UI performs no Keychain work on startup. Both actions require explicit user input; it uses a fixed experimental identifier, serializes actions within the view and derives the access-group string from signing information. The OS remains responsible for enforcing entitlements. Missing preferences fail reopening rather than enrolling or regenerating a key. Only public pin data is persisted in preferences.

The reservation update is read-then-update, not a compare-and-swap transaction against hostile writers. Cooperative creators are excluded by the reservation add, but malicious same-access-group code and mutable preferences remain outside the experiment's protection. The documentation acknowledges non-atomic preference/record state, partial failures, missing crash recovery and the remaining identity/lock/update matrix.

## Independent validation

Ran the fake-only Swift runner: profile tests, runtime fake tests and UI typechecking. The final runtime fake cases include a fresh fake instance reopening retained state and a valid DER signature over the wrong message. Seven portable Python runner-control tests passed. The runner executes only fake test binaries; the UI is typechecked, never launched. No native backend was instantiated by executed tests.

No real Keychain creation, lookup, signature, deletion, signing-identity change or application launch was performed by this reviewer. The local Xcode project is outside this seven-file review; its actual target build and manual results are separate evidence. Exact-head CI remains required.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
55abca21ac7587bca907a265468857c07bbfaf60825c9494c38577e1f58c3a56  spikes/macos-key/swift/Runtime.swift
b128f263f1d908383e64ab817be8e60421abc89c1f0501477cfe3100a2022502  spikes/macos-key/swift/RuntimeTests.swift
c4c3ef6cef58bba2d3bfe3f4f4c47a81b4cad9632fc1006a0d088744b5431364  spikes/macos-key/swift/ProbeView.swift
d7f01060de9d2494ebea4cf30bd25feb63330b99e41d9133f3e28f5d493e4768  spikes/macos-key/swift/RESTART.md
00aaad18a45336f8788a8a0af599eee8db9dcedf79ba6cb2d94968b965ce087d  spikes/macos-key/swift/run.py
e3322c66cf586bd4c2c7d7bdf59cead36a59c29e139abac66dc52b8e0c8e9025  spikes/macos-key/swift/test_run.py
eec17808a0109b17b78c44aa14090b34a4b6ec47dcf0477e2755852213d3db29  spikes/macos-key/swift/README.md
```
