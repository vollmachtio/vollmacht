# Independent prepared-key diagnostics review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the three reviewed files. These functions are observational experiment plumbing, not production authorization or evidence of locked-device behavior.

## Scope and conclusions

The ready-record and unique-key checks are extracted without changing preparation ordering or error mapping. Preparation still validates the retained P-256 public point before backend work and returns immutable request/pin/handle fields through the restricted initializer. Existing open still prepares then verifies a fixed-message signature. The create implementation and native backend are unchanged.

The three new probes independently inspect the ready record, inspect a fresh unique lookup against the original pin, or sign with the originally prepared handle. Fresh lookup never replaces that handle. Signing neither re-reads the record nor substitutes current lookup results; it verifies canonical DER evidence against the prepared public point and fixed diagnostic message. Wrong-key, wrong-message and malformed signatures reject without fallback.

Continuing a diagnostic sign after a record/lookup denial is deliberate observation, not revocation enforcement. Documentation explicitly prohibits interpreting it as production authority. The generic API does not bind a handle to its original backend/context, enforce single use or supply scheduling/serialization. Those remain obligations of a separately reviewed owner, including retention of the noninteractive native context. No UI, timer, native method, arbitrary-message entry point, mutation or retry is added.

## Independent verification

- Compiled `Profile.swift`, `Runtime.swift` and `RuntimeTests.swift` with warnings treated as errors and executed only the fake Runtime suite: passed.
- Independently compared native-backend and create implementation bytes with the prior source: unchanged.
- Inspected fake call-order, retained-handle, failed-record/lookup independence, unchanged state, malformed/wrong-key/wrong-message evidence and existing preparation/open controls.
- Independently normalized and compared the coordinator-provided schema-2 base/head coverage reports. Both recorded SDK build `25F70`, matching tool/configuration identity, and zero native-backend executions. The fixed four-source line/function comparison reported no regressions, additions or removals.
- The coverage artifacts were supplied by the coordinator, not independently regenerated base/head builds or authenticated revision artifacts. This scoped comparison is not a repository-wide coverage gate or proof of test adequacy.
- Git whitespace validation passed. The reviewer did not rerun the full workspace or UI checks, launch the app, invoke native Keychain operations, change signing configuration or mutate Git.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/Runtime.swift` | `664e7ac40f6b1570b1602537ccc805a6b934b8ac56d3f31dafc48de8412786b7` |
| `spikes/macos-key/swift/RuntimeTests.swift` | `3cc489fc8361b7a916a3ed23cdbe53623000e5bf2b74ee398730d208cbfe001f` |
| `spikes/macos-key/swift/README.md` | `a9cd8d15f233087147e6ba5c647fe6b0fb94764d7954d05bfd5bf07410408abd` |
