# Diagnostic UI integration review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings. Documentation was clarified to describe a key request derived from signing entitlements, not a signed request. This integrates experimental controls; it does not establish protected locked-device behavior or close P04b/P06 gates.

## Ownership, provenance and native boundaries

The view uses a lazy static main-actor model shared across windows. Constructing it stores closures only. The model retains one operation gate and its controller for the app lifetime; window disappearance neither resets the diagnostic allocation nor cancels work. Legacy Create/Open and diagnostic preparation, arming and cancellation cannot overlap through this owner.

Legacy completions capture their original token. Controller events originate from the configured private observer closure, hop to the main actor and retain the controller's run ID through the exact adapter. Stale or rejected callbacks cannot release a newer operation or overwrite accepted completion. Native work ends before its trusted completion is delivered; a cancellation request alone never releases the gate. The controller is retained before preparation is enqueued.

The native request, saved pin and backend/context are loaded only within explicitly invoked workers. The original suffix, preference key and signing-entitlement request derivation are unchanged. Preparation retains the original key handle through the existing session. No regeneration, repinning, arbitrary-message signing or new native method is added. Existing Create remains an explicit mutating action; the existing-key handoff prominently forbids repeating it.

Pure error formatting was moved into the model before final validation. Executed model tests exclude ProbeView and its native singleton factories entirely. The actual view is typechecked separately, not instantiated or launched. Its button enablement supplements the model's state checks rather than serving as the sole operation gate.

## Independent validation

- Compiled and executed the injected model fake suite under Swift 6 complete concurrency checking with warnings treated as errors: passed.
- Independently typechecked the complete nine-source UI graph with the same strict flags: passed, without app launch.
- Seven collector, ten normalizer and seven runner controls passed. All earlier fake suites remain; the UI dependency list is explicit and excluded from executed suites.
- Source inventory accepted 103 tracked sources, including sixteen measured Swift sources. ProbeView remains unmeasured.
- Independently normalized the supplied v7 artifact: model 84/84 lines and 19/19 functions; model tests 133/133 lines and 42/42 functions. All 12 native function records had zero executions.
- All fourteen retained sources have exact unchanged line/function numerators and denominators relative to the supplied v6 artifact. Recorded compiler/LLVM versions and SDK match; prior suite flags are retained. Policy v7 explicitly changes scope and cannot masquerade as v6. The comparator is unchanged.

Instrumented artifacts were supplied by the coordinator rather than independently regenerated for both revisions. Line/function counters do not establish exhaustive branches, multiwindow GUI behavior or native timing. Full workspace checks were coordinator-reported; this reviewer ran only the scoped checks above. No native calls, personal-project changes, signing changes or Git mutations were performed.

## Manual handoff limits

The instructions require review and CI before the maintainer manually updates the existing nine source copies. They preserve signing, bundle/key identity and saved pin, forbid unattended native testing and direct existing-key users away from Create. Screen lock is not asserted to lock Keychain. Timers can run late, entered operations can overrun, and all diagnostic completions remain inconclusive about a verified lock interval. Cancellation requires an accepted acknowledgement, not merely a click. Physical denied-access, isolation and protected locked-state gates remain open.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `coverage/sources.json` | `e6e9389fc1fac6f8605fbd6aa7c6c364e5c5eb8479658a99b49f9877e49b23f2` |
| `docs/coverage-inventory.md` | `9be1a91153c86b5e6fd8b4a7d4a3b1c3121056d9101335f76538894f82187f52` |
| `docs/coverage.md` | `145db816d9dc1c739bbcfbd91d9ccf616e97151b60742771e0316189c31c4d5b` |
| `docs/swift-coverage-normalization.md` | `1f74f3cfe0437aa9a0d2e267beb1d08646971217b6ead74e71f37451d7c9f785` |
| `scripts/coverage_swift.py` | `2ea1ef95a89e74f1970bc899aae9717087053a779b82c94b984d1765641a0d34` |
| `scripts/normalize_swift_coverage.py` | `4b90af87a8ee4c68adb36826b14b0e5a44106ed4d90f2d05f29c9fd252d56b44` |
| `scripts/test_coverage_swift.py` | `289fe00f2f10ae003938fd5f583a2c07db93025895b872a8157cb0c8f2a64286` |
| `scripts/test_normalize_swift_coverage.py` | `c1b67358cc2d865dedf53e2bc527b5a6f978080ac6951c1e7d76cd1b53072947` |
| `spikes/macos-key/swift/DELAYED-CONTROLLER.md` | `28ede9e6727fe6212a9f5e3d46b32026ca68bbb7861c9960c0ebeec1f901014e` |
| `spikes/macos-key/swift/OPERATION-STATE.md` | `44fce9aedb907d13ff09639e1a6883b4c75749185ad720e0ce3d68af88f3be87` |
| `spikes/macos-key/swift/ProbeModel.swift` | `9f7bb521b8e86d6544721b7ffdcb4ffd40a95b93968cb552a6c903f2c5a682b7` |
| `spikes/macos-key/swift/ProbeModelTests.swift` | `0847afd409f29bc8dac82fc823353dc53e671bbede1248cea23d74559a2f8605` |
| `spikes/macos-key/swift/ProbeView.swift` | `e63ac4a373d55a3ed505f9f0833c5f4ccb4f1d47c899368f6b548348906a7121` |
| `spikes/macos-key/swift/README.md` | `b18f637a92dec5bc017a9ada5a6e90ba052aff303be95256c618a387686e8131` |
| `spikes/macos-key/swift/RESTART.md` | `1363229f6bf659ee24d9bb99d4f445e96902852db4cc9cea882f580e3708d8b3` |
| `spikes/macos-key/swift/run.py` | `babbd4cf04f5debd9e413f7362acdc7390736cb3ed567ceccf4fbac4719c70d7` |
| `spikes/macos-key/swift/test_run.py` | `82b8c5ff91a20b2c8788ca3b295bb4704de117948163e892fd41e4d583928724` |
