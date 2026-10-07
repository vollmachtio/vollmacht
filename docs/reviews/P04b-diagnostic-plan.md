# Pure diagnostic plan review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: initial timing finding fixed and re-reviewed; no remaining blockers in the six reviewed files. This is a pure sequencing assessment, not native locked-device evidence or permission to run that experiment.

## Finding and resolution

The first version compared each attempted poll only with the arm timestamp. An early poll at 109 after arming at 100 returned `notDue` without retaining that observation; a subsequent 105 observation could therefore hide an observed rollback and permit a later conclusive result.

The final version retains `lastObserved` across early polls and compares each new observation against it. Rollback or changed continuity consumes an inconclusive attempt without backend calls. Added regression tests exercise the exact 100/109/105 sequence, continuity change after an early poll, and valid repeated early polling with inclusive diagnostic window endpoints. The reviewer inspected the fix and independently reran the final fake suite successfully.

## Boundaries and integration

Identity and public-pin shape checks are not cryptographic enrollment. Handle provenance, reliable clocks/lock evidence, native time bounds, unique run ownership and serialized access remain explicit future obligations. Late or discontinuous observations stop remaining probes; nil results mean unattempted, not denied. The synchronous plan cannot interrupt blocked calls or service cancellation mid-call, as documented.

Record read, fresh lookup and retained-handle signing are deliberately independent diagnostic probes. A denied lookup does not select a replacement handle or turn diagnostic signing into production authorization. Only a fixed message is supplied. A conclusive interval describes supplied timing evidence, not successful protection, Keychain lock state or biometric verification.

The runner adds a third fake executable compiled only from the two diagnostic files, retaining both previous fake suites and the separate UI typecheck. The structural runner test asserts all seven commands and the diagnostic-only input list. Inventory additions classify the model and tests as unmeasured; the existing Swift coverage collector is not silently expanded or relabeled.

## Independent verification

- All seven Python runner controls passed on the final integration.
- Compiled only `DiagnosticPlan.swift` and `DiagnosticPlanTests.swift` with warnings treated as errors, then executed that fake-only binary. All 216 outcome combinations and lifecycle/timing/evidence negatives passed, including the new regression controls.
- No native backend, Security API, Keychain operation, timer, UI, app launch or user-device action was invoked by this test run.
- Reviewed the integration and documentation changes statically. No full-workspace rerun, Git mutation or reviewed-source edit was performed by the reviewer.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/DiagnosticPlan.swift` | `ec82003c29bce0c3c16378264f2a1a5f585da4d6b2f9b034b6e3d551476be495` |
| `spikes/macos-key/swift/DiagnosticPlanTests.swift` | `2702753c9219f6a9fefed37404ab0287b10dcfecbe0ede2f666dc6f31158128d` |
| `spikes/macos-key/swift/DIAGNOSTIC-PLAN.md` | `d011552e2df517d424730c1ec385113391fe487529bb2322cd2a088f66fff667` |
| `spikes/macos-key/swift/run.py` | `c82d1fd247429c26b961d051141eab28c56b5081989714ae1c8690bd552a3d86` |
| `spikes/macos-key/swift/test_run.py` | `165183f60bafb1050cfb08e26b64195cddaa8dbab697ed075fd13534e20d38bb` |
| `coverage/sources.json` | `3871a94c198fed9e72578bec86a24c9d3d090bcc13d9451d7a2c0d56f9ce0916` |

## Final main integration

After integration with main `fa76dd6`, all five diagnostic/model/runner source hashes above remain unchanged. The inventory now retains main's two Python Swift-normalization entries and adds only the two reviewed diagnostic files relative to that base. The reviewer independently reran the inventory CLI: 85 indexed sources accounted for, with 80 unmeasured, four raw Swift fake-test sources and one attribution-only source. No integration blocker or classification weakening was found. Runtime tests were not repeated for this inventory-only follow-up.

Final integrated `coverage/sources.json` SHA-256: `01077661a9f52d2b9edfe37afe1cb8b755351bb4433ec76e9f0a59965e4a8835`.
