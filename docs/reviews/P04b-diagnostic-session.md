# Diagnostic session and coverage scope review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the reviewed sources. This is synchronous, observational experiment plumbing, not a scheduler, production authorization control or verified locked-device result.

## Ownership and behavior

The session prepares an existing key through the retained backend, privately retains the prepared handle, pin and identity, and gives the pure timing plan only a void placeholder. Subsequent lookup cannot replace the original signing handle. Public methods cannot inject a handle, message, identity or verified lock interval. Completion supplies no lock evidence and remains inconclusive. Record, lookup and signing observations stay independent, with actual OSStatus values preserved as failures rather than relabeled as verified denials.

Reference ownership prevents accidental value-copy replay of the plan. It does not isolate previously shared backend/clock references or implement synchronization. The README now explicitly requires serialized, non-reentrant callers and describes these alias limitations. Native work requires an explicitly supplied native backend; the reviewed tests use fakes. Synthetic error codes and OSStatus share an Int32 result space, not a unique provenance namespace. Existing Runtime, DiagnosticPlan and native backend implementations are unchanged.

The fake suite checks original context and handle retention, replacement lookup isolation, exact request binding, independent failure observations, constructor failure, one-shot use, cancellation, stale completion, timing rollback, continuity loss and expiry. No native adapter, UI action, Keychain mutation or signing-configuration change was invoked during this review.

## Coverage migration and verification

The collector retains both existing suites and adds the plan and session suites. All four executables and their profiles participate in the merged export. Exact eight-source inventory and zero native execution are required. Configuration and normalization policy explicitly advance to v3 while the metadata envelope remains schema 2; old v2 configuration rejects. The comparator is unchanged. Review feedback corrected stale two-suite/four-file descriptions in both coverage overview documents.

Independent checks:

- Compiled the session suite with warnings treated as errors and ran only its fake executable: passed.
- Collector unit tests: 7 passed. Normalizer unit tests: 10 passed. Runner controls: 7 passed.
- Source inventory: 91 tracked sources accepted, including eight measured Swift sources. Untracked local Xcode content is outside the inventory.
- Independently normalized the coordinator-provided expanded report: eight sources accepted and all 12 native function records had zero executions.
- Independently inspected baseline and expanded report metadata: recorded compiler/LLVM versions, SDK and compile flags match. All four previously measured sources retain exact line/function numerators and denominators. This is raw shared-source evidence, not a successful unchanged-policy comparison.

New source measurements in the supplied expanded report:

| Source | Lines | Functions |
| :--- | :--- | :--- |
| DiagnosticPlan.swift | 103/103 | 19/19 |
| DiagnosticPlanTests.swift | 231/235 | 68/69 |
| DiagnosticSession.swift | 63/64 | 14/14 |
| DiagnosticSessionTests.swift | 209/214 | 71/75 |

The uncovered session line is the private signing bridge's binding-mismatch return. Identity guards also have unexecuted rejection branches. Current public session entry points preserve these invariants; the defenses remain measured and were not removed or excluded to improve percentages. These counts do not establish complete branch coverage or absence of missing tests.

The reviewer inspected supplied collection artifacts rather than independently regenerating both instrumented builds. Artifact authenticity, hermetic environment identity, UI/native execution and a repository-wide regression gate remain outside this slice. Full workspace and UI checks were reported by the coordinator, not rerun by this reviewer.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/DiagnosticSession.swift` | `2a675994c853402bcac892978cd572db9ac3af724036fdd115df14cc3816ee8f` |
| `spikes/macos-key/swift/DiagnosticSessionTests.swift` | `5e2b8de37bcafb586189ca6ec3cc8bf9be8f2d6918dc895bb5f94c3281352178` |
| `spikes/macos-key/swift/run.py` | `88148ab08a67a6de5f842cb8ceb5c6d69c75d09869e8c0ef98af5e7d614fb80f` |
| `spikes/macos-key/swift/test_run.py` | `39b3726f1e5d7a075957af9e802747c6dbb7cf3a79ac047bc322cc7685c07fbf` |
| `spikes/macos-key/swift/README.md` | `e3e9a763d980345cd3793c09c75a21b2de004ef22baf458bad5022eec5cbe6bf` |
| `scripts/coverage_swift.py` | `ea376db61ebe4717e6298e272ba0803c3f1d3dc19abac494edf0891c32ac3775` |
| `scripts/test_coverage_swift.py` | `e56795d0723b9b58ff7cf5e408e3c655cc37fe184596e878e78a23d4b784f2fd` |
| `scripts/normalize_swift_coverage.py` | `42ee3876b3e48372eb48b7cbab761525a20a00ccad285da7a71eb11c4506247e` |
| `scripts/test_normalize_swift_coverage.py` | `9911beeab930ed868007aa16d66687df4eadab7e26fbf8bd7cbf37e0659d2450` |
| `coverage/sources.json` | `dc49a3e661aa3163a170c46beb2819112be5d8d0e42e3735253695917e4b59d9` |
| `docs/coverage.md` | `9c66b0266dae9320c9589ec82b62aeb01bf6ddb5838733a6a40e1c7950165231` |
| `docs/coverage-inventory.md` | `e20dfc9dc1516e57953b4ad794d9ae0d5290e62b4f2238ec04bdf308d4666033` |
| `docs/swift-coverage-normalization.md` | `00ffa0f8490bc0a6db141eff89a3fcf46373f55358aee0132624c545fa351577` |
