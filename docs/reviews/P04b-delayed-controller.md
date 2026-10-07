# Delayed diagnostic controller review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no remaining blocking findings in the reviewed slice. This is experimental diagnostic scheduling, not production authorization or verified locked-device behavior.

## Findings and resolution

The initial controller discarded the returned attempt and accepted completed evidence without matching its run ID or contents. The final version rejects a wrong attempt ID before completion and requires the completed report to match the exact attempt and controller run ID. Three valid-shaped negative controls cover these cases. Unexpected verified lock evidence also rejects.

The scheduler now explicitly requires asynchronous, serial, non-inline execution. Factory, driver and clock callbacks are trusted dependencies and must not reenter locked state or export session aliases. Observer callbacks execute outside the mutex and may enqueue follow-up commands. A bounded real-worker test covers off-main preparation and observer reentry without native operations.

The nongeneric controller retains a non-Sendable existential driver under a checked mutex, with no unchecked Sendable bypass. The factory constructs the owned session on the worker. Initialization alone does not construct a backend or access Keychain. Original-handle ownership and fixed-message signing remain in the previously reviewed session/runtime.

Cancellation only succeeds when processed while armed. A request queued behind an in-flight synchronous operation cannot interrupt it, and the documentation does not claim otherwise. Early, late, invalid-clock or discontinuous callbacks consume the attempt without entering the driver. Timer delivery is not a wake guarantee. Continuous elapsed time includes sleep but its constant continuity marker does not detect suspension. An entered operation can overrun its window; results remain inconclusive. No native factory or view integration is added.

## Independent checks

- Compiled the controller suite in Swift 6 mode with complete strict concurrency and warnings treated as errors; fake/software tests passed, including the bounded real-worker test. An initial compile was invalidated by a concurrent source edit; the stable-source rerun passed.
- Seven collector, ten normalizer and seven runner-control tests passed. Existing suites and UI typechecking remain in the runner; no existing assertion was removed.
- Inspected the actual expanded collector artifact and independently normalized its ten sources. All 12 native function records had zero executions.
- All eight retained sources had exactly unchanged line/function numerators and denominators against the supplied baseline. Recorded compiler/LLVM versions and SDK matched. The fifth suite adds Swift 6 flags and policy v4, so this is not an unchanged-policy comparison. No metadata spoofing or comparator weakening was used.
- New LLVM summary counts were controller 252/271 lines and 31/38 functions, and controller tests 250/257 lines and 99/104 functions. These are LLVM summary counters, not a claim of complete source-line or branch coverage.

The reviewer inspected coordinator-supplied instrumented artifacts rather than independently rebuilding both revisions. Full workspace checks, UI typechecking and hardware behavior are not claimed as independently rerun here. The reviewer made no native calls, Keychain changes, signing changes, personal-project changes or Git mutations. Artifact authenticity, environmental isolation, physical timing and a complete coverage-regression gate remain outside this slice.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/DelayedDiagnosticController.swift` | `3b8ab7ddd674904dd437bb00db50e7404f693ab837f9deed8ea86cf2462876e2` |
| `spikes/macos-key/swift/DelayedDiagnosticControllerTests.swift` | `21a3610b574ddfea32d7c07c78bee864682a09ec4fc58e0bba088d9215495e1a` |
| `spikes/macos-key/swift/DELAYED-CONTROLLER.md` | `b085d0ecb0a6178e70706e2be970b2747bd7e3a6473c6c38f8b57c2b415ee5aa` |
| `spikes/macos-key/swift/README.md` | `e21b961826031d4c003ffdca9e80260ba11019b182aeb2c05c4feeeee56b0697` |
| `spikes/macos-key/swift/run.py` | `41393bae8c9efdb4328c13de9956ebe445e482e884b7e71c2a808cd5f6dc1b2a` |
| `spikes/macos-key/swift/test_run.py` | `1714256c10f0134cbe337ba4c81b641bf80b2653bc0484fee09ff3cacf30fefb` |
| `scripts/coverage_swift.py` | `ba208ccf038db4063c17c5538c001d34043242bd7254ad8f4c3bb02d7627dc74` |
| `scripts/test_coverage_swift.py` | `d5ae6cb8af1cf3003d12aae2d8e59da10a8fae3d69f26802f709cca1fd50f515` |
| `scripts/normalize_swift_coverage.py` | `676cba0ff338484784075aa93affd36276ce4c6e3c9ee60b304ceeb39a20c1c1` |
| `scripts/test_normalize_swift_coverage.py` | `d015f6e3cfec3291528f778bcd0c30d94f22d295887897516e7d1cca8f57df6e` |
| `coverage/sources.json` | `b59301981838b3cad205bcd57e617baa1fd4784e523a339c25600b315a753b08` |
| `docs/coverage.md` | `ca3059317a0404b90346c18e1c48d8c6510fbe4af2317eb22ee469ac680b8596` |
| `docs/coverage-inventory.md` | `5480384671eae8b27b8ecdd91f2ba23af5d038c75209bebca5d37e0d3257d164` |
| `docs/swift-coverage-normalization.md` | `f61af7f4fbd236d8dceea439e62fe957102216d30aa9835597f26a729e59dc50` |
