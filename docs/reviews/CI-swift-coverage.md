# Swift coverage collection review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the five reviewed files, compared with parent `7d4f7fb`. This review covers collection only, not a coverage-regression gate.

## Scope and conclusions

The collector builds and executes only the existing `Tests.swift` and `RuntimeTests.swift` entry points. Their backends remain fake; native Keychain lookup, creation, update, signing and UI entry points are not invoked. In-memory access-control object construction in the profile tests is not a Keychain operation. The original noninstrumented suites and UI typecheck remain in CI unchanged.

Fresh destinations prevent stale report reuse. Compile, test, profile merge, JSON parse and validation failures propagate. Expected source paths must be present, and represented native-backend function records must all have zero counts. Both instrumented executables contribute profiles and objects to the export. This is a trusted-tool sanity check, not validation of an adversarial coverage report or proof that every possible future native function is inventoried.

Temporary builds are context-managed. Subprocess deadlines bound direct children; compiler-descendant containment relies on the CI job deadline, as the code explicitly states. JSON output retains fake-test source and unexecuted native code. Documentation correctly identifies UI/hardware gaps, warns about local paths in reports, and makes no percentage, nonregression or full-coverage claim.

CI retains read-only repository permissions and disabled persisted checkout credentials. Only the macOS job collects and uploads JSON from the dedicated report directory, with a 14-day retention and missing-files failure. The pinned upload action SHA matches the official [v7.0.1 release](https://github.com/actions/upload-artifact/releases/tag/v7.0.1) and its linked [commit](https://github.com/actions/upload-artifact/commit/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a). This verifies pin identity, not an exhaustive upstream action audit.

## Independent verification

- All six portable collector unit tests passed, including error propagation, platform/destination rejection, report validation and temporary-build cleanup controls.
- Independently ran the collector on macOS using a fresh temporary destination. Both fake suites completed and report validation passed.
- Export contained four source files and 12 native-backend function records, all with zero execution counts.
- No native adapter, app launch, Keychain mutation, entitlement change or hardware prompt was performed.
- Reviewed final workspace and workflow changes statically; the full workspace suite and hosted artifact upload were not rerun by this reviewer.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `scripts/coverage_swift.py` | `d0e323e463984d7bcb2dff5ec5ee781f404acebf452da60694a2694e69dae8c6` |
| `scripts/test_coverage_swift.py` | `4d82d363b8741c16ed23ca09ecb84adc524aa95041ec75ae6b27eb4f0b90adfb` |
| `scripts/check.py` | `343b732f1de9d5e1933a489d02cc83860d295eb3a4710fd1fde04555a352668c` |
| `.github/workflows/ci.yml` | `2cf9b4fe505099ac29238a0c60553c190117cd04f04706fcbe2fe0b3e73f9063` |
| `docs/coverage.md` | `ee404813edc648da20d3f7da371a0b26014fa9d6d05e9f721b11bf536b9a2134` |
