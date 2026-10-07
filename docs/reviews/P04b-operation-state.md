# Shared probe operation policy review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no remaining blocking findings. This slice models an app-lifetime ownership gate; it does not yet connect that gate to windows, controller events or native operations.

## Finding and resolution

The initial generic cancellation-failure acknowledgement released the gate without distinguishing terminal failure from a cancellation that was not applied. The final model separates `cancellationTerminalFailure`, explicitly reserved for the controller's terminal `failed/session_cancel_failed` result, from `cancellationNotApplied`. The latter cannot change state or release pending work. Regression tests require both legacy actions to remain blocked until a genuine terminal event.

The main-actor reference owner excludes overlapping legacy and diagnostic work. Tokens reject stale acknowledgements, failed preparation consumes the sole diagnostic allocation, and a completion arriving before the armed notification wins without reopening the gate. Terminal diagnostic completion permits later legacy work but never a second diagnostic on the same instance. Checked token allocation fails rather than wrapping.

These properties require a future app to share exactly one owner across windows and map exact trusted controller results, not merely phase names. The model cannot establish quiescence from arbitrary caller assertions or interrupt synchronous native work. Documentation explicitly leaves the event adapter, app-lifetime integration and manual handoff open. No existing view, native backend, key identifier, signing setting or personal Xcode project is changed.

## Independent verification

- Compiled the two new Swift files with Swift 6, complete concurrency checking and warnings treated as errors; the standalone fake suite passed.
- Seven collector tests, ten normalizer tests and seven runner controls passed.
- Source inventory accepted 98 tracked sources, including twelve measured Swift sources.
- Independently normalized the supplied v5 collector report. Both new files were measured: state 59/59 lines and 11/11 functions; tests 101/101 lines and 9/9 functions. All 12 native function records had zero executions.
- Compared raw counts with the supplied v4 report: all ten retained files had identical line/function numerators and denominators. Recorded compiler/LLVM versions and SDK matched. Existing suite flags remain unchanged; the new sixth suite has explicit Swift 6 concurrency flags.
- Inspected exact six-suite/twelve-file collection, old-policy rejection, timeout failure controls, inventory additions and documentation. The comparator is unchanged; policy v5 does not pretend to be comparable to v4.

The measured line/function totals do not establish complete branch coverage, exhaustive race testing or a production coverage gate. The reviewer inspected supplied instrumented artifacts rather than regenerating both builds, and did not independently rerun the full workspace/UI checks. No native operation or Git mutation was performed.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/ProbeOperationState.swift` | `d3faabe77828dc336562ebebd402add1231773d518508355ff1394e8fa1c86f6` |
| `spikes/macos-key/swift/ProbeOperationStateTests.swift` | `6c64deb15d6df84af839beaba8924ba634a3396c0aa91eabc62b6792742ddd01` |
| `spikes/macos-key/swift/OPERATION-STATE.md` | `598f2c85666e476557b6fc6b101bf498e7c43cfa37d184cdaac95b0d429e85f6` |
| `spikes/macos-key/swift/README.md` | `8e04fa2a9f0d65c7e49ec20ce90644ee0ebfdab67eceae05c101a3c8fe66fc2e` |
| `spikes/macos-key/swift/run.py` | `332297e93a7fc5dca2bda369876311579c244a385059f9ea542ce97da015e190` |
| `spikes/macos-key/swift/test_run.py` | `819ed5cad7475d76c0fd398e5ecf194fd8cd92de33ec1318c63cfab1bce58d17` |
| `scripts/coverage_swift.py` | `adfdfc5a618182d4e6272b0b56d2ac46a699832e0253227d632dde86797526af` |
| `scripts/test_coverage_swift.py` | `453788acf98cd0d6b08d1b05f0ac5c17b6cdc1d65317af463b843e48b1669907` |
| `scripts/normalize_swift_coverage.py` | `6eb8102d9a10888657e295761da91d3deb7b165e439773166ec9ef40ad4c6c24` |
| `scripts/test_normalize_swift_coverage.py` | `7c40ca146076821ea989a028cfeb488511eb4372c8cca900272657ad2a8a5e3d` |
| `coverage/sources.json` | `1f96480d0f4c65e9f9e536950411b2a15831248991c292088c5677bdaa9c5998` |
| `docs/coverage.md` | `27497faf9fbbc26b544155ac86b8ff519c5a750780d1d3bbfa7ae35c9934a17b` |
| `docs/coverage-inventory.md` | `5af753cd55f8eae9cd8cd14f90942fb6b8827f00201e35ade5da560026bc3bed` |
| `docs/swift-coverage-normalization.md` | `0dbc250a69ff43c600f7c5634f13caf11d49491ab1824680da56ea5635e16f1b` |
