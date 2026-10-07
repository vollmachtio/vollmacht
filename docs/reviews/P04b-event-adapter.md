# Exact probe event adapter review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the reviewed slice.

The adapter accepts only exact controller phase/result pairs and passes the original event run ID into the existing state's token check. Unknown, stale, duplicate and cancellation-not-applied labels cannot release the busy gate merely by carrying a terminal-looking phase. Completion summaries require bounded ASCII, exact field order/count, known outcomes, canonical Int32 status spelling/range and one of three exact timing labels. No prefix-only terminal acceptance or verified-lock claim is introduced.

Cross-product tests exercise known events against controller phases, owner stages and stale IDs. Additional controls cover malformed summaries, integer bounds, alternate integer spellings, extra/reordered fields, Unicode, cancellation rejection, duplicate completion and completion preceding the armed acknowledgement. Existing policy/controller code is unchanged.

This is a main-actor adapter for trusted in-process events, not authentication of event provenance. Future wiring must retain one shared app-lifetime state, deliver genuine observer events onto the main actor and avoid exposing this as an external command interface. Documentation leaves observer/UI integration and the separate native handoff open. No native backend construction or personal-project change is included.

## Independent verification

- Compiled and ran the adapter fake suite under Swift 6 complete concurrency checking with warnings treated as errors: passed.
- Seven collector, ten normalizer and seven runner controls passed. All prior suites and UI typechecking remain in the runner.
- Source inventory accepted 101 tracked sources, including fourteen measured Swift sources.
- Independently normalized the supplied v6 coverage artifact: adapter 37/37 lines and 4/4 functions; adapter tests 85/85 lines and 6/6 functions. All 12 native function records had zero executions.
- The supplied v5 baseline and v6 head retain exact line/function numerators and denominators for all twelve existing sources, with matching recorded compiler/LLVM versions and SDK. Existing flags are retained; the seventh suite explicitly uses Swift 6 strict concurrency.
- Inspected the explicit fourteen-source/seven-suite migration, old-policy rejection, new-suite failure controls, inventory and five documentation updates. The comparator remains unchanged.

Line/function coverage does not establish exhaustive branches or race behavior. Instrumented artifacts were supplied by the coordinator rather than independently rebuilt by this reviewer. Full workspace/UI checks, artifact authenticity and a complete regression gate are not claimed here. No native operations, signing changes or Git mutations were performed.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/macos-key/swift/ProbeEventAdapter.swift` | `ef25defd592b542d5a0e40611b93f4b96e06d4149cb303b7616a00261f157459` |
| `spikes/macos-key/swift/ProbeEventAdapterTests.swift` | `556d5d54ad0909105c58b51fc2824ebb271f7a952574e13c33c4b5465b1f7910` |
| `spikes/macos-key/swift/run.py` | `c63a585d48573f696912084178132755b7e7fd8222f396bce551ece574391cba` |
| `spikes/macos-key/swift/test_run.py` | `e40c5aeef9e657e621fbdc4e1e6027da37df8f8a246286ffc7e1943dfd506f4d` |
| `scripts/coverage_swift.py` | `312d80bb5daa376d09e7c6b1455fae80bc444c1ef72abed4efea792b15a65ccd` |
| `scripts/test_coverage_swift.py` | `2fc210258f7443bd12e8d92b17f0cc07264719a21467fe1a7bef312c48184b7d` |
| `scripts/normalize_swift_coverage.py` | `3012861a4059e2028551b0c9e283f82a8e5587b8fe8b2cb259dedefb8b870beb` |
| `scripts/test_normalize_swift_coverage.py` | `edfa69f3cd23f804d659377be7af2e61abde71fed7e7373e80bf7bd755f701b5` |
| `coverage/sources.json` | `de2c0de1ef8bbcf67c31faaf0b98319ac4f5fb258343856f6f4840ee8d91b3bd` |
| `docs/coverage.md` | `433551d0aed984d1f9dcf4fc0a702bbf30e69d7d23ae25a39524274c2ab7eb6c` |
| `docs/coverage-inventory.md` | `e31de7ada5d4a548a7deba2078cbe33481376c63e2e411383bac3644569d648d` |
| `docs/swift-coverage-normalization.md` | `0c4df08a4f3bb1aee918042a31ded275e87c514b4a753328e0c49942906255bb` |
| `spikes/macos-key/swift/README.md` | `82cc7955b334529ae9344221a4aaba50718b9c80338afa798cde314c94da544e` |
| `spikes/macos-key/swift/OPERATION-STATE.md` | `c25500b663007fcedda7b03bedf263c7138a418d55390de7d5f8364b9d234d1e` |
