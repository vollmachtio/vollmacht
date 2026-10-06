# Swift fake-suite coverage normalization

`scripts/normalize_swift_coverage.py` converts the existing merged LLVM JSON export into the strict `coverage_compare.py` format. It does not compile or launch anything, discover trust, modify coverage policy, or enable a complete CI regression gate.

Run it with the export, companion collector metadata and trusted absolute repository root, in that order. Normalized JSON goes to standard output. Each JSON input uses the comparator's bounded, duplicate-rejecting loader. Unsupported export versions fail; the initial accepted LLVM export version is `3.0.1` and collector metadata version is 1.

The fixed measured inventory is `Profile.swift`, `Runtime.swift`, `RuntimeTests.swift` and `Tests.swift`, all under `spikes/macos-key/swift/`. The adapter requires exactly one LLVM-merged data unit and exactly one entry for each expected path. Missing, duplicate, aliased, outside-root and unexpected sources fail. The root is supplied by the trusted caller, not discovered from the report. No source path is dereferenced; filenames identify collected coverage rather than authenticating source contents.

## Denominators and native gaps

The collector passes both fake-suite executables to LLVM's merged export. LLVM already combines `Profile.swift`, which is compiled into both. The adapter never adds independent executable summaries and rejects duplicate file entries instead of guessing how to combine them.

Only per-file `summary.lines` and `summary.functions` integer counts are used. Rounded percentages, regions, raw function entries and generic instantiations are not alternative denominators. The inspected local sample has 15 Runtime functions but 16 instantiations, illustrating why they must not be conflated. Zero-hit measured sources remain in the output. Branches are not reported: zero branch counters in this Swift export do not prove complete branch coverage.

Native backend function evidence must be present, attributed to `Runtime.swift` and have zero executions. These checks mirror the collector boundary; they do not authenticate an artifact or prove that an adversarially edited report contains every compiler-emitted function. Real native code remains in Runtime's measured denominator rather than being excluded to improve coverage.

`ProbeView.swift` remains explicitly unmeasured in companion metadata, with native Keychain and Touch ID manual gates. It is not fabricated as a zero-total measured file, since the comparator treats zero-total metrics as vacuously complete. The separate source inventory must continue classifying UI and manual gates explicitly; this adapter is not a repository-wide inventory validator. Existing UI typechecking is not runtime coverage.

## Identity and remaining gate work

The tool identity hashes exact Swift, llvm-cov and llvm-profdata version strings and records the Swift compiler's macOS target. It ignores installation paths, which legitimately vary between machines. Metadata declares these values; the adapter does not independently authenticate tool binaries or claim compatibility between arbitrary supplied versions.

Collector schema 1 stores the SDK path but not its version/build identity. The policy ID therefore includes `sdk-build-unverified`. Matching normalized identities are not sufficient to establish identical SDKs or fully comparable builds. Before enabling an authoritative cross-run gate, record and validate the SDK build and controlled collector/toolchain configuration, authenticate base/head inputs, and connect the reviewed source inventory. Do not treat this adapter alone as completion of that work.

Portable validation: `python3 scripts/test_normalize_swift_coverage.py`. Tests cover direct summary counts, zero hits and regressions, source attribution failures, native execution denial, malformed counts, tool identity, explicit UI limitations and bounded JSON loading. No compiler, Keychain or UI execution is required.
