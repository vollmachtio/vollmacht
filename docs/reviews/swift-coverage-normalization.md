# Swift coverage normalization review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the five reviewed source files. This adapter is not an authoritative coverage gate.

## Scope and conclusions

The adapter uses the existing bounded, duplicate-rejecting loader and accepts the explicit LLVM/collector format versions. Exactly one merged unit and four unique, exact source paths are required. Aliased, unexpected, missing and duplicate paths fail. Paths are identifiers only and are not dereferenced. Companion metadata requires the stated tool/version fields, measured suites and manual/UI boundary entries.

Per-file line and function summary integers become normalized counts without rounding or substitution of regions, instantiations or percentages. Already merged source summaries are not added again. Zero-hit native code remains in the denominator; UI code is not represented as vacuously complete zero-total coverage. Native-backend function records must be present, attributed to Runtime and unexecuted.

These are trusted-collector structural checks, not report authentication, independent denominator reconstruction or proof that an edited report lists every native function. Exact version text contributes to identity, but SDK build identity and controlled configuration remain missing. Both the policy ID and documentation explicitly preserve that limitation. Source/revision trust, complete repository inventory and an authoritative cross-run regression gate remain separate work.

Workspace integration adds the test runner without removing tests. The source inventory adds both new Python files as unmeasured. No compiler invocation, runtime isolation or hardware behavior changes are included.

## Independent verification

- All seven committed portable adapter tests passed.
- Current staged source inventory passed with 83 sources.
- Normalized the coordinator's retained real Swift export and metadata successfully, without rerunning the collector or invoking native APIs.
- Independently compared every normalized line/function count against that sample's corresponding LLVM per-file summary: exact equality. Runtime retained 15 total functions, not the separate instantiation count.
- Additional reviewer controls rejected 45 malformed metadata, path-alias and native-execution cases. The native-execution mutation used a function record from the actual sample.
- No full-workspace rerun, Keychain operation, app launch, Git mutation or reviewed-source edit was performed by the reviewer.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `scripts/normalize_swift_coverage.py` | `08456ec93a890e10accf60099c0e5b69f1d742d6b73c459cc3a4d0f20801d1a4` |
| `scripts/test_normalize_swift_coverage.py` | `53c5289c9b44056dfc0c584a01a6214d107b14eaba0271de3df3bb4dd26c5c40` |
| `docs/swift-coverage-normalization.md` | `f6fbc1042ffca44e320a1522362b7e45e08cf8b4a27d7da3a3debaa7e6dfca8d` |
| `scripts/check.py` | `91be3127b24a0bb4fe8c641dba1beb67e78820ac8ba9f85f9b77d251509c694b` |
| `coverage/sources.json` | `2ed8777d6dff5f5569ebbae38fe811bf46988156e22c6badc6878df5778537da` |
