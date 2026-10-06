# Swift coverage build-identity review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the five reviewed files. Recorded build identity is improved; this does not create an authoritative regression gate or hermetic build.

## Scope and conclusions

Collector schema 2 records the explicitly selected macOS SDK name, version and build alongside its provenance path. All xcrun discovery queries select `macosx`; failed or missing identity queries abort before compilation. The supported macOS target is extracted once from compiler version output and passed explicitly to both compile commands.

Ordered compile flags, target and suite input lists come from the recorded configuration. The reviewed merge and export invocations match their recorded sparse/single-merged modes. Installation paths remain provenance rather than identity. Exact tool version strings, SDK identity and configuration contribute to the normalized digest; old schemas and unsupported configurations fail rather than being guessed or silently upgraded.

The environment remains inherited and is labeled accordingly. Environment contents, binary/SDK authentication, source revision provenance and a trusted same-run expected identity are not established. Documentation preserves these limits. The fixed measured source set, native-zero check, per-file line/function denominators and UI/manual gaps are unchanged. No native operation, extra measured suite, coverage exclusion or new production behavior is introduced.

## Independent verification

- All six collector controls and eight normalizer controls passed.
- Thirteen additional reviewer controls rejected altered environment policy, reordered flags/suites, extra configuration fields, unsupported identifiers/targets, duplicate target lines and otherwise valid reports with changed tool identities.
- Identity-only changes preserved fixture coverage counts while preventing comparison, as intended.
- Inspected command construction and independent literal flag assertions, selected-SDK query controls, failed-query precompile checks and source-list matching.
- Git whitespace validation passed.
- This pass did not rerun the compiler/collector, full workspace, hosted CI or any native/hardware operation. Fresh real schema-2 collection remains part of coordinator and exact-head CI validation.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `scripts/coverage_swift.py` | `1e7467afd67312c64c67f87ed9ef2f344830b120bdf6dba00e97dbf950f795b2` |
| `scripts/test_coverage_swift.py` | `71e5efc3ffd36e2ef28ba1eb95b245bc82cf77e8e563a0327652e72276f03b99` |
| `scripts/normalize_swift_coverage.py` | `15adb16a6b5f0f74d0527a49660c3887fb79fe7db0d49ec62ef6117ea5103d69` |
| `scripts/test_normalize_swift_coverage.py` | `065eae625696684851b74e6f2a528ea7fa57ff7f61f3fdaaba617279e06a1151` |
| `docs/swift-coverage-normalization.md` | `7983c82cb78b9a54fad20d69c07c00af5dece6b3685f372e59d916b02a4f4123` |
