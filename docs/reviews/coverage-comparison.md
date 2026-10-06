# Normalized coverage comparator review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the four reviewed source files. This is a comparison component, not an active coverage-regression gate.

## Scope and conclusions

The loader bounds each input, requires UTF-8 without BOM, rejects decoded duplicate keys and nonfinite constants, and rejects negative integer tokens including negative zero. Schema validation rejects extra/missing fields and noninteger counts without coercion. Source records must exactly match the separately supplied canonical inventory. Exact tool identities and metric sets must match before comparison.

Overall sums and retained-file ratios use exact Python integer arithmetic. Each supported metric is independently checked. Zero-total semantics, additions, removals and path-based rename handling match the documentation. A retained-file loss cannot be hidden by improvement elsewhere.

The supplied inventories, tool identities and reports remain trusted caller inputs. This component cannot prove source completeness, counter authenticity, unchanged exclusions or exact revision identity. Removing poorly covered paths, reducing measurable totals, or offsetting new uncovered code can improve ratios; the documentation explicitly leaves removal review, trusted policy enforcement and changed-code checks to later integration. No full-coverage, security or effective CI regression-gate claim is made.

The workspace change adds the comparator test runner without replacing existing suites. No collector, runtime boundary, permission or artifact change is included.

## Independent verification

- All 16 committed comparator tests passed, including CLI status/output, malformed JSON, source inventory, metric identity, zero totals and retained-file regression controls.
- Additional reviewer diagnostics rejected 72 malformed schema/tool/count variants, including nonfinite and oversized counts.
- Compared 2,000 seeded large-integer ratio cases with the independent standard-library `Fraction` oracle; all matched.
- Confirmed metric-list order is immaterial and a rename emits explicit addition/removal without inventing retained identity.
- Git whitespace validation passed. The documentation's relative coverage-rollout link resolves.
- No full workspace rerun, hosted CI, hardware operation or runtime implementation change was performed by the reviewer.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `scripts/coverage_compare.py` | `b676cffceabaa7acf883c6962e183b2a29c9cf66dae03a2835a29e5b841c52a1` |
| `scripts/test_coverage_compare.py` | `c90986234d9839fc3f9cfb2e896b261ea745e6842f412da49ed2242031f46b52` |
| `docs/coverage-comparison.md` | `d3db201ca7498196ef4db116771a1feb8bb27f530b8fa7b57b5b2cbaf827c388` |
| `scripts/check.py` | `afbab4622071533dba7841e736c7d9323f55d4f0514111b29e62fdb5e4b9de49` |
