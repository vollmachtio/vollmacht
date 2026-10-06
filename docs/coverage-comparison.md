# Normalized coverage comparison core

This is a tested comparison component, not a collector integration or required CI gate. It does not change the [coverage rollout status](coverage.md), authenticate reports or prove test quality.

Run `python3 scripts/coverage_compare.py BASE HEAD BASE_INVENTORY HEAD_INVENTORY`. Each inventory is a JSON array of unique repository-relative source paths, using canonical forward slashes and printable ASCII. The caller must obtain complete inventories from trusted policy and the exact source revisions, not from whichever files a collector happened to execute. Every listed source needs a report record, including zero-hit files. Extra or absent records fail.

Report shape:

```json
{
  "version": 1,
  "tool": {"name": "collector-and-adapter", "version": "exact-version", "platform": "exact-platform", "policy_id": "trusted-policy-identity"},
  "metrics": ["lines", "functions", "branches"],
  "files": {
    "src/example.rs": {
      "lines": {"covered": 8, "total": 10},
      "functions": {"covered": 2, "total": 3},
      "branches": {"covered": 4, "total": 8}
    }
  }
}
```

Only supported metrics actually measured may be listed. The list must be nonempty, unique and identical between reports; every source supplies exactly those metrics. Tool identity fields must match exactly, including configuration/exclusions identified by `policy_id`. These strings are assertions by the caller, not verified tool discovery. A future trusted adapter must derive them, and reject weakened measurement policy independently.

Unknown/missing fields, duplicate decoded JSON keys at any depth, invalid UTF-8, BOM, nonfinite JSON constants, boolean/float/string counts, negative integer tokens (including negative zero) and covered counts exceeding totals fail. Counts are integers through `2^63 - 1`; cross-products and sums use Python's exact integers. JSON inputs are limited to 8 MiB each. Empty inventories are representable but cannot stand in for a nonempty trusted source inventory.

For each metric, the comparator requires a nondecreasing ratio across the summed counts and independently for every retained path. It uses integer cross-multiplication, never rounded percentages. A metric with zero total items is vacuously complete: moving from no items to partially covered items is a regression. No threshold, grace or baseline reset exists.

New paths contribute to head totals but have no individual base ratio. Removed paths contribute to base totals but have no retained-file comparison. Both lists are emitted explicitly. A rename is an addition plus removal; identity is not inferred. Removing poorly covered code can improve ratios, and other improvements can offset an uncovered new file in the overall ratio. This core does not claim changed-line coverage or prevent such behavior. Trusted inventory/policy checks, review of removals/renames and a separate changed-code gate remain necessary before calling this complete regression enforcement.

The command emits JSON with `regressions`, `added` and `removed`. A regression or invalid input exits nonzero. The caller must supply exact trusted-base and proposed-merge reports, isolate untrusted execution, preserve all mandatory tests, and bind reports to revisions and tool provenance. This component supplies none of that orchestration. Run negative controls with `python3 scripts/test_coverage_compare.py`.
