# Explicit source accounting

`coverage/sources.json` accounts for every Git-tracked `.rs`, `.py`, `.js`, `.mjs`, `.cjs` and `.swift` path. Run `python3 scripts/coverage_inventory.py` from any directory. It queries the repository containing the script with NUL-delimited `git ls-files`; untracked files are not evidence of committed scope. Newly added source files must be staged before the final local check, and explicitly classified in the same reviewed change. The validator never stages or generates anything.

Each record has exactly `path`, `role` and `measurement`. Paths are unique canonical printable-ASCII repository-relative paths. Top-level fields are exactly `version: 1` and `sources`. Duplicate JSON members, duplicate paths, malformed records, unsupported roles/statuses, missing tracked sources and stale/untracked inventory paths fail. Additions, removals and renames therefore require an inventory change and review. The bounded strict JSON loader is shared with the comparison core.

Roles describe purpose, not exclusion from a coverage denominator:

| Role | Meaning |
| :--- | :--- |
| `cli_scaffold` | Current non-production CLI skeleton |
| `experiment` | Executable feasibility or assessment implementation, including browser UI |
| `test` | Test assertions and suite orchestration |
| `test_support` | Synthetic fixture/helper implementation or shared test driver |
| `developer_tool` | Build, dependency, measurement or developer workflow tool |
| `fixture_generator` | Generator of synthetic reviewed artifacts |
| `assessment_model` | Executable proposed-rule model embedded in tests |
| `documentation_only` | Present source file contains documentation without executable items |

There is no blanket test-directory exclusion. In particular, `tests/support/client_data.rs` is an assessed validator used by the standalone driver. Classifying it as support does not make its behavior irrelevant. Documentation-only files remain listed; this label does not fabricate a zero denominator. Classification changes require review just like additions.

Measurement status describes available collection, not successful behavior or thresholds. `unmeasured` means no current coverage measurement, even when tests execute the file. `attribution_only` identifies the shipped browser script whose VM attribution is checked, without complete coverage collection. `raw_swift_fake_tests` identifies the twelve Swift files compiled into the six instrumented fake-test binaries (profiles, runtime, diagnostic plan, diagnostic session, delayed controller and probe operation state). Native backend methods remain unexecuted; `ProbeView.swift` remains unmeasured. No status means excluded, fully covered or production-ready.

The validator only checks structural inventory completeness against the Git index. It does not verify role/status truth, inspect report counts, compare trusted revisions, authenticate policy, or prove complete coverage. Unsupported source extensions, generated untracked code and dependencies need separate policy assessment if introduced. The committed manifest is editable data, not an immutable trust root. A future trusted orchestrator must review policy changes and derive appropriate measured inventories without hiding untested files. See [coverage rollout](coverage.md) and [comparison limitations](coverage-comparison.md).

Run portable negative controls with `python3 scripts/test_coverage_inventory.py`.
