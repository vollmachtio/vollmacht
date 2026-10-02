# P03f.1 developer setup and packaging baseline

Experimental developer tooling, not a distributable application. This step measures the existing external-Node helper before choosing a runtime or bundle. It does not install software, change credentials, invoke Touch ID or contact GitHub. P03f is not complete: LTS validation and distribution design remain separate reviewable tasks.

Reproducible here means a pinned, repeatable setup and test procedure, not byte-identical binaries across hosts or rebuilds.

## Reproduce from a fresh checkout

Use a trusted checkout and toolchain. Requirements: Python 3.11+, the Rust version in `rust-toolchain.toml`, Node 26.5.1 from `.node-version`, npm, and the native build prerequisites in [development](../../docs/development.md). On macOS the build needs the developer tools/SDK and usable OpenSSL development libraries; the hosted macOS runner already provides its native build environment. These instructions assume dependencies/tools were obtained through a trusted installation process; the preflight does not establish their provenance.

Run from the repository root:

```sh
cd spikes/simplewebauthn
npm ci
npm audit
npm test
cd ../..
cargo build -p vollmacht-helper-launcher --bin vollmacht-helper-launcher --example real-helper --release --locked
python3 spikes/helper-protocol/dev.py doctor "$(command -v node)" \
  "$PWD/target/release/vollmacht-helper-launcher" \
  "$PWD/target/release/examples/real-helper"
python3 spikes/helper-protocol/dev.py measure "$(command -v node)" \
  "$PWD/target/release/vollmacht-helper-launcher" \
  "$PWD/target/release/examples/real-helper"
VOLLMACHT_TEST_DRIVER="$PWD/target/release/examples/real-helper" \
VOLLMACHT_TEST_LAUNCHER="$PWD/target/release/vollmacht-helper-launcher" \
npm --prefix spikes/simplewebauthn run test:helper-e2e
python3 scripts/check.py
```

`npm ci` replaces this experiment's `node_modules` using the lock; do not keep manual edits there. The checked-in `.npmrc` disables lifecycle scripts. The assessment itself never runs npm or fetches anything. `command -v` above selects your trusted development runtime once; you can instead supply its absolute path explicitly. The assessment executes that exact resolved file with an empty environment and no shell. Do not supply agent-controlled executable paths or run as root. CI repeats install, release build, synthetic regressions and measurement on fresh macOS/Linux checkouts; that is not evidence of a pristine user Mac with no prior toolchain installation.

`doctor` checks the exact runtime pin, installed dependency names/versions against the lock, existing lock metadata policy, required helper files and helper import. It only checks launcher/driver executability and records their hashes: a wrong executable or architecture can pass that part of preflight. `measure` actually exercises the complete synthetic path and requires every sample to verify with a consumed coordinator. Neither command checks installed dependency file contents against npm tarballs. Reinstall from the lock to remove stale changes; hashes are observations, not authenticated provenance.

The JSON report includes runtime/host metadata, artifact sizes/hashes, a lock digest, and all 25 locked npm package entries with versions, licenses and tarball integrity metadata. Two versions of `tslib` count as distinct installed entries. This is an inventory, not an SPDX/CycloneDX SBOM or a vulnerability scan. Cargo inventory/advisories remain covered by the existing dependency CI job.

## Errors and recovery

| Error | Action |
| :--- | :--- |
| `node_absolute_path_required` | Supply the absolute path of your trusted Node installation. |
| `node_missing_or_not_executable` | Install/select the pinned runtime; no automatic download or PATH fallback occurs. |
| `node_version_mismatch_use_repository_pin` | Use the version in `.node-version`; do not edit the pin merely to silence this check. |
| `launcher_missing_or_not_executable`, `driver_missing_or_not_executable` | Run the release build command and check the supplied paths. |
| `helper_files_missing` | Restore a complete trusted checkout. |
| `dependencies_missing_run_npm_ci`, `dependency_version_mismatch_run_npm_ci` | Run `npm ci` in `spikes/simplewebauthn`, then rerun audit/tests. |
| `tool_failed`, `tool_launch_failed`, `tool_timeout`, `tool_output_limit` | A local tool failed; check runtime/build/dependency setup. No partial measurement counts as success. |
| `tool_cleanup_failed` | Group cleanup or its confirmation failed. Stop the assessment and inspect the local process environment. Do not bypass with elevated runtime privileges. |

Process output has a 64 KiB per-stream cap; preflight subprocesses have a five-second deadline, measurement has a sixty-second deadline, and direct-child reaping has a one-second budget. The measurement's existing Rust supervisor retains its own shorter verification limits. On failure the developer tool signals its process group before reaping the leader, preserving its identifier until cleanup. This is not a sandbox: a malicious descendant can escape its group or change privileges.

On macOS, `killpg` can return `EPERM` for a group containing only zombies. The tool keeps the leader unreaped, then uses a capped one-second `/bin/ps` group-state census to distinguish that case from a live-process denial. Missing/denied/truncated inspection fails closed. A restricted execution environment may need permission to inspect the process table. This mechanism is developer tooling, not a change to the production-bound Rust supervisor. See Apple's [XNU signal implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c), `killpg1`.

## Local observation, 2026-10-01

Apple Silicon, Darwin 25.6.0, Node 26.5.1 (Homebrew), Rust/Cargo 1.98.1; release build. This host-reported kernel version is not the earlier user-reported browser/OS matrix. Lock SHA-256: `d8bce676832f62e3912bde3a94cf663cb7280f9ac96502beeaaf375c9ddc7101`.

| Measurement | Observation |
| :--- | :--- |
| First process round trip | 548.929 ms |
| Next 20 fresh-process round trips | median 90.564 ms; nearest-rank p95 94.138 ms; range 89.271–95.560 ms |
| Release launcher file | 433,040 bytes |
| Release test driver file | 1,177,616 bytes; not a shipping component |
| Installed npm regular-file content | 3,206,857 bytes across 25 package entries; symlinks excluded |
| Homebrew Node executable | 50,320 bytes, emphatically not the complete runtime |
| Homebrew `libnode.147.dylib` | 75,091,664 bytes, with further shared-library dependencies |

Timing includes Rust-driver startup, software-key/assertion generation, launcher, Node startup/import, real verification and cleanup. It excludes startup/import of the Node measurement controller, preflight and compilation. Each sample uses a fresh process and new credential, but filesystem caches are uncontrolled. First-process timing is not a cold-start guarantee; these 21 samples are a baseline, not a performance SLA. No hardware approval latency or peak memory measurement is claimed. There is no CI timing threshold.

Logical file bytes differ from allocated disk blocks: the earlier roughly 6.9 MiB directory observation is not comparable to this regular-file sum. `otool -L` showed the Homebrew Node executable depends on `libnode` plus OpenSSL, ICU and other libraries. The JSON artifact hashes cover the named files only, not their dynamic dependency closure. Adding these table rows does not produce a valid signed-bundle size. Distribution size, architecture coverage and memory remain unmeasured.

## Runtime and release decisions still required

Primary sources checked on 2026-10-01:

- [Node release policy](https://nodejs.org/en/about/previous-releases) lists Node 26 as Current and recommends LTS for production. Our 26.5.1 experiment pin is not a production recommendation.
- [Node downloads](https://nodejs.org/en/download) currently lists 24.21.0 LTS and 26.10.0 Current; the pinned experiment is not the latest release. [24.21.0 release notes](https://nodejs.org/en/blog/release/v24.21.0) date that LTS release to 2026-09-08. Recheck before selecting the candidate.
- [Node security releases](https://nodejs.org/en/blog/vulnerability) is separate from npm audit. A passing npm audit does not certify the Node binary or OpenSSL build. No claim is made that the retained baseline pin is free of known runtime vulnerabilities.
- [SimpleWebAuthn runtime requirements](https://simplewebauthn.dev/docs/packages/server) document Node 22+. That floor does not establish that every supported-major patch has passed Vollmacht's integration tests.

Next, P03f.2 should obtain a verified upstream LTS runtime in an isolated location, run the full macOS/Linux helper and browser/session synthetic matrix, repeat these measurements, record native dependency/architecture differences, and propose a separately reviewed pin change. Never silently fall back to a different runtime after verification failure. Keep historic physical-browser evidence labeled with its original runtime; rerun hardware tests if the chosen change affects the ceremony.

Before any user distribution, explicitly decide external versus bundled Node, verify the full artifact/dependency closure, produce license notices/SBOM, establish trusted install/update ownership, and assess Apple signing/notarization and required entitlements. Test missing/corrupt runtime, interrupted updates, downgrade/rollback and untrusted replacement. An absolute path or fresh local hash alone is not an integrity policy. These are release gates, not completed work in P03f.1.
