# Base64 0.23.1 dependency assessment

Reviewed 2026-10-05 against `origin/main`, on the updated PR 35 checkout with both direct dependency declarations restricting features. Status: the original feature-selection concern is resolved in the reviewed files; complete updated CI and dependency audit remain merge gates.

## Reviewed artifact

SHA-256 values computed from the actual reviewed working-tree bytes:

- `spikes/helper-launcher/Cargo.toml`: `e25257a729534be18a844dc7702345b3f61dd8e0753dad9b111f275f7df2757e`
- `spikes/helper-protocol/Cargo.toml`: `1de5603116f0cd52449ec12a65f725aadae3743c9daed4dbb502132a97981a49`
- `Cargo.lock`: `474f73a9029d6dd0149b9bab1427bdf5db074eebff8854e00065de416d2ae3b8`

The lockfile adds base64 0.23.1 for these two consumers and retains 0.21.7 for the existing WebAuthn dependencies. Unrelated versions and checksums are unchanged. Standalone JOSE and canonicalization workspaces are outside this dependency update.

## Findings

The original Dependabot manifests would have enabled the newly default `simd-unsafe` feature. Both reviewed declarations now specify `default-features = false` and `features = ["std"]`. An independent local `cargo tree -e features -i base64@0.23.1` check reported only `std` and `alloc`, including the launcher dev-dependency edge. No consumer re-enabled SIMD in this resolved workspace graph.

The [pinned upstream manifest](https://raw.githubusercontent.com/marshallpierce/rust-base64/v0.23.1/Cargo.toml) enables SIMD by default; its nearby comment saying otherwise is stale. The [pinned crate source](https://raw.githubusercontent.com/marshallpierce/rust-base64/v0.23.1/src/lib.rs) confirms unsafe code is forbidden when that feature is disabled. The downloaded local 0.23.1 source has the same feature guard. This does not establish that the entire dependency graph is free of unsafe code.

The [upstream release notes](https://github.com/marshallpierce/rust-base64/blob/master/RELEASE-NOTES.md) describe changed decode-error details, slice-buffer handling, SIMD engines and an MSRV of 1.71.0. Our Rust pin is 1.98.1. A source search found no downstream use of the changed decode error variants, `internal_decode` or `decode_slice`. The runtime request decoder uses scalar `URL_SAFE_NO_PAD.decode`, maps errors to the fixed protocol error, checks decoded length, then demands exact canonical re-encoding. No direct API incompatibility was identified; this remains subject to compilation and execution.

`binary_fields_enforce_canonical_encoding_and_each_boundary` exercises minimum, maximum and out-of-range lengths for all binary fields. It rejects padding, invalid length, nonzero trailing bits (`AB`), standard-alphabet symbols, whitespace and non-ASCII input. These tests are meaningful regression controls for the upgrade, but are not exhaustive differential testing or fuzzing of the dependency.

No additional blocking source finding was identified after the feature fix. This is not a claim that upstream code has no vulnerabilities.

## Validation and limits

The independent reviewer inspected the full dependency delta, downstream call sites, malformed/canonical regression tests, downloaded feature guards and resolved feature graph. To avoid contention with the coordinator's running workspace checks, the reviewer did not start another Cargo build or test run. The coordinator's in-progress suite is not recorded here as a completed success.

Before merge, require all current mandatory checks on the final revision, including Ubuntu and macOS Rust formatting, Clippy, tests and release builds; npm tests; real-helper E2E; client-data gate; existing Swift checks and coverage collection; and fresh root-policy dependency auditing of the exact lockfile. Confirm feature resolution still excludes `simd-unsafe` after any subsequent edits. Do not skip failing tests or weaken canonical input rejection to accommodate this upgrade.

Only this review document was edited by the independent reviewer. No dependency installation, source modification, hardware access or Git mutation was performed.
