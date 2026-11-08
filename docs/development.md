# Development

Install Rust using [rustup](https://rustup.rs/), Python 3.11 or newer, and the Node.js version pinned in `spikes/simplewebauthn/.node-version`. From the repository root, rustup selects Rust 1.98.1 and the rustfmt and Clippy components specified in rust-toolchain.toml. Homebrew Rust also works when its version matches the pin and those components are present. The check script rejects mismatched rustc or Cargo versions because Homebrew does not enforce rustup's toolchain file.

```sh
cargo build
npm ci --prefix spikes/simplewebauthn
python3 scripts/check.py
target/debug/vollmacht help
target/debug/vollmacht version
```

The current binary only prints help and version information. Unsupported arguments fail with status 2 without echoing input. It opens no listener, reads no credentials, and performs no GitHub operations.

## Reviewable demo

After installing the prerequisites above, run `python3 scripts/demo.py` from the repository root. It runs the existing fresh integration and prints a concise walkthrough only if the test succeeds and every expected stage is present in order. The command does not install or change runtimes, uses no native key or GitHub credential, and sends no GitHub request. Cargo may fetch and build locked dependencies. Disposable test storage is removed on normal completion; interruption can leave temporary test files.

The walkthrough deliberately uses synthetic approval. It ends at a verified merge candidate, not a reservation or dispatched action. Review the sequence and terminology now; native approval, live execution and polished UI follow as separate increments. On failure, run the fresh-flow test below for diagnostics. The command selects the pinned Node already on PATH and times out after five minutes, terminating its owned process group. Both command regression tests and the actual walkthrough run in the standard check script.

Proposal details come directly from the immutable Rust approval payload used for the synthetic assertion, not separate Python constants. The trace checks that its fingerprint matches the assertion's signed challenge. Before printing, the diagnostic runner requires one bounded, unambiguous record, validates the restricted ASCII/integer shape, and recomputes that profile's fingerprint. This display check is not an authorization verifier or a general JCS implementation. Public references and test-clock timestamps are labeled synthetic; raw evidence and key bytes are never displayed. Output appears after the test succeeds, so it must not be treated as an interactive approval ceremony.

## Integrated simulated merge

After the prerequisites above, run this targeted integration test from the repository root:

```sh
VOLLMACHT_TEST_NODE="$(command -v node)" cargo test -p vollmacht-helper-launcher --test simulated_merge --locked -- --nocapture
```

This test connects the core issuer/agent signature checks and original-byte client-data gate to the actual Node WebAuthn verifier through the Rust helper coordinator and launcher. Trusted setup uses fixed signed fixtures and a fixed test clock. Successful verification reaches only an in-memory merge recorder; the test also checks rejection paths and reuse. Missing runtime or helper prerequisites fail rather than skip. The full check script supplies the Node path automatically.

This is an integration checkpoint, not the live MVP: it does not create a real approval ceremony, issue a new mandate, enroll a user, persist replay state or call GitHub. It uses no native keys or GitHub credentials. Durable enforcement and deployment qualification remain required before live execution.

The core execution verifier uses a captured trusted context and a coordinator-selected evidence adapter. Its candidate result is not authorization to dispatch. The simulation claims each matching attempt before verification and performs fake final state checks separately. Production callers will need authenticated storage, durable consumption/reservation and fresh state/time checks; implementing the evidence adapter incorrectly can bypass WebAuthn verification. No agent-supplied context or adapter is trusted by this design.

### Fresh synthetic approval and issuance

The fresh-flow test generates ephemeral issuer, agent and synthetic authenticator keys rather than loading pre-signed artifacts:

```sh
VOLLMACHT_TEST_NODE="$(command -v node)" cargo test -p vollmacht-helper-launcher --test fresh_simulated_merge --locked -- --nocapture
```

It creates a new proposal and mandate challenge, obtains a synthetic assertion, verifies the evidence with the actual helper, signs new mandate/proof bytes through the prepared-input guards, and exercises core verification before recording a verified candidate. Software signing is confined to this test executable. The original fixed-vector integration remains as an independent regression oracle.

Execution attempts use disposable SQLite storage: a matching claim commits before verification, captured bindings are compared with the trusted context, and failed verification appends a rejection. Successful verification leaves the attempt claimed and records only a candidate, not a reservation or completed merge. Same-session reopen checks cannot recover a receipt or reuse the challenge.

Before recording, the fresh flow also compares exact repository identity/label, PR number, head and base against a fixture metadata provider, and checks method restrictions and policy revision. The clock is sampled after metadata retrieval so provider delay cannot bypass proof expiry or the original deadlines. Resource/policy comparison failure appends a rejection while the claim receipt is still held. This is partial resource comparison, not complete live preflight: current API eligibility, disposable-fixture qualification, full policy evaluation, remote races and final atomic status/revision checks remain separate. No GitHub metadata is fetched by this demo.

Synthetic user-verification flags do not demonstrate human approval or Touch ID. This test does not enroll a real credential, qualify a native issuer, provision production authority or contact GitHub. It is a fresh simulated flow, not the user-facing MVP; real approval/issuance, final reservation and deployment-qualified persistence remain required.

## Durable attempt ledger

`vollmacht-state` supplies the first transactional coordinator-state slice: open an existing, exactly matched database, claim one matching pending challenge, append a rejection, and inspect an operation without recovering authority. Run its portable tests with `cargo test -p vollmacht-state`. Tests provision disposable databases directly; the library exposes no provisioning or import shortcut.

A successful claim returns a non-cloneable receipt and captured bindings, not a verified mandate or dispatch permit. Concurrent matching claims have one winner. State, operation records, audit records and the wall-clock high-water mark commit together. An ambiguous write poisons that writer; read-only lookup cannot reconstruct a receipt. Rejected attempts retain their history while allowing a fresh challenge for the same still-approved mandate.

The fresh simulated flow integrates this crate through explicit test provisioning. It does not implement reservation, dispatch, enrollment/disable, bootstrap authentication, executor leasing or startup invalidation. Its caller must supply authenticated bindings and trusted time/deadlines. File checks and SQLite settings do not qualify filesystem isolation, rollback resistance or power-loss durability. Reopening test state demonstrates persistence, not a qualified process-restart protocol. These remain required before live execution.

## Workspace conventions

The separate [Apple key experiment](../spikes/macos-key/README.md) compiles on macOS and Linux. Its tests use software keys only. Hardware invocation is explicit and is never part of CI; default invocation prints help. It requests no permanent keys and does not alter the production CLI.

Start with the CLI crate. Add core, WebAuthn, policy, storage, and GitHub crates when they acquire real implementations. Do not add placeholder authorization APIs. Experiments belong under spikes/ and must be explicitly added to or excluded from the workspace when created.

All packages inherit workspace metadata and lints. Publishing is disabled during development. Unsafe Rust is forbidden in the current workspace. A future Apple FFI boundary requires an explicit design review of any change to that rule.

## Dependencies and CI

The CLI remains dependency-free. The separate [WebAuthn probe](../spikes/webauthn/README.md) has an experimental localhost server and native OpenSSL dependencies; its README records prerequisites and limitations. Synthetic authenticator code remains development-only. Commit Cargo.lock, review lockfile changes, and run locked builds in CI. Before adding a dependency, review its maintenance, RustSec advisories, license, default features, build scripts, native code, and transitive graph. Prefer minimal features and crates.io releases; git sources require a pinned revision and justification. Dependabot opens Cargo and Actions update PRs; it does not replace advisory scanning or review.

Run `python3 scripts/dependencies.py install` once to install the pinned cargo-deny checker and check the locked dependency graph. Subsequently run `python3 scripts/dependencies.py`. These commands require network access to refresh advisory/index data. CI runs the same advisory, license, and source checks in its dependencies job. The normal check.py command covers compile/test/lint, not dependency advisories.

Rust 1.98.1 was checked against its upstream release on 2026-09-20. Check [Rust releases](https://github.com/rust-lang/rust/releases) and [security announcements](https://rust-lang.org/policies/security/) when updating the pin. The [checkout action](https://github.com/actions/checkout/releases/tag/v7.0.1) is pinned to the upstream commit resolved on the same date. Neither pin is a guarantee against undiscovered vulnerabilities.

CI uses read-only repository permission, disables persisted checkout credentials, and runs on pull requests and main pushes. It accepts no secrets and has no publish or merge step. Both macOS and Linux execute the same checks: toolchain validation, formatting, Clippy with warnings treated as errors, tests, and release build. No caches are shared across untrusted changes. macOS CI does not validate a physical authenticator; P03 requires a separate interactive test.

After successful CI runs, maintainers can configure branch protection to require both check jobs and review. This repository change does not itself configure branch protection.
