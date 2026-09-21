# Development

Install Rust using [rustup](https://rustup.rs/) and Python 3.11 or newer. From the repository root, rustup selects Rust 1.98.1 and the rustfmt and Clippy components specified in rust-toolchain.toml. Homebrew Rust also works when its version matches the pin and those components are present. The check script rejects mismatched rustc or Cargo versions because Homebrew does not enforce rustup's toolchain file.

```sh
cargo build
python3 scripts/check.py
target/debug/vollmacht help
target/debug/vollmacht version
```

The current binary only prints help and version information. Unsupported arguments fail with status 2 without echoing input. It opens no listener, reads no credentials, and performs no GitHub operations.

## Workspace conventions

The separate [Apple key experiment](../spikes/macos-key/README.md) compiles on macOS and Linux. Its tests use software keys only. Hardware invocation is explicit and is never part of CI; default invocation prints help. It requests no permanent keys and does not alter the production CLI.

Start with the CLI crate. Add core, WebAuthn, policy, storage, and GitHub crates when they acquire real implementations. Do not add placeholder authorization APIs. Experiments belong under spikes/ and must be explicitly added to or excluded from the workspace when created.

All packages inherit workspace metadata and lints. Publishing is disabled during development. Unsafe Rust is forbidden in the current workspace. A future Apple FFI boundary requires an explicit design review of any change to that rule.

## Dependencies and CI

The CLI remains dependency-free. The [WebAuthn probe](../spikes/webauthn/README.md) adds test-only dependencies, including native OpenSSL; its README records prerequisites and limitations. Commit Cargo.lock, review lockfile changes, and run locked builds in CI. Before adding a dependency, review its maintenance, RustSec advisories, license, default features, build scripts, native code, and transitive graph. Prefer minimal features and crates.io releases; git sources require a pinned revision and justification. Dependabot opens Cargo and Actions update PRs; it does not replace advisory scanning or review.

Run `python3 scripts/dependencies.py install` once to install the pinned cargo-deny checker and check the locked dependency graph. Subsequently run `python3 scripts/dependencies.py`. These commands require network access to refresh advisory/index data. CI runs the same advisory, license, and source checks in its dependencies job. The normal check.py command covers compile/test/lint, not dependency advisories.

Rust 1.98.1 was checked against its upstream release on 2026-09-20. Check [Rust releases](https://github.com/rust-lang/rust/releases) and [security announcements](https://rust-lang.org/policies/security/) when updating the pin. The [checkout action](https://github.com/actions/checkout/releases/tag/v7.0.1) is pinned to the upstream commit resolved on the same date. Neither pin is a guarantee against undiscovered vulnerabilities.

CI uses read-only repository permission, disables persisted checkout credentials, and runs on pull requests and main pushes. It accepts no secrets and has no publish or merge step. Both macOS and Linux execute the same checks: toolchain validation, formatting, Clippy with warnings treated as errors, tests, and release build. No caches are shared across untrusted changes. macOS CI does not validate a physical authenticator; P03 requires a separate interactive test.

After successful CI runs, maintainers can configure branch protection to require both check jobs and review. This repository change does not itself configure branch protection.
