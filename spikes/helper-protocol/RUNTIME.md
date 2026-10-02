# P03f.2 LTS runtime assessment

Decision: pin the developer experiment to Node 24.21.0 LTS, replacing the 26.5.1 Current baseline. Keep an explicit external runtime for development. Do not select a production bundle or claim distribution integrity from this experiment. No verifier, browser ceremony, npm dependency or mandate format changes are included.

## Selection and acquisition

Checked on 2026-10-01: [Node downloads](https://nodejs.org/en/download) lists 24.21.0 as LTS; [release notes](https://nodejs.org/en/blog/release/v24.21.0) date it to 2026-09-08. [Node release policy](https://nodejs.org/en/about/previous-releases) recommends LTS for production applications. This makes 24.21.0 a candidate for continued development, not a security certification. The [SimpleWebAuthn requirements](https://simplewebauthn.dev/docs/packages/server) document Node 22+; our pinned library remains 14.0.2.

The official [darwin-arm64 archive](https://nodejs.org/dist/v24.21.0/node-v24.21.0-darwin-arm64.tar.gz) and [checksum manifest](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt) were downloaded over HTTPS into an isolated temporary directory. The SHA-256 matched before extraction or execution:

```text
bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057
```

This is HTTPS-source plus checksum validation, not independent release-signature verification. GPG/GPGV were unavailable; no global verification tools or runtime were installed. The upstream detached signature was not verified. Before redistributing a bundled runtime, follow Node's [release-key verification guidance](https://github.com/nodejs/node#verifying-binaries), establish the expected signing identity independently, and retain provenance for each architecture. Do not describe the checksum check as a verified release signature.

The developer's existing Homebrew Node installation was left unchanged. The isolated runtime reported Node 24.21.0, arm64, OpenSSL 3.5.8, with bundled npm 11.19.0. Dependency installation used that runtime with the existing lock and lifecycle-script suppression. `npm audit` reported zero known vulnerabilities at assessment time. [Node runtime advisories](https://nodejs.org/en/blog/vulnerability) are a separate source from npm audit; neither the LTS label nor that npm result establishes absence of runtime vulnerabilities.

## Validation boundary

Local macOS checks using the isolated runtime:

- A clean `npm ci`, unchanged lockfile, lock metadata policy and npm audit.
- 21 challenge-binding, 18 browser/session and 18 private-helper tests, including wrong origin/RP, absent UP/UV, tampering, replay, expiry and cancellation.
- All 23 Rust-to-launcher-to-Node integration tests with release artifacts.
- Full workspace checks, including 19 developer-tool controls, Rust tests, seven original browser-script tests, formatting, strict Clippy and release build.
- The developer preflight and 21 fresh-process measurement samples.

CI selects the same `.node-version` in both the helper and workspace jobs on macOS/Linux. Runtime version is checked again by preflight; there is no fallback to a different runtime. Hosted jobs are a separate merge gate. A passing local ARM64 run must not be described as Intel Mac or Linux evidence.

The historical Chrome/Safari Touch ID matrix belongs to the original 26.5.1-pinned experiment; the tester did not separately report a Node version. It was not repeated for 24.21.0. No UI or verification-policy code changed, so a new hardware matrix is not required to merge this developer-runtime assessment. A physical registration/approval/recovery smoke test on the selected runtime remains a gate before claiming the end-user approval path is validated on LTS. No test here proves biometric identity.

## Observations

Apple Silicon, Darwin 25.6.0; release Rust artifacts. Same npm lock SHA-256 as P03f.1: `d8bce676832f62e3912bde3a94cf663cb7280f9ac96502beeaaf375c9ddc7101`.

| Item | Observed value |
| :--- | :--- |
| Official compressed macOS ARM64 archive | 52,909,993 bytes |
| Extracted Node executable | 122,129,232 bytes |
| Node executable SHA-256 | `e4b5a3af0e05c75de2eae013904145f40fe7fc2a6e6f17510128bf45cca4e79b` |
| First synthetic round trip | 88.126 ms |
| Next 20 fresh-process samples | median 86.095 ms; nearest-rank p95 88.917 ms; range 84.584–92.329 ms |

The P03f.1 Homebrew baseline median was 90.564 ms. Different builds, cache states and only 20 subsequent samples mean this is not evidence of a performance improvement. The timing includes Rust startup, fixture key/assertion generation, launcher, Node import, verification and cleanup; it is not hardware approval latency. The [measurement method](DEVELOPMENT.md) is unchanged.

`otool -L` for the official Node executable listed only CoreFoundation, Security, libc++ and libSystem at system paths. Unlike the Homebrew baseline, it did not list a separate `libnode` or Homebrew OpenSSL/ICU libraries. This is useful packaging evidence, not a full dynamic-load audit or a completely static binary. The Rust test driver and launcher have their own dependency closures; these observations apply only to Node.

Only the macOS ARM64 archive was inspected locally. The official manifest also lists macOS x64 and Linux x64/ARM64 archives; their existence does not prove Vollmacht compatibility on those architectures. Hosted reports identify the architecture actually exercised. No universal macOS bundle, complete installed-runtime size or peak-memory claim is made.

## Development and distribution choice

Use an explicit external Node 24.21.0 installation for now. Select it with your trusted runtime manager or obtain the versioned upstream archive and verify its provenance. Ensure `node` and `npm` resolve to that installation before following [developer setup](DEVELOPMENT.md). You can supply its absolute executable path directly to `dev.py`; changing the machine-wide default is not required. The old 26.5.1 runtime is deliberately rejected by the current preflight pin.

For the first packaged macOS prototype, assess a versioned official runtime bundled with the locked helper. This avoids relying on a Homebrew installation but adds substantial size, licensing and update responsibilities. Keep that as a proposal for the P06 architecture decision, not an implemented delivery mechanism. An embedded/single-executable runtime remains unassessed.

Distribution gates remain: signature/provenance verification, architecture matrix, full native dependency closure, SBOM/license notices, signed/notarized artifacts, installation ownership, update authenticity and rollback handling. Do not ship a fresh local hash as a trust policy or permit runtime fallback on errors. Runtime/dependency updates require a reviewed pin change, fresh install/audit, the complete synthetic matrix and new measurements; reassess hardware coverage when ceremony behavior changes.

The helper feasibility and developer-packaging evidence can now inform P06. The next independent implementation task is P04b: durable Apple key storage, starting with the signed-identity/entitlement matrix and software tests. Real Keychain creation or identity changes remain explicit user-assisted steps.
