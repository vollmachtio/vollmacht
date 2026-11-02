# jsonwebtoken candidate adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from author `dependency_triage`. Initial scope: four candidate-assessment files, compared with HEAD `2607b5229450efd38db2e9b34dac76b2b84e5723`. A subsequent two-file delta against `9061c8d6ee9a45da8d541f7800c1ffe94d4c0566` is reviewed below; the manifest records the resulting source bytes. These changes belong in their own PR, not the provider-contract change. No production library selection or protocol acceptance is part of this review.

## Reviewed source identity

| Source | SHA-256 |
| :--- | :--- |
| `spikes/jose/Cargo.toml` | `589a51b9abcc4b602631eebd3e61af7b4ec73b27176a92f0a1c07462122c957a` |
| `spikes/jose/Cargo.lock` | `67948818b92c831b87fbb90b578e9f981449445ca417fcfe5421dfff88f6bff7` |
| `spikes/jose/tests/jsonwebtoken_candidate.rs` | `d51f3b248f5bb82f46a9a2dfb4462374e64ab6366076acccc739071fd52a25c4` |
| `spikes/jose/JSONWEBTOKEN.md` | `2c20d68bba0bfea34f34c2df21ab78bdb04502995f305a89cd81b83a80d40e18` |

## Findings and disposition

No actionable findings or unresolved blockers identified in this bounded assessment. No author correction was requested. The negative result is appropriate: the public encoder's protected-header ordering differs from the candidate canonical header, so the assessment stops without claiming full compatibility or an upstream vulnerability.

## Review checks

- Read `CONTRIBUTING.md`, the actual manifest/lockfile diff, both new files, the existing compatibility tests and the unchanged JOSE/dependency validation scripts.
- Inspected installed jsonwebtoken 11.1.0 source for `encode`, its manifest and process-global provider implementation. Registry VCS metadata identifies commit `4c0ae752e9acc108c8e2c4c8ed8128dc66014210`, matching the documented tag commit. The manifest declares Rust 1.88.0 and passively maintained status; the repository pins Rust 1.98.1.
- The new dependency is exact-pinned, default features disabled and confined to the isolated spike's dev dependencies. The feature tree confirms no enabled jsonwebtoken backend or PEM feature. Added target-specific lockfile dependencies do not imply all are compiled on macOS. No root runtime dependency, existing lockfile package upgrade or audit exemption was introduced by this diff.
- The test uses the public encoder and custom signer factory. It checks literal observed header bytes, inequality with literal canonical bytes, exact callback input and preserved fixture payload, rather than merely verifying its own serialization helper.
- The signer hashes the received signing input once through OpenSSL and converts the generated signature to fixed-width ES256 form. Verification reconstructs DER for a public-key-only verifier and checks both the original and altered input. The document correctly limits independence to jsonwebtoken serialization, not the shared OpenSSL provider.
- Unknown, empty and extended handles plus ES384 cannot reach the signer; the final callback count checks this. The opaque handle is explicitly test routing, not a native key API or a private-key confinement claim. Only an ephemeral software key is generated; no production key export or hardware access occurs.
- One test in one integration-test executable owns the global key and installed provider. Reinstallation rejection is checked; other integration-test binaries have separate process state. Unsupported verifier/JWK functions cannot silently provide a production fallback.
- No existing suite or check is removed. The initial assessment did not cover nested payload serialization; the bounded follow-up below adds one fixture, not general canonicalization or production profile enforcement. Generic JWT decoding remains outside scope.

## Follow-up delta review

Reviewed changes to the assessment test and its documentation against `9061c8d6ee9a45da8d541f7800c1ffe94d4c0566`. No actionable finding or blocker identified. Manifest and lockfile hashes remain unchanged.

The added payload expectation comes from the existing independently generated `candidate-envelope-vector.json` canonical string, not a new expectation computed by the candidate encoder. The test first parses that canonical string, checks semantic agreement with the fixture envelope, then compares emitted payload bytes and callback signing input exactly. The protected header still demonstrably differs from the canonical fixture. Documentation correctly avoids claiming that arbitrary input map order is canonicalized or that this one ASCII/integer fixture establishes full JCS conformance.

The changed `kid` observation is explicit and accurate: the same configured ephemeral signer signs a header with a different claimed identity, and public-key verification still succeeds. This establishes the need for application-level key/identity binding, not trust in that claimed key ID. Re-signing fixture payload bytes with this unrelated ephemeral key does not validate the fixture's issuer authority or retained evidence.

The extracted verification helper retains exact-input signature checking and altered-input rejection for every successful signing case. The final callback count becomes three only after the initial invalid-handle/algorithm attempts have already been checked not to sign. Global provider setup remains a single test in its own integration-test executable.

Reference fixture SHA-256: `7e73628c2242a17a80f4b3cd0959a67c15924294e991aaee2ff8bfb48cc02e47`. Independently reran `python3 scripts/check-jose.py` after the delta: formatting, Clippy and all 21 tests passed. The two-file whitespace diff check also passed. No authored source was edited, and no broader decoder or dependency re-audit is claimed for this delta.

## Independent validation

Ran `python3 scripts/check-jose.py` successfully: formatting check, all-target Clippy with warnings denied, and all 21 integration tests passed. This includes the 20 pre-existing tests and the new bounded assessment. Inspected the offline locked feature tree for jsonwebtoken; it appears only under the isolated spike dev dependency. The manifest/lockfile whitespace diff check passed.

The author separately reported an isolated cargo-deny check passing. This reviewer did not independently rerun the advisory scan, and passing tests do not establish absence of vulnerabilities. Full required dependency checks and exact integrated-head CI remain merge gates.

No authored source was edited by this reviewer; only this report was written. No native probe, Keychain, VM, signing identity or external write was performed. Material changes after the recorded hashes require review of the delta.
