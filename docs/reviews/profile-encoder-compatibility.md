# Current profile encoder compatibility review

Date: 2026-11-01. Independent reviewer: `/root/review_profile_compatibility`, separate from the author. Scope: the two-file diff against HEAD `73602b3d869384a5ff8b94522fc9322636d66261`. The unrelated registration-helper proposal and personal Xcode project are excluded.

## Source identity

| Source | SHA-256 |
| :--- | :--- |
| `spikes/jose/tests/jsonwebtoken_candidate.rs` | `d86813741b4b9b746a9ef52fea58012892edcee611ff35e857d6be5e69d4a736` |
| `spikes/jose/JSONWEBTOKEN.md` | `e212348776d354db1fac930d7cfc611881b3bd5f1bfd87500ed0b48ed72e29ce` |

The unchanged supporting fixture `spikes/canonicalization/fixtures/candidate-profile-vector.json` has SHA-256 `b5660d224a1dd6f07366bf002f91a317141bbba5256c16dc531b7c984b191215`.

## Findings

No actionable findings or merge blockers identified within this bounded assessment. No source changes were requested or made by the reviewer.

The added cases compare decoded encoder output against independently supplied exact header and canonical payload bytes for issuer, execution and enrollment possession artifacts. They also compare the complete callback signing input, so verification success alone cannot hide a serialization mismatch. The issuer profile is checked in the nested approval payload; the other two profiles are checked at the payload root.

Each artifact is verified using the fresh software key's public component. Wrong-key, signature-mutation and unsigned profile-change cases reject. The single profile occurrence assertion makes the profile substitution bounded to the intended fixture field. Historical canonical-header incompatibility and opaque-handle/algorithm rejection cases remain intact. The existing wrong-`kid` demonstration continues to expose the application's required identity-to-handle binding rather than implying that the provider establishes it.

The documentation accurately limits the result to three fixtures and the current encoder. It does not claim arbitrary JSON canonicalization, strict production parsing, unknown-profile policy enforcement, native confinement, fixture issuer authority, library adoption or P06a acceptance. Verification remains outside jsonwebtoken and uses the same OpenSSL cryptographic provider as signing. Re-signing with an unrelated ephemeral key tests bytes, not authorization or the embedded evidence's trustworthiness.

No dependencies, production code, coverage exclusions or mandatory checks changed in this scope.

## Independent validation

- `python3 scripts/check-jose.py`: formatting and all-target Clippy passed; all 23 integration tests passed, including the revised encoder assessment.
- Git whitespace diff check passed.
- Inspected the unchanged supporting profile fixture, deterministic-header proposal and pinned assessment dependency manifest.

Only this review report was written. No Keychain access, hardware probe, signing configuration, VM operation or external write occurred. Required CI on the exact integrated head and review of any later material changes remain necessary before merge.
