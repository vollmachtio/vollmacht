# P06 client-data syntax assessment review

Reviewed 2026-10-03 by independent reviewer `adversarial_p02`, separate from the implementation, corpus and documentation authors.

## Scope and disposition

No blockers found in the six files identified below. This is a test-only structural prevalidation experiment, not runtime hardening or a closed P06 gate. Concurrent follow-up files are excluded.

The visitor checks decoded member names independently in each object, including objects reached through arrays. It traverses unknown values rather than skipping them. Container checks include empty containers and count the root as one; scalars do not add container depth. The byte limit is checked before parsing, UTF-8 is checked without replacement, and the parser requires a complete top-level object with no trailing non-whitespace input.

The validator returns only acceptance or rejection and borrows immutable original bytes. It does not expose normalized data for cryptographic verification. Escaped-equivalent names collide, distinct Unicode normalization forms remain distinct, and malformed surrogates fail. The finite-number restriction is documented as a compatibility choice rather than JSON grammar or WebAuthn semantics.

The 24 unsigned corpus expectations match the proposed rules. The consumer verifies unique vector IDs, expected profile/count and canonical base64url encoding before applying the gate. Dedicated tests exercise exact byte and container limits separately from the corpus. Passing syntax intentionally permits missing or invalid WebAuthn fields; the documentation correctly preserves trusted-verifier and controller responsibilities.

## Independent validation

All 15 client-data integration tests passed independently. Strict Clippy passed for all targets in `vollmacht-helper-probe`. These checks used cached locked dependencies, without elevation or hardware access. No full-workspace rerun, advisory refresh or runtime integration test was performed by this reviewer.

Remaining gates include signed cross-runtime agreement, security-field interpretation, every ingestion path, resource-limit compatibility and explicit policy adoption. Selected regression cases are not exhaustive fuzzing or proof of parser equivalence. Exact-head CI remains required before merge.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
49d580832263cec40059f6433a889e7941ce56fb429ff34860c7c5fcdb95683b  spikes/helper-protocol/tests/support/client_data.rs
220239da174d1f9cb6993f5c4c6e6edfa4638feb0cd4634754879f45c1455dff  spikes/helper-protocol/tests/client_data.rs
e95750b6edff1736a7744c47565a8e64eef19a35236e021bff05639a886dd2de  spikes/helper-protocol/CLIENT-DATA.md
4e8fa4cc669fafb5c07e4c0b991e3d80705ebb2aede7073bd628ce9e8b282bb5  spikes/helper-protocol/README.md
a5241a7339faa19dd911db606efd8b8362599bf6e9d1c94cec124c36b635a5ba  spikes/simplewebauthn/client-data-vectors.json
c7fc7244ce9ce94dd126ef4dd7ec8d31e72c7ddc9b64a94737803c276413df0b  spikes/simplewebauthn/CLIENT-DATA-VECTORS.md
```
