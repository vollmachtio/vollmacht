# Proposed registration transport vectors

`registration-vectors.json` and `tests/registration_vectors.rs` are a test-only executable model of the proposed [registration helper interface](../../docs/architecture/registration-helper-profile.md). They do not implement a runtime version 2 codec, launch a helper, verify WebAuthn or freeze P06a.

The three fixed examples describe request, success-shaped response and rejection-shaped response. Every example is synthetic: `AA` is not an attestation object or COSE public key; `{}` is valid JSON syntax but not valid WebAuthn client data. The string `verified` is simulated helper testimony. A passing model check is never evidence of cryptographic verification, possession, user verification or enrollment authority.

## What the model checks

- Exact request, registration, success, credential and rejection fields; missing, unknown, null, wrong-type and duplicate decoded members.
- Version, operation and profile literals; unsigned integer syntax and counter bounds; request-ID format and response correlation.
- Canonical unpadded base64url, encoded length before decoding, decoded boundaries for IDs, challenge, client data, attestation and returned key.
- Browser ID equality as a semantic precondition, and response ID equality with both browser IDs. The returned ID remains simulated; no authenticator-data ID is extracted here.
- Allowed backup combinations, disjoint response alternatives and fixed rejection code.
- Original client-data and attestation bytes preserved; malformed client-data syntax rejected separately from a structurally valid transport request.
- Shared framing, fragmented input, exact maximum frame size, over-limit whitespace and trailing-frame rejection. All maximal request fields fit the frame limit, but valid individual fields do not exempt a padded body from that limit.
- Existing version 1 request parser rejection of the registration shape, including when relabeled version 1; the proposed model rejects a genuine version 1 assertion request both unchanged and relabeled version 2. The existing response decoder rejects version 2 results against a valid version 1 request rather than falling back.

The model reuses the existing strict outer JSON parser unchanged through test-only path inclusion because that parser is private. Its two existing parser tests also run in this integration-test binary. This is reuse, not independent-parser agreement evidence. Framing uses the existing public API. Client-data syntax uses the existing test-only candidate gate unchanged. No production visibility or dependencies were added.

`request` models transport schema only. `syntax_and_browser_ids` checks only the named preconditions; its success is not registration verification. A response model returning `true` means only a correlated success-shaped message. The rejection alternative returns `false`; malformed or unbound responses fail. These return values are not available to production callers.

## Evidence still missing

These fixtures are authored alongside their contract model, not independent cross-runtime conformance vectors. They do not validate attestation format, COSE labels or curve coordinates, UP/UV, RP hash, challenge/origin/type semantics, backup provenance, activation, process lifecycle, deadlines, cancellation, protected state or registry uniqueness. Existing SimpleWebAuthn registration-binding characterization is separate evidence; it is not invoked or replaced here. Proposed attestation/key bounds still require real browser compatibility qualification.

Before implementation, independently review and freeze the protocol and option-generation boundary, then test an actual maintained-library helper against independent valid and invalid cryptographic evidence. Do not infer actual helper version 2 support from these tests.

Validation: `cargo test -p vollmacht-helper-probe`, plus package formatting and strict all-target Clippy checks. These commands run portable/fake checks and do not perform native key operations.
