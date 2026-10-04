# Candidate signed client-data syntax validation

Assessment only, 2026-10-03. The implementation lives under `tests/support/client_data.rs`, is compiled only into integration tests, and is not called by the helper transport, browser server or Node verifier. It does not close the P06 ambiguity-policy gate or harden current runtime behavior.

The [signed characterization](../simplewebauthn/CLIENT-DATA.md) found that the current helper accepts some correctly signed ambiguous JSON. This experiment assesses a separate prevalidation step using the existing pinned serde/serde_json parser rather than writing a JSON tokenizer or loosening the outer IPC decoder.

## Candidate scope

Validate exactly one top-level object with valid UTF-8 and no leading BOM. Reject duplicate decoded member names in every object, including objects inside arrays, malformed escapes, unpaired surrogates and trailing non-whitespace input. Name comparison uses decoded strings without Unicode normalization. The same name in different objects is permitted.

Unknown fields may contain Unicode strings, objects, arrays, null, booleans and numbers supported by the pinned parser. In particular, the mandate profile's ASCII-only strings, unsigned integer grammar and unknown-field ban do not apply here. Finite floating-point conversion is an assessment restriction: numeric overflow such as `1e400` rejects even though its token follows JSON number grammar. No parsed numeric value supplies authority, and this is not a promise to preserve numeric meaning for future extensions.

Input is bounded to 12,288 bytes and 16 nested containers, counting the root object as level one and counting arrays as containers. These are proposed resource limits, not WebAuthn conformance claims. Size bounds limit aggregate allocation; per-object decoded-key sets detect duplicates. The experiment validates without returning a normalized representation. The caller retains the original input bytes for cryptographic verification.

## What success does not establish

An empty object passes this syntax gate. Success does not establish required field types or values, challenge/origin/RP agreement, UP/UV, credential trust, signature validity, freshness, revocation or replay consumption. Those remain the trusted verifier and controller's responsibilities. A malicious helper is still inside the trust boundary.

Neither assertion nor registration paths are integrated with this validator. Adoption requires a separately reviewed decision covering compatibility limits, agreement on security-relevant fields, and every ingestion path. A Rust precheck alone does not change direct Node helper calls. Signed data must never be reserialized before signature verification.

## Validation

Run `cargo test -p vollmacht-helper-probe` or the full repository check script. Tests consume the [24 shared unsigned vectors](../simplewebauthn/CLIENT-DATA-VECTORS.md) and exercise exact byte/depth limits, nested duplicates and valid data beyond the narrower IPC profile. Workspace CI discovers the integration tests automatically. These are selected regression cases, not exhaustive fuzzing or evidence of cryptographic verification.
