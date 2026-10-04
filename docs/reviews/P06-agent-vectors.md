# P06 candidate agent-proof vector review

Reviewed 2026-10-03 by independent reviewer `adversarial_p02`, separate from the fixture and Rust test authors.

## Scope and disposition

No blockers found in the five files identified below. This is a provisional public fixture and compatibility assessment, not enrollment, a context validator, a frozen protocol or P10 implementation.

The generator explicitly uses public test scalar one to preserve the existing generator-point thumbprint. Its output contains public JWKs and proof artifacts, not a private JWK. This key is forgeable by everyone and must never be trusted operationally; the documentation states that prominently. The generator prints output, does not write fixture files, and checks existing canonical-byte and digest expectations before building proofs. Its restricted canonicalizer is independent of the Rust serialization implementation, not a general JCS library.

Rust checks canonical bytes, RFC 7638 public-member thumbprint links, all three domain-separated digests, audience, fixed challenge and the example time interval. Tests compare canonical payload fields with the separately recorded pending fixture. They do not claim that unauthenticated fixture JSON establishes real trust or that static time comparisons enforce freshness.

JOSE tests validate original compact bytes with the selected fixture key and reject wrong keys and unsigned header, payload and signature mutations. All three context variants retain valid signatures but differ from trusted test expectations in exactly the specified field. The documentation correctly describes these as mismatches, not rejection by a production policy implementation. No caller-supplied key selection or operational signing endpoint is introduced.

## Independent validation

Passed `scripts/check-canonicalization.py`: formatting, strict Clippy and 21 tests, including four new agent tests. Passed `scripts/check-jose.py`: formatting, strict Clippy and 17 tests, including three new agent tests. Separately verified the four committed proof signatures and exact payload bytes with pinned Node 24.21.0 and its native crypto API, without regenerating the fixture.

The generator was inspected, not executed. No elevated commands, advisory refresh, hardware operations or full-workspace rerun were performed. Existing CI discovers the new Rust integration tests; exact-head hosted checks remain required.

Independent serialization paths do not establish independent cryptographic providers. Remaining gates include strict parsing, canonical base64url/profile validation for untrusted artifacts, authenticated registries/pending state, future-issued/expired handling, monotonic deadlines, revocation, atomic challenge consumption and production key protection. The fixed nonce/challenge and public test key are not runtime defaults.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
27e46a1e7e333b3aedf0e05ac0aeebeabbef3a241e1ed77d829894ba43f6dbe0  spikes/simplewebauthn/agent-vector-generator.mjs
1398fe9c3015929b5aed734f7d244bc8c7df7f7a3119881af2e8ffd663d1a3e9  spikes/canonicalization/AGENT.md
213fda4031ddbae444ee636d664d61ccaed28eb68c3cb0d9337471507085d6ea  spikes/canonicalization/fixtures/candidate-agent-vector.json
9042cce52ba96d5646d62bf1dd6dbf5c03849297d7ee9061c681145fac532f1e  spikes/canonicalization/tests/candidate_agent.rs
3fc939e227081816b067216788b19cb1a38f8664f79cf55542ac33197dd3146f  spikes/jose/tests/candidate_agent.rs
```
