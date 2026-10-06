# P06 synthetic envelope vector review

Reviewed 2026-10-03 by independent reviewer `adversarial_p02`, separate from the fixture and integration authors.

## Scope and disposition

No blockers found in the seven files identified below. The review covers a provisional public fixture, offline generator, Rust and Node consumers, documentation and the additional CI step. It does not select a production protocol or integrate authorization.

The generator uses temporary software keys, exports only public key material, and prints the vector rather than writing files. Its restricted ASCII/integer canonicalizer is separate from Rust's serializer and checks the previously committed payload oracle before constructing evidence. Test execution consumes the committed fixture rather than regenerating expected output. Regeneration is deliberately nondeterministic and is not claimed to reproduce signatures byte-for-byte.

The retained client-data bytes bind the existing payload digest. Rust independently checks canonical header/envelope bytes, evidence linkage and envelope-domain hashing. JOSE tests verify the exact original compact segments with explicitly selected fixture issuer keys and reject wrong keys and unsigned modifications. Node separately verifies retained WebAuthn evidence with fixture credential context.

The rebound case has a valid issuer signature but a changed operation and unchanged assertion. Its rejection under the recomputed challenge demonstrates the distinction between issuer provenance and credential approval. Wrong credential/domain and reserialization cases have a valid positive control. Synthetic UP/UV flags, JSON trusted-context fields and public fixture keys are correctly described as lacking real enrollment, human evidence and protected-registry provenance.

CI adds only a Node test step within the existing pinned-runtime job. No new permissions, dependencies, actions, secrets or privileged trigger are introduced. This branch's workflow delta does not include the separate client-data gate PR.

## Independent validation

Passed `scripts/check-canonicalization.py`: formatting, strict Clippy and 17 tests, including four new envelope tests. Passed `scripts/check-jose.py`: formatting, strict Clippy and 14 tests, including three new envelope tests. All six Node envelope tests passed with pinned Node 24.21.0. Existing Web Crypto experimental warnings appeared without failures.

Inspected the generator without executing it or regenerating the fixture. Inspected public context and decoded assertion fields. No elevated commands, advisory refresh, full-workspace rerun, hardware operation or GitHub action was performed. Hosted exact-head CI remains required.

Independent serialization paths are not an independent cryptographic-provider guarantee. Strict untrusted-input parsing, complete rejection vectors, native issuer protection, enrollment, agent proof, current time/policy checks and durable replay consumption remain separate gates. The fixture's fixed identifiers and nonce must never become runtime defaults.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
7e73628c2242a17a80f4b3cd0959a67c15924294e991aaee2ff8bfb48cc02e47  spikes/canonicalization/fixtures/candidate-envelope-vector.json
0802992d8132615bc7c1dbdf5a2768b8483a36a7b2f445a1c63275ecc26c7279  spikes/canonicalization/ENVELOPE.md
10f6d5557bfd04a0d69abe92d04e30b1c6e1d17e5c6f93a70133a212d6917895  spikes/canonicalization/tests/candidate_envelope.rs
7d11c6205972047a005d22c33224d3e62d533259dfac2c6c60f58816cd86633b  spikes/jose/tests/candidate_envelope.rs
57e2aaa83c797171ace78d4c196637a72dc0370eb2e0ad9bc575faca3cef2664  spikes/simplewebauthn/envelope-vector-generator.mjs
b226b0b1f357ead3d7bd5228091c813ae1813ee11bebfa45e17d44749220ca4a  spikes/simplewebauthn/envelope-vector-test.mjs
fa058f3510795cd697cc5ee2f000e0de81e7e492e48c03da63232b5fab59201d  .github/workflows/ci.yml
```
