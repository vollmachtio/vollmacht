# Candidate enrollment vector review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in this assessment-only slice. A factual description of future fixture timestamps as historical was corrected to fixed synthetic examples.

The generator uses the explicitly public P-256 scalar 1, emits no private JWK or administrative capability, and writes only to standard output. The canonicalization oracle is restricted to fixture ASCII strings, unsigned integers and objects. Rust independently reproduces canonical bytes, the exact administrative domain with one terminating zero byte, digest and public-key thumbprint. Tests check all 19 proposal leaves, distinct authorization/possession stages, nested intervals and exact payload/header relationships.

Node signs the original compact input with ES256 P1363 encoding. Rust JOSE/OpenSSL verifies the committed signatures independently. Five correctly signed variants demonstrate context/type mismatches without relying on broken signatures. Wrong-key and unsigned mutation controls reject; the existing execution proof verifies cryptographically but differs from the required enrollment type and pending payload. Trusted fixture context is test data, not authenticated pending storage.

There is no signed WebAuthn authorization linkage, strict untrusted parser, actual administration capability, monotonic deadline, replay consumption or atomic enrollment commit. Proposal digest sensitivity does not establish administrator approval. Documentation states these limitations and leaves production P06 acceptance open. The inventory adds only the two test sources and generator, all unmeasured.

## Independent validation

- Four scoped canonicalization tests passed offline against the locked dependencies.
- Three scoped JOSE tests passed offline against the locked dependencies.
- Inspected the five authored files against the proposed enrollment profile and inspected the three-row inventory integration.
- Did not regenerate fixtures, change reviewed sources, rerun full workspace checks, invoke hardware or modify Git.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/enrollment-vector-generator.mjs` | `395811fc2a1bfb40b538e864ae884e7a3789acb2a477937d0ac2accd29e3caeb` |
| `spikes/canonicalization/fixtures/candidate-enrollment-vector.json` | `c87bbdda4c47df89c7e6a2588c004580ece97f1a7414a52474f6dbcf87a616d1` |
| `spikes/canonicalization/tests/candidate_enrollment.rs` | `7b7c7cd7dae621a1862439d101799ecf916cc252f106be76e8648ea00324ccf8` |
| `spikes/jose/tests/candidate_enrollment.rs` | `8f417fe5c18c19d755574ced15443f7652f712cb00e93eee25e188cadde7ced7` |
| `spikes/canonicalization/ENROLLMENT.md` | `283c88cf797b1fbac1243d9968451acca4c7600c2719f904bc2175072606c2ec` |
| `coverage/sources.json` | `abeb504997408ae456aa20013089ad6b1eb89dd00e50fcca6153706fec250969` |
