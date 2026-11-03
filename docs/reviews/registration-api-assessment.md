# Registration public API assessment review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in this synthetic compatibility assessment. No production helper or enrollment policy is approved by this review.

## Reviewed boundaries

Creation-options tests compare the complete observed output, not only the requested algorithm. They preserve the caller's challenge and user-ID bytes, characterize string challenge re-encoding and string user-ID rejection, and expose mutation of the supplied authenticator-selection object. The explicit ES256, platform, UV, resident-key and attestation settings match the proposed narrow profile. Propagated timeout and exclusions are correctly distinguished from authoritative deadlines and registry checks.

Public package exports provide COSE decoding and fixture encoding. The test composition checks map shape, labels and coordinate lengths before a verify-only P-256 WebCrypto import. The positive control succeeds; malformed shapes fail before import, while correctly sized zero and out-of-field coordinates reach WebCrypto and fail with DataError. This gives meaningful evidence beyond rejecting malformed labels. No bespoke curve algorithm or private package import was added.

The pinned decoder uses first-object CBOR decoding. The documentation does not claim strict arbitrary CBOR, trailing-data or duplicate-label validation. Selected point-import controls do not establish private-key possession, attestation provenance or actual registration verification. These limits, the unresolved options-generation owner and lack of production integration are stated explicitly.

Package integration appends the new test without dropping existing suites. Inventory adds only the new source as an unmeasured test. No dependency or runtime-verifier changes are present.

## Independent validation

- Inspected the pinned package's public exports, registration-options implementation and credential-key decoder.
- Ran the six new tests directly on Node 24.21.0: all passed.
- Initial full npm execution was blocked by sandbox loopback restrictions in four existing HTTP tests. Repeated with approved loopback capability: complete npm test command passed, including all 83 tests and five lockfile negative controls. No tests were skipped or weakened.
- Inventory validation passed with 111 sources.
- No browser ceremony, native key operation, reviewed-source edit or Git mutation performed.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/registration-api.test.mjs` | `6f41fda392524adf3926f81d8712267be3b25b8f95d793de5c3f632fffa3cd3d` |
| `spikes/simplewebauthn/REGISTRATION-API.md` | `f32c27c1248ff5ddfd4e6d10000522336d484bdeecc9b383609876450e8d3577` |
| `spikes/simplewebauthn/package.json` | `8770f87d7e7730d2956f2b2ea064dbe410d932b59603df9f2b1516d65698f634` |
| `coverage/sources.json` | `1391167d2dd0a07c8ab7a181883e4a69c0122b587a061f866225a01b1bfd9a18` |
