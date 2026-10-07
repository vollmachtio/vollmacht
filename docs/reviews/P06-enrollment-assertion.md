# Synthetic enrollment assertion linkage review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in this test-only slice.

The test recomputes the exact administrative domain, terminating zero byte and reviewed proposal bytes against both committed digest encodings. Synthetic software credentials are associated with the proposal's credential ID only in explicitly trusted test setup. That association does not claim registration or operational credential possession.

Correctly signed challenge, domain, ceremony type, origin, RP and UP/UV negative controls are independently checked with Node crypto before invoking the unchanged helper verifier. Credential association and wrong-key tests preserve the original signed evidence. Proposal identity/revision/nonce and candidate key/thumbprint changes alter the expected digest while retaining the assertion, and the original positive control still verifies. The replacement candidate is a valid public P-256 key with explicit canonical member order; single-field key/thumbprint inconsistencies test digest binding, not profile acceptance. Pretty-printed client data is preserved; equivalent reserialization demonstrably invalidates its signature.

Repeated verification against unchanged counter context intentionally succeeds. Documentation accurately limits this to stateless signature/expectation linkage, not replay prevention, human verification, enrollment commit, current registry state or a complete two-stage flow. Signed-client-data ambiguity gating and private-pipe orchestration remain separate. No private material or capability is written by the test.

Package integration appends the test without removing earlier commands or changing dependencies. The inventory adds one unmeasured test source. The previous vector documentation links the new assessment without claiming deployed enrollment.

## Independent validation

- Ran the new file with pinned Node 24.21.0: all seven tests passed.
- Inspected the existing synthetic authenticator and verifier to confirm signed-byte construction and enforced expectations.
- Reviewed all five scoped files and their integration. Did not regenerate fixtures, modify production/helper code, run the network-dependent full package suite, invoke hardware or mutate Git.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/enrollment-assertion.test.mjs` | `192c76a7a6cd52b0f9d04932bd1c6f5b2c1024cb7cf3388705211c1bbff1a46c` |
| `spikes/canonicalization/ENROLLMENT-ASSERTION.md` | `c90493faeca11939ac35ccc8550e392acda68189e23550f353406afcdc825c13` |
| `spikes/canonicalization/ENROLLMENT.md` | `8b671ba35f00b41d22796afd1d9ee18e4e3425a25f962d5378494c2eea2f5366` |
| `spikes/simplewebauthn/package.json` | `e86d7edf76ad3a0a3ecb998af8611c9a23660edfc877ca660e442a8656d4a254` |
| `coverage/sources.json` | `576d6dff2c06829bd11dcac4c2c6ccc2110ac0fe64f7a9c896efffd9a095e4b2` |
