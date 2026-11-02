# Bounded jsonwebtoken verifier assessment

This is an assessment of the existing jsonwebtoken 11.1.0 dev dependency, not library adoption, a production parser or a P06a freeze. Default crypto features remain disabled. A test-only public-key provider uses existing OpenSSL ES256 verification; unused signer and key utilities fail closed. No native keys or hardware are accessed.

## Verified boundary

The integration test verifies all three independently generated current profile artifacts: issuer envelope, agent execution proof and enrollment possession proof. Public keys come from the fixture's trusted section, not attacker-selected header material. The callback receives the original encoded `header.payload` bytes, compared against the independent fixture's exact deterministic header and canonical payload. Decoded payload values also match.

Wrong public keys, profile-only payload mutation, signature mutation and signature lengths 0, 63 and 65 fail. A changed ES384 header is rejected by the explicit ES256 algorithm allowlist before the verification callback. Empty and malformed public-key containers fail. Raw signature length and P-256 key checks belong to this test provider, not implicit library enforcement. The provider maps verification errors to failure and uses public DER only. The factory receives algorithm and key, not `kid` or trusted role/context.

## JWT settings are not mandate validation

Default `Validation::new(ES256)` rejects the fixture payloads because they lack the registered JWT `exp` claim. The assessment clears required JWT claims and explicitly disables `validate_exp`, `validate_nbf` and `validate_aud`, while preserving the single ES256 allowlist. It uses the signature-verifying `decode`, never an insecure decoding API. Signature mutation tests confirm verification is still enforced.

These settings are suitable only for this bounded non-JWT cryptographic experiment. They do not authorize an operation. Vollmacht must separately require and validate its own `issued_at`, `expires_at`, audience, profile, role, schema and pending-state bindings. A validly signed root `exp: 0` passes the assessment settings but fails default JWT expiry validation. A nested `payload.exp` does not satisfy the default required root `exp` and is ignored by optional root expiry validation. Likewise, the library does not interpret `expires_at: 0` as expiration. Unexpected registered claim names must not become an alternate schema escape hatch.

## Observed permissiveness

Validly signed test variants show that this decode path accepts wrong `typ`, wrong `kid`, additional header fields, an unknown critical header and reordered header bytes. It also accepts a payload with an unknown `crypto_profile` and expired-looking Vollmacht timestamp. These are explicit negative compatibility findings: successful cryptography is not a profile gate. In particular, the unknown critical header result cannot be treated as compliant application processing of that extension.

A correctly signed header with duplicate `alg` is rejected, but a correctly signed payload decoded into `serde_json::Value` collapses duplicate `crypto_profile` members to the last value. One rejected known-header duplicate does not establish general duplicate rejection. Production parsing needs its own evaluated strict boundary before duplicate information is lost, and exact deterministic header matching before accepting an artifact. The byte/value comparisons in this test merely expose missing gates; they do not implement those gates.

The locally signed negative fixtures use fresh ephemeral software keys and a test-only OpenSSL fixture builder. They are separate from the independently generated positive fixtures and are not production JOSE code. Verification independence here is from Node's fixture generation and jsonwebtoken serialization, not from OpenSSL as the test cryptographic backend.

## Remaining gates

Library selection still requires a strict bounded parser design, duplicate and unknown-field rejection, explicit profile enforcement, role/type/algorithm/kid/key binding, and initialization/failure behavior for the process-global provider. Authorization, replay, expiry and original WebAuthn evidence verification remain outside this assessment. Native key confinement and deployment qualification remain separate.

Inspected sources are the pinned upstream [decoder](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/decoding.rs), [validation settings](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/validation.rs), [header model](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/header.rs) and [provider API](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/crypto/mod.rs). Run `python3 scripts/check-jose.py` for formatting, strict Clippy and the complete JOSE spike test suite. Passing this assessment is not a security certification.
