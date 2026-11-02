# Public verifier assessment review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no unresolved blocking findings in this test-only assessment. This is not production verifier approval or a P06a freeze.

## Findings and resolution

The initial negative-header baseline used an invented type and combined header changes with an invalid payload. Review requested a current-profile baseline and isolated mutations. The final test re-signs and successfully decodes the actual execution fixture header and payload, changes each header dimension separately, and separates unknown-profile and expired-looking payload cases. This resolves the evidence-precision concern.

## Reviewed boundaries

The public verification callback receives the original encoded signing input. Positive controls compare that input and decoded values against independently generated fixture artifacts for all three roles. Trusted public keys come from the fixture's trusted section, not the token header. The test provider explicitly restricts ES256, checks P-256 public-key validity, requires a 64-byte signature, converts its scalar encoding and verifies SHA-256 once. Wrong-key, altered-input, altered-signature and malformed-length controls reject. Algorithm mismatch is rejected before the verification callback.

The pinned local jsonwebtoken 11.1.0 decoder, header, validation and provider sources support the documented distinction between cryptographic verification and application policy. Default registered JWT claims do not implement Vollmacht timestamps or context. The permissive-header, duplicate-payload and root-versus-nested expiry tests characterize missing gates rather than claiming to enforce them. The critical-header case demonstrates acceptance of an unsupported critical declaration, not compliant extension processing.

The documentation correctly limits independence from OpenSSL, attributes raw-signature and curve checks to the custom provider, and leaves strict parsing, role/key/context binding and global-provider initialization as adoption work. No dependency, production parser, authorization path or native operation changes. Inventory adds exactly one unmeasured test source. The unrelated registration-helper proposal was excluded.

## Independent validation

- Ran `python3 scripts/check-jose.py` on final bytes: formatting, strict Clippy and all 24 tests passed.
- Ran `python3 scripts/coverage_inventory.py`: 109 sources passed.
- Read the three scoped files and relevant pinned dependency implementation. No hardware, network-dependent checks, Git mutations or reviewed-source edits performed.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/jose/tests/jsonwebtoken_verifier.rs` | `762b45993606aadc48f0ba26bfc5d75e971f5f283566776a6a965d77fdeff7e8` |
| `spikes/jose/VERIFIER.md` | `5be1e5375b74cf472ef2708f9428793446f0d5d2232a3c40d9dd43d655974e18` |
| `coverage/sources.json` | `b92f69130b8932328db7e69506b12547f0573fbd0657b76d537ea5e94c3fe9b0` |
