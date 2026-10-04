# JOSE signing-interface assessment

Isolated experiment, not a production issuer or verifier. The proposed candidate is josekit 0.10.3 with existing OpenSSL 0.10.81, base64 0.21.7 and serde_json 1.0.151 pins. The standalone lockfile and repository dependency policy must be audited before merge.

Scope: compact ES256 compatibility, exact signing-input bytes, raw 64-byte ECDSA signatures, one SHA-256 operation over the original signing input, and independent verification. Test keys are temporary in-memory software keys. No Apple API, private-key confinement, hardware attestation, enrollment, mandate parsing or agent authorization is implemented.

The custom signer experiment assesses whether a maintained JOSE library can call a signer without requiring the private key to be exported into the library. Its software test key is exportable and does not establish non-exportability. A future native bridge requires a separate reviewed protocol and signed-identity assessment.

Cryptographic validity is not application authorization. A production verifier must separately enforce the selected algorithm, exact allowed protected-header fields and values, trusted key resolution, critical-header policy, payload profile, bounded parsing and canonicality. No schema or production header is frozen here. A general JOSE verifier can accept valid signatures over headers that our future profile would forbid.

josekit includes JWE-related functionality, compression, regex and insertion-ordered-map dependencies that this JWS-only experiment does not need. Its older release and broader dependency surface are tradeoffs, not automatically disqualifying or evidence of safety. This experiment does not choose the production library or satisfy the complete P06 gate by itself.

## Observed compatibility and profile gaps

The tests compare the signing callback with exact `base64url(protected) + "." + base64url(payload)` bytes. OpenSSL's message signer hashes that original input once and converts DER to fixed-width r/s using maintained integer routines. Independent verification reverses the encoding and verifies with only the public key; hashing an already hashed input fails. This is independence from the JOSE serialization layer, not a second cryptographic provider.

Header serialization preserves insertion order, not canonical JSON order. Tests deliberately preinsert `alg`, `kid`, `typ` in the desired order and compare with literal bytes; reordered headers still verify but have different bytes. The serializer also overwrites `alg` from the signer and can overwrite `kid` when the signer supplies one. Production callers must not treat a supplied header as unchanged output.

Passing negative demonstrations show validly signed wrong `typ`, an unbound `kid`, extra fields, and `b64: false` without its critical declaration can pass the generic verifier. A verifier with an explicitly configured key ID rejects mismatched IDs. Unknown critical names fail by default; unencoded payloads verify only after the context explicitly permits the `b64` critical extension. None of these options is selected for Vollmacht.

The library parses protected headers through a normal serde_json map. A correctly signed header containing duplicate `alg` fields can therefore verify after duplicate collapse. The production bounded duplicate-rejecting parser must run before this library; using its generic verification function alone is insufficient.

Source review additionally found self-recursive equality in `PartialEq for Box<dyn JwsAlgorithm>`. Compact verification compares algorithm names and does not exercise that equality implementation; neither do these tests. This unused-path defect is a maintenance concern that remains part of library selection, not an issue this spike silently patches. No upstream report or dependency change is made here. [Pinned algorithm trait source](https://docs.rs/crate/josekit/0.10.3/source/src/jws/jws_algorithm.rs)

From repository root, run `python3 scripts/check-jose.py` for formatting, strict Clippy and locked tests. `scripts/check.py` invokes this isolated crate explicitly on both CI platforms; ordinary Cargo workspace tests alone do not include it. `python3 scripts/dependencies.py` audits all three graphs with the repository policy, including this standalone lockfile.

Sources: [josekit 0.10.3 API](https://docs.rs/josekit/0.10.3/josekit/), [RFC 7515 JWS](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7518 ES256](https://www.rfc-editor.org/rfc/rfc7518).
