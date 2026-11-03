# Registration options and public-key API assessment

Synthetic assessment for SimpleWebAuthn 14.0.3 and pinned Node 24.21.0. No browser, native key, enrollment, helper protocol change or production adoption. Six tests use public package exports and Node WebCrypto; no dependency or private library import is added.

## Creation options

Explicit byte-array challenge and user ID retain their exact base64url representation in generated options. Passing an already base64url-encoded challenge as a string instead encodes that string's UTF-8 bytes, producing a different challenge. A string user ID rejects. The coordinator must therefore supply the intended decoded bytes and compare the returned values, not assume strings are decoded.

The exact observed shape pins ES256 only, UV required, platform attachment, resident key preferred and none attestation. The library adds `requireResidentKey: false`, `extensions: {credProps: true}` and `hints: []`. It mutates the supplied authenticator-selection object, so the assessment creates it afresh per call. These extra fields are compatibility observations, not authorization inputs or evidence of hardware provenance. Explicit timeout and exclusion descriptors are propagated; browser timeout does not enforce the coordinator's deadline and exclusions do not replace registry uniqueness.

This does not choose an options-generation owner. Rust-owned fixed options or a separately reviewed generator interface remain a design decision; the registration-verification version 2 proposal is unchanged. Tests do not exercise browser compatibility or establish that a client honors requested authenticator preferences.

## Public-key validation

The test-only composition decodes COSE with public `decodeCredentialPublicKey`, requires EC2/P-256/ES256 labels and 32-byte x/y byte strings, then imports a public JWK with `node:crypto` WebCrypto `subtle.importKey`, ECDSA/P-256, nonextractable, verify-only. Encoding negative fixtures uses the existing public `isoCBOR` helper, not a new CBOR parser or curve implementation.

A fresh synthetic valid key imports. Malformed input, non-map COSE, wrong labels, missing coordinates and invalid coordinate types/lengths reject before import. Correctly sized zero coordinates and an out-of-field coordinate reach WebCrypto and reject with `DataError`. These selected cases establish a viable maintained point-validation path, not exhaustive input coverage, proof of possession or trust in the key. No signature is generated or verified by this test composition; activation remains necessary.

The test does not qualify arbitrary CBOR ambiguity/trailing-data handling, full registration validation, trusted pending state, counter/revision races, deadline handling or retained-evidence verification. No existing helper registration path gains these checks. The pinned library's none-attestation registration success must not be mistaken for a separate proof that the point-validation step has already run.

Run `node spikes/simplewebauthn/registration-api.test.mjs` with pinned Node 24.21.0, or the existing npm test command from that spike directory. Production selection and P06a acceptance remain separate reviewed decisions.
