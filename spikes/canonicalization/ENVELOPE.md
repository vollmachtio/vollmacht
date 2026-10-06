# Complete synthetic envelope vector

`fixtures/candidate-envelope-vector.json` joins the existing candidate payload, a software-generated WebAuthn assertion and an issuer ES256 JWS. It is a provisional compatibility fixture, not a frozen mandate schema, trusted enrollment record or executable authority.

The payload exactly matches `candidate-payload.json`, including its deliberately fixed IDs, zero nonce and timestamps. The assertion challenge is the existing domain-separated canonical payload digest. Signed client data is pretty printed and retained byte-for-byte; authenticator data contains the `localhost` RP hash, synthetic UP/UV flags and counter one. Trusted test context supplies counter zero, user handle `AA` and backup eligibility false. The evidence has an absent user handle represented by an empty string.

The separate `trusted` object provides public issuer and credential keys plus distinct wrong-key controls. Tests choose these keys explicitly as fixture configuration; the artifact cannot enroll or select its own trusted key. These ordinary JSON fields have no protected-registry provenance in a real system. No private keys or passkeys are included. Synthetic UP/UV flags are not proof of a human, biometric identity or a platform authenticator.

## Two issuer-signed artifacts

The positive envelope contains exactly the candidate version, payload and evidence. Expected canonical envelope/header strings and the domain-separated envelope digest are included. The compact issuer artifact signs the original `base64url(header).base64url(envelope)` bytes, using ES256 raw 64-byte r/s encoding. Its header carries only alg, kid and typ.

The rebound envelope changes only PR number 42 to 43 and retains the original assertion. It has a fresh valid signature from the same fixture issuer. Its issuer signature should verify, but evidence verification using the challenge recomputed from the changed payload must reject. This distinguishes issuer provenance from human-approval binding: an issuer signature alone is not sufficient.

Other consumers should test wrong trusted issuer/credential keys, payload/evidence mutation without resigning, a different challenge domain, and equivalent client-data reserialization without resigning. Comparisons of canonical bytes and digests should use independent Rust serialization and hashing, not call the fixture generator as their expected-value oracle.

## Offline generation and reproducibility

From repository root with the pinned Node runtime available:

```sh
node spikes/simplewebauthn/envelope-vector-generator.mjs
```

The generator requires Node 24.21.0 and the already pinned SimpleWebAuthn dependencies. It reads only the existing payload and expected-vector files, generates temporary in-memory software keys and prints the public vector JSON to stdout. It never writes files or exports private keys. Existing experimental Web Crypto warnings may appear on stderr. Process termination ends access to these keys; no claim of secure memory erasure is made.

Node crypto supplies key generation, SHA-256 and both ECDSA encodings; the maintained SimpleWebAuthn CBOR helper encodes the public COSE key. The independent canonical-byte oracle accepts only this fixture's ASCII strings, nonnegative safe integers and objects with restricted member names. It is not a general JCS implementation or an application parser. It first checks the existing independently reviewed canonical payload and challenge expectations.

A rerun generates different keys and nondeterministic ECDSA signatures, so it does not reproduce the committed vector byte-for-byte. The committed public vector is stable verification input. Regeneration is a deliberate fixture update requiring independent checks of new bytes, signatures and trusted context; never automatically overwrite expectations from the implementation under test.

No dependencies, native signer, production parser, registration flow, protected storage, agent proof, current policy/time check, reservation or live GitHub action is added. The fixed payload cannot demonstrate freshness or replay resistance. Passing cryptographic tests does not satisfy those separate gates or select production JCS/JOSE libraries.
