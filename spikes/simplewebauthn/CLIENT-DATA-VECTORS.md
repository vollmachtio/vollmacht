# Shared candidate client-data syntax vectors

`client-data-vectors.json` contains 24 unsigned, public fixtures for a candidate syntax gate. Each vector has an ID, exact original bytes encoded as unpadded base64url, an expected `accept` or `reject`, and a manually assigned reason. The encoding was generated with Node Buffer; expectations were assigned from the candidate rules, not copied from an implementation's output. No credential, private key or signature is included.

This is not the helper's current behavior, a frozen production policy, or a WebAuthn conformance corpus. `accept` means only that the candidate syntax profile permits these bytes. For example, `{}` is accepted here but cannot establish a valid assertion. Signature verification, required field values, trusted credential binding, origin/RP checks, current status and replay controls remain separate. The helper characterization in `CLIENT-DATA.md` intentionally permits some inputs this candidate would reject.

## Candidate rules

- Require valid UTF-8, no leading BOM, exactly one top-level object, and ordinary JSON syntax. Surrounding JSON whitespace is allowed.
- Reject repeated decoded member names in every object, including objects within arrays. The same member name in separate objects is allowed.
- Decode escapes for name comparison and reject lone surrogates. Do not perform Unicode normalization: precomposed `é` and `e` plus combining acute remain distinct names.
- Permit unknown fields, arrays, nested objects, null, booleans, valid Unicode, paired surrogate escapes, fractions, exponents and negative zero. This gate must not accidentally import the mandate schema's restricted lexical profile.
- The candidate uses a restricted finite-number profile: `1e400` is rejected because ordinary f64 conversion overflows. This is a deliberate compatibility restriction, not a claim that its JSON grammar is malformed. Numeric semantics of unknown extensions are outside this gate. An exactly representable integer beyond JavaScript's safe-integer limit is included to distinguish this gate from mandate validation.

Consumers must decode base64url without replacing invalid UTF-8 and feed the decoded bytes to the gate without parsing/re-serializing first. Preserve the original bytes for subsequent cryptographic verification. Vector names and explanations are descriptive; only the decoded bytes are test input.

Byte and nesting-depth limits are additional implementation controls. This small corpus deliberately does not freeze their values or test their boundaries; each bounded parser needs dedicated exact-limit and over-limit tests. Likewise, these 24 vectors are selected cases, not exhaustive fuzzing or proof of agreement across all JSON parsers. Cross-runtime results and independent review are required before adopting the candidate policy.
