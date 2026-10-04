# Signed client-data ambiguity assessment

Observed 2026-10-03 with pinned Node 24.21.0 and SimpleWebAuthn 14.0.2. These are synthetic signed fixtures, not browser or authenticator evidence. Five tests check the test-only input guard and characterize the unchanged helper, including permissive outcomes that are **not** proposed production acceptance rules. No parser, normalization layer or runtime mitigation is added.

`fixture.mjs` can now sign exact test-supplied client-data bytes instead of JSON.stringify output. This option is test-only, requires a Buffer bounded to 12,288 bytes and copies it before hashing. The helper never imports this fixture. The fixture's software key is known to the test, and its asserted UP/UV flags provide no human-verification evidence. The helper request still passes its strict outer decoder before verification; base64url encoding does not make the embedded JSON unambiguous.

## Results

| Correctly signed client data | Observed helper outcome |
| :--- | :--- |
| Duplicate `type`, `challenge`, `origin` or `crossOrigin`: wrong value first, allowed value last | Verified |
| Same fields with allowed value first, wrong value last | Rejected |
| Escaped-equivalent `challenge` member name | Same last-value behavior |
| Unknown object-valued field | Verified |
| `crossOrigin` absent or false | Verified |
| `crossOrigin` null, string, integer, object or array | Rejected |
| `topOrigin` present, including null or false | Rejected |
| Invalid UTF-8 byte inside an unknown string field | Verified |
| Escaped unpaired surrogate inside an unknown string field | Verified |
| UTF-8 BOM before the JSON object | Verified |
| Truncated JSON or trailing non-JSON text | Rejected |
| Valid pretty printing, reversed member order or escaped slashes, each signed as supplied | Verified |
| Those valid variants replaced by compact equivalent bytes without resigning | Rejected |

This confirms the signature still covers original bytes: semantically equivalent replacements invalidate it. Successful duplicate/invalid-text fixtures require signatures by the enrolled test key; they do not demonstrate an attacker forging another credential's assertion. They do expose inconsistent-interpretation risk if different components apply different JSON or UTF-8 rules.

Local pinned source inspection shows `decodeClientDataJSON` calls `JSON.parse` after decoding base64url as UTF-8. The behavioral tests establish duplicate collapse and permissive decoding for the listed cases. They do not establish behavior for every malformed sequence, extension or future library version. Do not mistake the strict outer request parser for validation of the decoded signed JSON.

## Candidate P06 decision, not implemented

Before production reuse, select a bounded, standards-aware client-data validation policy and assess its implementation independently. Proposed direction: reject invalid UTF-8, BOM, duplicate decoded member names and unpaired surrogates before trusting parsed fields; retain the original bytes for library signature verification. Preserve valid whitespace/order/escaping. Do not canonicalize and verify a replacement representation. Unknown fields need an explicit compatibility policy rather than applying the mandate schema's blanket unknown-field ban to WebAuthn data.

Any future validation layer must prove agreement with the selected library for security-relevant fields and reject ambiguity before either component can select a different value. Tests should assert the new rejection policy separately; these characterization expectations deliberately record the current library/helper behavior. Registration uses client data too and needs its own covered validation path. This slice exercises assertion verification only and makes no claim of complete WebAuthn conformance, authorization, replay protection, trusted enrollment or hardware identity.

Run `node client-data-test.mjs` in this directory using the pinned runtime. The normal `npm test` command also includes these checks. No network, Keychain or live GitHub operation is performed by this test file. Source references are local pinned `node_modules/@simplewebauthn/server/esm/helpers/decodeClientDataJSON.js` and `helper.mjs`; observations remain tied to the tested versions.
