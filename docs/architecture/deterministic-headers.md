# Deterministic protected headers and profile agility

Decision direction approved by the maintainer on 2026-11-01: use fixed-order protected headers instead of JCS-sorted protected headers. This records only that choice. P06a, production library adoption and implementation remain unaccepted pending reviewed interfaces and updated independent vectors. Existing experimental JCS-header fixtures remain historical evidence, not vectors for this revised profile.

## Exact bytes

For the three candidate compact JWS types, the protected header is UTF-8 JSON with exactly three string members in the order `typ`, `alg`, `kid`, with no whitespace, escapes, BOM or trailing bytes:

```text
{"typ":"<type>","alg":"ES256","kid":"<key-id>"}
```

The placeholders are not literal values. Type is exactly `vollmacht-mandate+jws`, `vollmacht-execution+jws` or `vollmacht-agent-enrollment+jws` for the corresponding operation. Issuer key ID is the registered lowercase-hex `id`; execution and enrollment key IDs use the existing canonical base64url SHA-256 thumbprint profile. These alphabets require no JSON escapes. Decoded headers are at most 512 bytes and depth one. Bound encoded input before decoding and require canonical unpadded base64url, not merely a decodable segment.

Before passing input to a general JOSE parser, reject duplicate decoded member names, unknown members, wrong types, malformed encodings and unsupported algorithms. Require exact header bytes for the expected type and validated key ID. A differently ordered or escaped header fails this profile even if its signature is valid. Never rewrite received bytes and verify the rewritten artifact. Verify the original compact signing input as defined by [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2).

Only protected-header serialization changes. Payloads remain JCS, including the complete issuer envelope and agent proof payloads. Domain-separated mandate, operation and envelope digests, original WebAuthn evidence, challenge construction and reservation identity remain unchanged. No detached payload, unencoded payload, critical extension, embedded key, key URL, algorithm negotiation or fallback is introduced.

## Key binding and library independence

Resolve the intended signing identity through trusted state before encoding. The coordinator must bind the expected type, algorithm, header key ID, selected provider handle and registered public key. A provider factory that receives only an algorithm and opaque handle cannot establish the header-to-key binding. An agent-supplied `kid` must never choose an arbitrary signer. Verification likewise resolves only a permitted trusted key in the correct issuer or pending enrollment context.

The byte profile belongs to Vollmacht, not a library's default field order. Pin and test the encoder output against independent literal vectors. A dependency update that changes bytes fails compatibility checks; it cannot silently revise the protocol. Another library may replace the implementation if it meets the same profile and trust contracts. The current jsonwebtoken assessment proves selected fixture compatibility, not complete parsing, verification or provider qualification.

## Controlled agility

V0 remains ES256 only. Agility means reviewed upgrades, not accepting whatever algorithm an untrusted header requests. Keep serializer, signing provider and verifier interfaces separate; select permitted profiles from trusted configuration and enrollment metadata. Reject `none`, algorithm/key-type mismatches and unknown profiles without fallback or trial verification across algorithms.

Before adding an algorithm or changing wire semantics, define an explicit authenticated profile discriminator, key/algorithm bindings, independent positive and negative vectors, rollout and retirement policy, and downgrade/cross-profile rejection tests. The full choice of future discriminator is not frozen here. Existing `version: 1` must not silently acquire incompatible semantics after release. No second algorithm or generic negotiation framework is needed for MVP.

## Remaining acceptance evidence

- Produce separate revised issuer, execution and enrollment header/signature vectors; preserve historical fixtures and label their old profile. A valid old-profile signature must fail the revised header profile.
- Test reordered headers, whitespace, escapes, duplicate names, extra fields, wrong type, wrong algorithm, wrong key ID and mismatched provider handle. Reject before dispatch or registry mutation.
- Exercise full canonical payload equality and original-input verification through the selected implementation. The current external OpenSSL verification experiment does not qualify a generic JWT decoder or the production strict gate.
- Review library selection, provider failure behavior and the remaining P06a contracts before implementation. This decision is not acceptance of the whole authorization system.
