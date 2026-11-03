# Proposed P06a portable decision packet

Status: **PROPOSED**, 2026-11-02. This resolves portable design choices for independent review using the merged assessments; it is not their acceptance record. No production implementation is authorized by this document. P06b/native qualification, deployment configuration and live operations remain separate. The packet proposes the following concrete decisions rather than another open-ended feasibility program.

## Decision 1: restricted canonical objects and exact parsing

Select `serde_jcs` 0.2.0 `to_vec` for the existing restricted ASCII/string/object/unsigned-integer application profile. Do not use its unsafe UTF-8 convenience conversion or treat serialization as validation. A bounded duplicate-rejecting parser must inspect decoded member names and integer lexical forms before constructing ordinary maps. Reject unknown/missing fields through exact object schemas; do not pass arbitrary JSON values into production constructors. Application schema and crypto-profile restrictions remain those in [mandate-contract](mandate-contract.md) and [crypto-profiles](crypto-profiles.md).

Make the candidate bounds unambiguous: the 8,192-byte approval payload and 65,536-byte envelope limits apply both to the original decoded JSON bytes, including whitespace, and to their canonical output. The 100,000-byte issuer compact limit applies before splitting/decoding. Each nested object also obeys its own bound. Object depth counts the root as one and is at most eight; reject before recursive allocation exceeds that limit. Execution proof has independent caps of 8,192 bytes for the whole compact artifact, 512 decoded header bytes and 8,192 decoded payload bytes; the compact cap can be the tighter limit. Bound each encoded segment before decoding, then enforce decoded and canonical output caps. Existing stricter enrollment/header depth and byte caps remain unchanged and likewise cover original decoded and canonical output where applicable. Signed WebAuthn byte strings use their separate policy, never this application profile.

For this first profile, `base_ref` is 1 through 255 ASCII bytes, preserving case, with the following explicit restrictions. Reject a leading dash; leading/trailing/double slash; any slash-delimited component beginning with a dot or ending in `.lock`; any `..` or `@{` sequence; a terminal dot; the complete name `@` or `HEAD`; ASCII control characters, space or DEL; and any `~`, `^`, `:`, `?`, `*`, `[` or backslash. One-level names such as `main` are allowed. Do not expand Git shorthand or normalize input, and do not invoke a Git subprocess at runtime. This is a bounded ASCII branch subset informed by the [Git reference-format rules](https://git-scm.com/docs/git-check-ref-format), not all valid Git references. Trusted GitHub resolution must still return the exact approved branch; syntax does not establish existence or protect against retargeting. This proposed exact subset replaces the candidate's imprecise “valid Git branch name” predicate only after acceptance.

Existing independent candidate-profile fixtures and literal canonical tests are the initial oracle, not full RFC 8785 conformance. Parser exact-limit and malformed-input tests accompany P07 implementation after acceptance. This choice does not require full Unicode/floating-point support or a new canonicalizer.

## Decision 2: maintained JOSE with a narrow crypto provider

Select `jsonwebtoken` 11.1.0 with default features disabled for compact JWS encoding and signature-verifying decoding. Select existing `openssl` 0.10.81 bindings for portable P-256 public-key validation, SHA-256 hashing and ES256 verification, and for explicitly test-only software signing. This is an adoption proposal for assessed versions, conditional on the integrated dependency policy checks. Do not enable another backend, PEM, JWE or algorithm negotiation. josekit remains historical experiment evidence, not the selected production dependency.

Use the reviewed deterministic `typ`, `alg`, `kid` header bytes and required `vollmacht-local-es256-v1` payload profile. Before library decode, independently require bounded canonical base64url segments, exact schema, no duplicates/unknown fields, exact expected header bytes and canonical payload bytes. Verify original compact signing-input bytes. The library's generic header and claims checks are not this profile gate.

Construct `Validation` with only ES256, empty required registered JWT claims, `validate_exp = false`, `validate_nbf = false`, `validate_aud = false`, and zero leeway, as assessed. Keep signature verification enabled and use no insecure decode API. Vollmacht separately enforces its required timestamps, audience, crypto profile and trusted state. Registered JWT claim names such as `exp` are unknown application fields, not optional alternate semantics.

For encoding, serialize only a schema-validated canonical value, and require the encoder's callback input to equal the independently prepared exact base64url header plus period plus canonical payload before a key is used. Require final emitted header/payload segments to match those bytes too; no generic-map insertion-order assumption. An output mismatch is an error, never re-signing under revised bytes. This guard turns assessed encoder compatibility into an enforceable interface requirement.

The custom provider is installed exactly once, before threads, listeners, pending ceremonies or signer handles are available. Failure to install, any previously installed provider, or failed startup self-check stops initialization; do not reuse an unknown global provider. No request can replace it. Unsupported algorithm and key utility operations fail closed. Integration tests requiring different provider configurations run in separate processes, not by resetting global state.

The application binds role/type/profile/key ID/public key and signer handle using trusted state before creating an immutable per-operation signing context. The provider factory's algorithm and opaque key bytes are insufficient by themselves. Route through a bounded private handle table whose entries pin that context and exact expected signing input; unknown, expired or mismatched handles fail. Remove the entry when its operation ends, and do not expose handles through browser/agent APIs. Provider callbacks cannot infer authority from `kid`. Real issuer handles route only to the separately qualified issuer provider, never portable software signing as fallback.

The OpenSSL verifier imports only the resolved trusted public key, requires P-256 and `check_key` success, requires exactly 64 signature bytes, converts raw scalars through maintained OpenSSL integer/signature APIs, and verifies SHA-256 over the original input once. Invalid/out-of-range scalar or signature verification failure denies. If DER conversion is needed at a real signing boundary, require exact consumption, canonical encoding and valid scalar ranges using the already assessed maintained APIs. No custom curve, hash, ECDSA or ASN.1 primitive is introduced. Signature nonuniqueness remains compatible with ID-based durable replay protection.

## Decision 3: Rust constructs fixed browser options

Rust owns option construction from the already claimed pending stage. Do not add an option-generation helper RPC or call a browser-selected algorithm generator. The browser performs only the explicit base64url-to-byte conversions below and invokes the authenticator. The [public API assessment](../../spikes/simplewebauthn/REGISTRATION-API.md) supplies compatible observed shape and byte-conversion pitfalls, not proof that a browser honors preferences.

Creation options contain exactly these fields under `publicKey`:

| Field | Fixed value or trusted source |
| :--- | :--- |
| `challenge` | Canonical base64url of the pending 32-byte registration challenge |
| `rp` | `{name: "Vollmacht", id: "localhost"}` |
| `user` | `{id: <pending 32-byte user handle as base64url>, name: <principal id>, displayName: <principal id>}`; the local ID is not a civil identity claim |
| `pubKeyCredParams` | Exactly `[{alg: -7, type: "public-key"}]` |
| `timeout` | Integer milliseconds calculated below |
| `attestation` | `"none"` |
| `excludeCredentials` | `[]` for fresh one-principal bootstrap; existing/incomplete installations reject before reaching this stage |
| `authenticatorSelection` | Exactly `{authenticatorAttachment: "platform", residentKey: "preferred", userVerification: "required", requireResidentKey: false}` |
| `extensions` | Exactly `{credProps: true}`; returned hints never supply authority |
| `hints` | `[]` |

The table describes transport JSON. Immediately before `navigator.credentials.create`, the UI strictly decodes `challenge` and `user.id` to byte buffers. It must not pass base64url text as UTF-8 bytes or regenerate either value. Other values are copied unchanged from the trusted server response. No agent text, custom extensions or browser-provided RP ID enters options. The complete server response remains subject to the existing same-origin, capability, CSP and bounded transport contract.

Activation/assertion options contain exactly `challenge`, `rpId: "localhost"`, `timeout`, `userVerification: "required"`, and `allowCredentials: [{type: "public-key", id: <exact selected credential ID as canonical base64url>}]`. Decode challenge and credential ID to bytes before `navigator.credentials.get`. No transport restriction, discoverable selection, conditional mediation, extensions or alternate RP is added. Activation selects only the immutable pending candidate; normal approval/administration selects only the enabled credential already fixed before challenge construction. The returned credential and optional user handle still require full server checks.

For every stage calculate `timeout = min(120000, floor(remaining_monotonic_milliseconds))`; additionally cap by remaining payload wall-time milliseconds for mandate or administrative payloads that carry expiry. If the result is below 1 or time has moved backward, deny rather than extend the ceremony. Activation and later stages use the original operation deadline, not a fresh 120 seconds. Request delay and browser behavior may shorten usefulness but never extend server validity. Browser timeout is a hint: independently recheck monotonic deadline, wall expiry when applicable, cancellation and revisions before/after helper verification and at commit.

Creation options do not prove platform provenance, passkey creation does not enroll a principal, and `excludeCredentials` is not uniqueness enforcement. None attestation plus mandatory fresh activation remains the chosen pending-candidate flow. Credential replacement/rotation is deferred and rejected; this packet defines no options for it.

## Decision 4: trusted WebAuthn verification and key representation

Retain the trusted SimpleWebAuthn 14.0.3 helper on assessed Node 24.21.0. Rust owns authorization and state, while the helper performs full registration/assertion verification; Rust correlation is not independent cryptographic validation. Adopt the proposed registration version 2 and assertion version 1 exact schemas without trial decoding or additional modes. The [registration helper proposal](registration-helper-profile.md) remains the source for 16-KiB attestation bound, `none`-only restriction, three-way credential-ID equality and fixed result alternatives.

Adopt the assessed signed-client-data syntax policy on both sides before security-field interpretation: strict UTF-8, no BOM, one object, duplicate decoded member rejection at every level, valid surrogates, finite-number restriction, 12,288-byte and 16-container bounds. Unknown extension fields and valid Unicode remain permitted under that policy. Preserve original bytes for cryptographic verification. A passed Rust syntax gate does not remove the helper's equivalent check; the existing Node verifier is not already hardened by this decision.

For registration candidate keys, use the assessed public COSE decoder on the maintained verifier's returned representation, require EC2/P-256/ES256 and exact 32-byte coordinate strings, then validate the point through Node WebCrypto `subtle.importKey` as ECDSA/P-256, nonextractable, verify-only. The import does not establish possession or storage confinement. Keep the library-returned validated COSE representation for later verification and retain original registration evidence separately; no byte-identical extraction claim or custom CBOR parser. Raw CBOR acceptance remains the maintained verifier's parsing boundary, not a claimed independently strict CBOR gate or canonical-CBOR profile. No other component independently interprets raw attestation fields as authorization claims.

Activation uses the registration counter and backup eligibility in its original trusted context. Only final authorized commit applies its returned counter/backup update. Mandate issuance similarly updates exactly once by revision compare-and-update; later evidence rechecking uses stored original verification context, rechecks current identity/profile/status and never updates counters again. Synced zero counters remain allowed, never substituted for durable replay state.

## Decision 5: state/provider semantics and permitted scope

Adopt the [provider contract](provider-contract.md) as the portable interface proposal: independent non-expiring process ownership, fixed anchor/key/database write order, read-only reconciliation, no automatic partial-bootstrap recovery, one lifetime agent slot, and definitive reservation acknowledgement before one-use dispatch. Use the retained exact fixture/profile mappings rather than adding another crypto format. Test-only providers are explicit, isolated and unable to reach real credentials or a live adapter; they do not satisfy P06b and cannot become fallback.

The existing local-origin browser contract is unchanged. Future VM-to-host proposal transport must be designed separately from the protected localhost administration/approval surface; this packet does not expose an existing admin endpoint to the guest or grant setup permission.

## Finite acceptance record still required

Before P06a is accepted, one reviewed change must record these choices and reconcile the linked candidate documents where this packet resolves an earlier question. Bind the accepted record to exact document/fixture hashes, reviewed dependency versions and the following concrete remaining evidence:

1. Independent review of the fixed options table, bounded parser semantics, application/provider initialization and per-operation handle binding. The options choice and narrower branch subset are new decisions here, not already verified product behavior.
2. Independent review of current profile and registration vectors as conformance expectations, explicitly retaining their limitations. Registration transport fixtures/model share authorship, so compare them against the accepted table rather than claiming independent cryptographic evidence.
3. Document which strict-parser, callback-input guard, dual client-data gate and provider fault tests must accompany their implementation PRs. Their absent production implementations are not a reason to invent another pre-freeze spike; do not claim them passed. Any unresolved semantic contradiction must be fixed before the affected interface is frozen.
4. Exact-head required CI and dependency checks, with no suppression or reduced coverage policy, plus a separate acceptance decision. This document alone leaves P06a proposed and P07 blocked.

After that record, P07 begins with bounded application parsing and canonicalization against the accepted profile. Provider, helper and state implementation can follow the accepted interfaces in small independently reviewed PRs. Physical browser/native tests, usable deployment isolation and clean-machine packaging remain live/release gates, not reasons to defer portable contract review. No further human choice is needed for these proposed portable defaults unless review identifies a material trust-model change.
