# Candidate registration verification helper interface

Status: **PROPOSED**, 2026-11-01. This specifies a private registration-verification message for P06a review, not an implemented helper, accepted contract or enrollment service. Read with [enrollment](enrollment.md), [cryptographic profiles](crypto-profiles.md) and the [experimental assertion protocol](../../spikes/helper-protocol/README.md). Synthetic verification cannot establish physical user verification, authenticator provenance or protected administration.

## Version and ownership boundary

Reserve protocol `version: 2` exclusively for `verify_registration` and its result. Existing assertion requests/results remain version 1 with their existing exact field sets. Version 2 does not accept assertion requests; version 1 does not accept registration requests. Select the supported operation from trusted coordinator configuration and pending stage, never by trying another decoder after rejection. The present helper implements neither this version nor its registration operation.

Rust owns protected bootstrap authorization, immutable expectations, candidate storage, stage deadlines, cancellation, registry uniqueness and final commit. The helper owns complete maintained-library registration verification against those expectations. It cannot enroll a credential or create authority. Correlated helper output is trusted verification testimony, not independent Rust signature verification.

This interface does not generate browser creation options. Before implementation, a separate reviewed decision must fix their generation boundary and exact option shape. Regardless of that choice, Rust fixes the challenge, user handle, RP/origin and ES256-only policy; any generated options must match those values and require platform selection, UV and the enrollment profile's resident-key preference and `attestation: none`. No library-generated default may broaden the algorithm list. The registration response does not authenticate a user handle: its association comes from the protected pending bootstrap operation, not a returned helper field.

## Framing and bounds

Reuse the existing one-request/one-response child lifecycle: four-byte big-endian length, UTF-8 JSON body of 1 through 65,536 bytes, stdin EOF, bounded stdout/stderr, zero exit and EOF before success, 5,000 ms child budget capped by the ceremony deadline, and existing bounded cleanup/fail-closed behavior. No network helper endpoint, log output, retries or secret arguments. A supported-version change does not relax launch integrity or descriptor controls.

Apply the existing strict outer JSON rules: reject unknown, missing or duplicate decoded members, invalid UTF-8, BOM, invalid surrogates, trailing data, nulls and wrong types; maximum eight containers. Integers have unsigned decimal lexical form without fractions/exponents. All outer strings are ASCII. Base64url is canonical and unpadded, checked before and after decoding. The entire frame limit applies even when individual fields fit.

The following new limits are proposed, not established browser compatibility: attestation object 1 through 16,384 decoded bytes; returned COSE public key 1 through 4,096 bytes. Credential ID and client-data limits reuse existing protocol bounds. Test exact encoded and decoded boundaries before accepting these limits. Oversize evidence rejects rather than increasing a limit or truncating it silently.

## Request: exact fields

| Field | Required value |
| :--- | :--- |
| `version` | Integer `2` |
| `kind` | Literal `verify_registration` |
| `request_id` | Fresh Rust-generated 16 random bytes encoded as 32 lowercase hexadecimal characters |
| `crypto_profile` | Literal `vollmacht-local-es256-v1`, from trusted pending bootstrap policy |
| `challenge` | Base64url of the pending fresh 32-byte registration challenge |
| `rp_id` | Literal `localhost` |
| `origin` | Literal `http://localhost:8374` |
| `registration` | Exact object below |

`registration` contains exactly `id`, `raw_id`, `type`, `client_data_json` and `attestation_object`. Both IDs are base64url of 1 through 1,024 bytes; `type` is `public-key`; client data is base64url of 1 through 12,288 bytes; attestation object uses the bound above. Browser transports, extension-result hints and attachment claims are not authority and are not transported. Signed authenticator extensions stay in the original attestation bytes for library processing; no extension-dependent feature is supported.

Rust constructs expectations from its claimed pending stage, not from browser or agent fields. It retains the original bounded evidence separately. The request ID maps privately to the installation, principal, user handle, operation/stage IDs, policy/registry revisions and original deadline; those do not become caller-controlled helper options. A matching response cannot change that context.

## Verification and raw-byte preservation

Before sending a request, Rust applies the [assessed client-data syntax gate](../../spikes/helper-protocol/CLIENT-DATA.md) to decoded `client_data_json`: one object, valid UTF-8, no BOM, no duplicate decoded keys at any depth, valid surrogates, no trailing data, at most 12,288 bytes and 16 nested containers. Preserve valid whitespace, ordering, escaping and unknown fields under that gate's compatibility policy, including its finite-number restriction. The helper independently enforces that same syntax policy before parsing security fields; adoption requires cross-runtime agreement tests, not an assumption that ordinary `JSON.parse` satisfies it. Neither side reserializes the signed data.

The helper requires browser `id == raw_id`, `crossOrigin` absent or false, and `topOrigin` absent. Invoke the maintained registration verifier with exact expected challenge, origin, RP ID, type `webauthn.create`, UP and UV required, and `supportedAlgorithmIDs: [-7]`. Library success must include verified user verification and the expected origin/RP. Reject an absent or inconsistent successful result.

Validate the returned credential key as COSE EC2/P-256/ES256 with valid curve coordinates through maintained public-key validation, not only labels and coordinate lengths. Require the returned authenticator-derived credential ID to equal both browser IDs byte-for-byte after canonical decoding. The [identity-binding assessment](../../spikes/simplewebauthn/REGISTRATION-BINDING.md) demonstrates that the selected library does not itself enforce this three-way equality. Return the maintained verifier's validated COSE key representation. SimpleWebAuthn 14.0.3's `parseAuthenticatorData` decodes and re-encodes the credential key before returning it; these bytes are not guaranteed identical to its original encoding inside the attestation object. Preserve the original attestation object and client data separately as evidence; never replace them with this returned key representation. Exact original credential-key subbytes are not required by this interface and would need a separate library-API assessment, not a bespoke CBOR extractor. Reconcile earlier enrollment wording about raw public-key bytes with this distinction before P06a acceptance.

This narrow proposal accepts only verified attestation format `none`, consistent with the requested creation option; other formats reject without fallback. This is an explicit local restriction requiring compatibility review, not a claim that WebAuthn universally requires that response format. No AAGUID, attachment or attestation metadata becomes a trust root. `none` attestation does not prove possession of the candidate private key; activation remains mandatory.

Derive backup eligibility/status only from the verified library result. Reject an unknown device-type result or `backed_up: true` with `backup_eligible: false`. Require a counter in 0 through 4,294,967,295. Synced passkeys remain permitted; a zero counter is not replay protection. No database, counter or enrollment mutation occurs inside the helper.

## Response: exact alternatives

Every response contains `version: 2`, `kind: "registration_result"`, and the request's exact `request_id`, `crypto_profile` and `challenge`.

- Success adds `outcome: "verified"` and `credential`. That object contains exactly `id`, `public_key`, `counter`, `backup_eligible` and `backed_up`, with the bounds and types above. Its ID is the extracted credential ID, not an unverified browser copy.
- Rejection adds only `outcome: "rejected"` and `code: "verification_rejected"`.

Reject mixed alternatives, surplus fields, invalid backup combinations, invalid encodings and mismatched correlation/profile/challenge. No raw evidence, attestation metadata or library diagnostics are echoed. Invalid framing, version, operation or request schema yields no response and nonzero exit. A structurally valid request whose evidence fails any semantic, syntax-gate or cryptographic check yields the fixed rejection result and zero exit. Both outcomes deny enrollment. Malformed helper output, late success, nonzero exit or incomplete cleanup cannot become candidate acceptance.

Rust rechecks the original deadline, capability scope, active stage, cancellation and captured policy/registry revisions after complete helper success. It also checks returned ID equality and credential-ID uniqueness across enabled and disabled registry records. Only then may it store a pending candidate. A helper result never supplies administrator authority or bypasses the atomic bootstrap commit requirements.

## Activation and retained evidence

Activation reuses assertion protocol version 1 unchanged. Rust supplies only the pending candidate ID/key, registration counter and backup eligibility, plus its trusted user handle and a fresh independent activation challenge. The challenge is state-bound to the exact candidate and operation. Successful activation updates the candidate's counter/backup state only in the final authorized commit; it does not renew the administrative deadline. Cancellation or failure consumes the operation even if a passkey already exists in the authenticator.

Retained assertion rechecking also reuses version 1 with trusted original verification context, not current advanced counters or agent-provided historical data. Rust separately enforces the current allowed crypto profile, identity/status/revisions and reservation policy and never updates counters from a recheck. No new assertion field or mode is inferred. Registration and assertion ingestion must both apply the reviewed raw-client-data gate before production reuse; the existing helper and gate experiments do not already provide that integration.

## Acceptance evidence still required

Before adopting this contract, independently review the version split, new attestation bound, `none`-only restriction, option-generation boundary and actual library/key-validation APIs. Freeze independent positive and negative request/result fixtures. Exercise wrong version/kind/profile, ambiguous outer JSON, encoded/decoded size boundaries, trailing frames, wrong correlation, triple-ID mismatch, unsupported/malformed/off-curve keys, wrong challenge/origin/RP/type, missing UP/UV, invalid backup flags and counters, and registration client-data gate disagreement. Test raw-byte preservation and non-registration evidence substitution.

Controller integration later must cover stale revisions, duplicate IDs, concurrent bootstrap, helper success after cancellation/expiry, candidate-only activation, wrong-key activation, and commit failure without enabled authority. These are implementation acceptance tests, not prerequisites to writing the reviewed interface. Physical browser confirmation of the new enrollment flow, actual storage protection and native provider qualification remain separate deployment gates. This document freezes none of them.
