# Candidate Human Mandate contract

Status: **PROPOSED**, 2026-10-01. This is an exact candidate for review, not a frozen schema or implemented API. Acceptance requires [P06 gates](README.md#evidence-and-acceptance-gates), independent vectors and library assessment. Names and limits may change before acceptance; do not make artifacts or integrations depend on them yet.

## Encoding profile

All application objects have exactly the listed fields, all required. Reject unknown/duplicate fields, invalid UTF-8, BOM, trailing non-whitespace bytes, invalid escapes/surrogates, arrays, nulls and wrong types before canonicalization. Decoded application strings are printable ASCII unless their field has a narrower grammar. Integers are decimal tokens without sign, fraction, exponent or leading zero, and at most 9,007,199,254,740,991. These are deliberate v0 restrictions, not general JCS rules. No Unicode normalization, trimming, lowercasing or coercion on input.

Use a maintained implementation of [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) after strict schema validation. JCS determines canonical UTF-8 bytes; it does not authorize input or reject all invalid application values. Maximum payload 8,192 bytes, decoded envelope 65,536 bytes, compact issuer JWS 100,000 ASCII bytes, nesting eight objects. Bound encoded fields before decoding. `b64(n)` means canonical unpadded base64url decoding to exactly n bytes; ranged bounds are decoded bytes. Require decode/re-encode equality. `id` means 32 lowercase hexadecimal characters, generated from 16 random bytes for local identities/mandate IDs. Nonces use 32 fresh CSPRNG bytes, never derived from IDs or timestamps.

These limits do not apply the ASCII/unknown-field restrictions to the *contents* of signed WebAuthn byte strings. Those retain their original bytes and require the selected WebAuthn verifier's standards-aware parsing and an explicit ambiguity policy reviewed in P06. Never canonicalize signed client data to make it fit this application profile.

## Approval payload

Exact top-level fields:

| Field | Candidate rule |
| :--- | :--- |
| `version` | Integer `1` |
| `mandate_id` | Fresh `id` |
| `nonce` | `b64(32)` |
| `issuer_id`, `audience` | Local registered `id`; audience identifies one executor/state authority, not a URL |
| `principal_id` | Registered local `id`, not a verified civil/biometric identity |
| `credential_id` | Base64url, 1 through 1,024 bytes, exact enrolled credential ID |
| `agent_jkt` | `b64(32)` SHA-256 JWK thumbprint of enrolled agent key |
| `policy_revision` | Positive integer matching the approval policy snapshot |
| `issued_at`, `expires_at` | Integer UTC Unix seconds, with `0 < expires_at - issued_at <= 300` |
| `operation` | Exact operation object below |
| `display` | Exact display object below |

`issued_at` is fixed when constructing the proposal, before displaying it. Default expiry is `issued_at + 120`; approval cannot extend it. Pending ceremony monotonic deadline is at most 120 seconds and at most the remaining payload TTL. Issuance and dispatch both require `issued_at <= now < expires_at`, with no positive expiry grace. Record process-session identity and monotonic deadline locally, never supplied by the agent.

`operation` has exactly `action`, `resource`, `constraints`. `action` is the literal `github.pull_request.merge`. `resource` has exactly `host` (literal `github.com`), `repository_id` (positive decimal string, 1 through 20 digits, no leading zero), and `pull_request_number` (positive integer at most 2,147,483,647). Local adapter resolution must confirm the numeric repository ID rather than trust an owner/name path.

`constraints` has exactly `expected_head_sha` (40 lowercase hex characters), `base_ref` (1 through 255 printable ASCII bytes, valid Git branch name and no ambiguous control characters), and `merge_method` (one of `merge`, `squash`, `rebase`). No caller-supplied merge message, automatic branch deletion, alternative endpoint or API option is permitted. Repository rules and supported methods may further restrict the operation. Changed head, repository, base or method requires a new proposal. The adapter must verify current API capabilities before these choices are frozen; this candidate does not assert that GitHub atomically enforces base-branch equality.

`display` has exactly `version` (integer `1`) and `repository` (1 through 201 ASCII bytes matching an owner/name pair of nonempty `[A-Za-z0-9_.-]+` components). Rust obtains this label from trusted adapter resolution of the same repository ID. The UI renders a fixed template displaying the repository label and numeric ID, PR number, head SHA, base, method, agent thumbprint, principal reference and expiry directly from payload fields. No agent-supplied explanatory HTML, PR title or free-form approval message. Escape all displayed values. The label is not routing authority; a renamed/transferred repository requires renewed preflight and a new proposal, not silent relabeling.

The [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) thumbprint is a key identifier, not enrollment or proof of possession. Restrict agent keys to validated P-256 public keys. Compute the SHA-256 thumbprint using that RFC's public EC member set; resolve it only through the trusted agent registry.

## Digests and WebAuthn binding

Define `P = JCS(payload)` and `O = JCS(payload.operation)`. Fixed domain bytes include one terminal zero byte, not the two printable characters backslash and zero:

```text
mandate_digest = SHA-256(UTF8("vollmacht:mandate:v1") || 0x00 || P)
operation_digest = SHA-256(UTF8("vollmacht:operation:v1") || 0x00 || O)
WebAuthn challenge bytes = mandate_digest
```

Challenge transported to the helper is `b64(mandate_digest)`. There is no separate nonce concatenation: the random nonce is already inside P. The payload contains neither its digest, assertion nor issuer signature. Registration uses a fresh independent random challenge and a distinct authorized pending enrollment, never this mandate construction. Experiment domains and opaque operation bytes are incompatible with this candidate.

## Evidence and issuer envelope

Envelope has exactly `version` (integer `1`), `payload` (above) and `evidence`. `evidence` has exactly `kind` (literal `webauthn.get`), `credential_id`, `client_data_json`, `authenticator_data`, `signature`, and `user_handle`. Credential ID matches payload/enrollment. Remaining byte strings are unpadded canonical base64url with bounds: client data 1 through 12,288, authenticator data 37 through 8,192, signature 1 through 1,024, user handle 0 through 64. Empty user handle means absent; a present value must exactly match enrollment. Preserve all signed bytes. Browser id/rawId must match at ingestion; one canonical credential ID is retained. Browser extension results are not authorization inputs.

The issuer artifact is a single [RFC 7515 compact JWS](https://www.rfc-editor.org/rfc/rfc7515.html) with embedded payload `JCS(envelope)`. Its protected header has exactly `alg: "ES256"`, `typ: "vollmacht-mandate+jws"`, and `kid` (registered issuer key `id`). Require canonical header/envelope bytes after decoding, not just semantic equality; verify the original compact signing input. No detached content, embedded key, key URL, unprotected header, algorithm negotiation or critical extension. Apply [RFC 7518 ES256 encoding](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4), including 64-byte `r || s`, through maintained libraries. These private type labels are not claimed registered standards profiles.

Trusted registry maps issuer ID plus kid to an enabled public key and local signing provider; credential ID to principal, ES256 COSE key, RP ID/origin, user handle, counter, backup eligibility/status and revision; agent thumbprint to enabled key and revision. Enrollment and replacement require protected administration. Every record has locally authenticated provenance, not just JSON containing a public key. Storage protection and recovery are implementation/security gates, not properties of these fields.

Helper verifies `webauthn.get`, exact expected challenge/origin/RP, signature, UP and UV, enrolled key association, counter and backup consistency. Require no cross-origin ceremony: `crossOrigin` absent or false and no `topOrigin`. Prefer registered-credential selection so credential identity is fixed before challenge generation. Expected RP and origin come from executor configuration/registry, never from evidence. Candidate local origin is `http://localhost:8374`, RP `localhost`, matching the experiment; changing either requires a reviewed profile change and migration, not an agent input.

Commit counter/backup updates once at issuance with a serialized credential-revision compare-and-update. Final execution rechecks current credential status and validates retained assertion cryptography against the original stored verification context, not the already-incremented counter. Persist that context with the approved record; only the local issuer creates it. Re-verifying an assertion cannot repeatedly update its counter or approve another mandate. If the library cannot safely express this evidence recheck, resolve it in P06 rather than skipping verification or mutating current registry state. An imported signed artifact without its trusted local approval record cannot execute in v0.

## Agent execution proof

Agent submits a separate compact ES256 JWS. Exact protected header: `alg: "ES256"`, `typ: "vollmacht-execution+jws"`, `kid` equal to enrolled `agent_jkt`. Exact canonical payload: `version: 1`, `mandate_digest`, `operation_digest`, `envelope_digest`, `audience`, `challenge`, `issued_at`, `expires_at`. All digests/challenge are `b64(32)`; audience equals mandate audience. `envelope_digest = SHA-256(UTF8("vollmacht:envelope:v1") || 0x00 || JCS(envelope))`, independent of potentially nonunique issuer signature bytes.

Executor generates a fresh random challenge, bound in pending state to all three digests, audience and agent key. Lifetime is at most 30 seconds and no later than mandate expiry; timestamps and monotonic checks follow the approval rules. Proof times must lie within that pending lifetime. Maximum compact proof is 8,192 bytes. Verify proof using registry key, never a header-supplied key. Consume its challenge in the reservation transaction. Failed proof attempts consume that pending challenge; a fresh challenge may be requested only while the mandate remains approved and unexpired, subject to rate limits. Artifact theft without the enrolled agent key does not authorize execution.

## Verification and errors

1. Bound and strictly parse JWS, header, envelope and payload. Check supported version/type/algorithm, canonical bytes, size and time.
2. Resolve enabled issuer and trusted local approval record. Verify issuer signature; match stored mandate/envelope digests. Resolve principal, credential, agent and audience independently.
3. Recompute challenge and verify raw evidence through the trusted helper, using stored original counter context. Recheck all registry revisions after helper completion. A helper error is denial, never issuer-only fallback.
4. Verify agent proof and bound execution challenge. Re-evaluate current policy; revision mismatch requires new approval. Policy can narrow, never widen. Resolve fresh GitHub metadata and check exact approved operation, including fixture marker for a live demo.
5. In one serialized reservation transaction, recheck relevant status/revocation/policy revisions, time, session identity and pending challenge, then persist reservation. Dispatch only the fixed adapter request. Recheck local deadline immediately before dispatch; if expired, mark the consumed reservation failed without sending. Bind the head SHA in the actual API request. Document remaining remote-state races.
6. Persist a sanitized result or unknown outcome, never return a reservation to approved. Audit digests/IDs, policy decision and transitions, not raw assertions, tokens or sensitive helper diagnostics. Local audit cannot prove resistance to deletion or rollback.

Fixed external denial categories: `invalid_format`, `unsupported_profile`, `untrusted_identity`, `invalid_evidence`, `agent_mismatch`, `expired`, `revoked`, `policy_denied`, `replay`, `stale_resource`, `state_unavailable`, `remote_result_unknown`. No raw parser/crypto/OS/helper errors in the agent API. The trusted local diagnostic path may distinguish bounded helper failure codes without exposing evidence. All failures deny new execution; unknown remote result does not mean the remote operation failed. Cancellation consumes the pending approval ceremony.

## Freeze checklist and adversarial vectors

Publish independent fixtures before accepting this contract: original payload bytes, canonical P/O/envelope, exact domain bytes, expected digests, trusted public keys, original assertion bytes, protected JWS bytes and expected outcome. Generate with a second implementation, not an expected-value function shared with the code under test. Test JSON key order/whitespace and escapes, duplicate escaped keys, boundary integers, Unicode rejection, payload/evidence mutation, algorithm/header confusion, unsupported COSE key, tampered origin/RP/UP/UV, counter reuse, synced-passkey cases, stale registry, wrong agent/audience/challenge, TTL equality, reservation/revocation races, restart and nonunique signature encodings.

Before live approval, resolve the base-branch retargeting race: establish an atomic remote precondition, reject the unsupported live operation, or explicitly accept and describe the residual limitation through architecture review. Documenting a race alone does not enforce `base_ref`; never claim exact base equality without an effective precondition.

Select and assess maintained JCS/JOSE libraries and WebAuthn signed-client-data ambiguity behavior before freeze. Registration's complete evidence and trust-bootstrap protocol is a separate required P06 artifact; this assertion contract does not invent it. Refresh [standards mappings](../standards.md) before acceptance. The primary RFC links above were consulted on 2026-10-01 for building-block semantics; no current IETF agent-draft compatibility is claimed.
