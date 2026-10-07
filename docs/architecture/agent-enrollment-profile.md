# Candidate agent-enrollment proof profile

Status: **PROPOSED**, 2026-10-06. This fills one profile gap in [trusted enrollment](enrollment.md); it is not frozen, implemented or a Human Mandate. It does not accept P06, waive P04b, establish protected first administration or solve agent/admin isolation. It covers enrollment of a previously unknown agent key only. Credential replacement, agent rotation, recovery and disabling retain their separate design requirements.

## Parsing and candidate key

Apply the [mandate encoding conventions](mandate-contract.md#encoding-profile): exact required fields, duplicate decoded names rejected before map construction, no unknown fields, strict UTF-8 without BOM, no trailing non-whitespace, printable ASCII application strings, unsigned decimal integer tokens through 9,007,199,254,740,991 and canonical unpadded base64url. No coercion, arrays, nulls or alternate integer spellings. `id` and `b64(n)` retain their existing meanings. Byte limits below apply before parsing/decoding; object depth counts the root as one.

The candidate public JWK has exactly `kty: "EC"`, `crv: "P-256"`, `x: b64(32)` and `y: b64(32)`. Reject private fields, embedded metadata and invalid curve points through the selected maintained key library. Its standalone JSON is at most 512 bytes and one object deep. Compute `agent_jkt` with the existing public EC thumbprint convention, not an administrative hash domain. The candidate is untrusted until the complete administrative commit; possession alone never enrolls it.

## Immutable administrative proposal

Rust constructs proposal `A` only after a valid local `enroll_agent` administration capability claims one operation. Candidate input supplies only the public key; every identity, revision, timestamp, stage ID and nonce below is fixed by trusted local state. `A` has exactly:

| Field | Required value |
| :--- | :--- |
| `version` | Integer `1` |
| `operation` | Literal `enroll_agent` |
| `operation_id` | Fresh `id`, bound to the capability's one operation |
| `installation_id` | Existing installation `id` |
| `audience` | Existing local executor `id`, not a URL |
| `principal_id` | Existing enabled administrator principal `id` |
| `credential_id` | Exact enabled administrator credential, base64url of 1 through 1,024 bytes |
| `registry_revision`, `credential_revision`, `policy_revision` | Positive integer snapshots from trusted state |
| `agent_key` | Exact validated public JWK above |
| `agent_jkt` | Recomputed thumbprint, `b64(32)` |
| `ceremony_id` | Fresh `id` for the passkey-authorization stage |
| `nonce` | Fresh independent CSPRNG `b64(32)` |
| `issued_at`, `expires_at` | Integer Unix seconds; `0 < expires_at - issued_at <= 120` |

Maximum proposal JSON is 4,096 bytes, depth two. Fix its times before displaying it. Expiry may not exceed the original capability deadline mapped conservatively to wall time; if no positive interval remains, deny rather than renew. Both wall-time `issued_at <= now < expires_at` and the original local monotonic deadline must hold. Clock rollback and process restart fail closed under the existing proposal. The process-session binding remains trusted pending state, not a caller field.

Define exact bytes and challenge:

```text
authorization_digest = SHA-256(UTF8("vollmacht:admin:enroll-agent:v1") || 0x00 || JCS(A))
passkey challenge bytes = authorization_digest
```

The zero is one byte. Freshness comes from the included nonce and pending stage; never reuse a mandate digest, login challenge or execution proof. Retain exact proposal bytes/digest in the authorized pending operation. The fixed UI shows enrollment action, installation/executor, principal, credential reference, candidate key thumbprint and expiry. It must not render agent-authored explanatory HTML or describe enrollment as approval to merge.

## Passkey authorization then candidate possession

The stage order is `current_credential_authorization → candidate_possession → atomic commit`, all within the original 120-second capability lifetime. Each stage has a distinct fresh ceremony ID and single-use pending/verifying/completed state. Successful authorization does not refresh the capability or enable the candidate.

First verify a fresh assertion by the exact enabled credential against `authorization_digest`, using the existing raw-evidence field bounds and complete trusted-helper checks: expected challenge/origin/RP, signature, UP/UV, credential and user-handle association, counter and backup consistency, and the selected signed-client-data ambiguity policy. Preserve original signed bytes. This produces a pending authorization result only. Keep the original credential revision/counter context and proposed updates for final commit; do not overwrite registry state at this intermediate stage.

Only after that success, Rust generates a fresh 32-byte CSPRNG possession challenge and fresh stage ID. It fixes proof payload `B`, with exactly `version` (integer `1`), `operation` (literal `enroll_agent`), `operation_id`, `installation_id`, `audience`, `principal_id`, `agent_jkt`, `authorization_digest`, `ceremony_id`, `challenge`, `issued_at` and `expires_at`. IDs and thumbprint match `A`; `authorization_digest` is `b64(32)` of the value above. `ceremony_id` is the new possession-stage ID, not A's passkey-stage ID. `challenge` is `b64(32)`. Times form a positive interval of at most 30 seconds within A's interval, also capped by the unchanged monotonic capability deadline. Every field must exactly match the Rust-created pending proof context; the candidate cannot choose a shorter or different interval.

The candidate signs one compact ES256 JWS with protected header exactly `alg: "ES256"`, `typ: "vollmacht-agent-enrollment+jws"`, `kid: agent_jkt`, and embedded payload `JCS(B)`. Header and payload decoded bytes must equal their canonical representations. Verify the original compact signing input and a 64-byte `r || s` signature through maintained libraries. No detached/unencoded payload, critical extensions, key URL, header-supplied key or algorithm negotiation. This new candidate type is distinct from `vollmacht-execution+jws` and `vollmacht-mandate+jws`; none may substitute for another. There is no extra hash before the JOSE signing API.

Maximum compact proof is 8,192 ASCII bytes; decoded header is at most 512 bytes and depth one; decoded B is at most 2,048 bytes and depth one. Require exactly three nonempty canonical base64url segments, bounding each before decode against its decoded limit (signature exactly 64 bytes). The proof verifier resolves only the immutable candidate key stored with this authorized operation, not a key in the proof or an existing registry lookup inferred from its header.

The operator may relay public B to the candidate and return its proof through the capability-protected administrative flow. Never give the administration capability to the agent. This profile adds no agent-accessible bootstrap/reset endpoint and no new transport API. The candidate's valid signature proves possession for this pending operation, not administrator authority or a trustworthy agent implementation.

## Commit, failure and evidence

Claim each matching finish once before verification. A wrong capability or stale/unrelated stage ID cannot consume another operation. A failure on an authenticated, matching finish, cancellation, expiry, restart or helper failure consumes the whole operation; late successes cannot revive it. No retry with the same challenge or capability. No candidate mutation is permitted between the passkey approval, possession proof and commit.

In one serialized final transaction, recheck operation/stage ownership and completion, session and deadlines, installation identity, all captured revisions, current principal/credential enabled status, policy, proposal/digest equality and candidate key/thumbprint equality. Reject an already present thumbprint, including disabled records; this new-enrollment profile cannot act as rotation or reactivation. Atomically insert the enabled agent with principal/provenance association, apply the verified administrator counter/backup update by revision compare-and-update, increment affected registry revisions, and consume capability and stage challenges. Competing commits have one winner. Any changed snapshot requires a fresh operation; never silently rewrite A. Uncertain commit permits only read-only reconciliation, not a duplicate insertion.

Retain the canonical A/B, verified raw passkey evidence and original verification context, possession JWS and bounded provenance reference in protected enrollment storage. Routine audit records contain IDs/digests/transition results, not capabilities or raw assertions. This retention is a design requirement, not an implementation or proof of storage integrity. Nothing here grants a GitHub capability: future operations still require their own Human Mandate and execution proof.

Before acceptance, independently generate exact A/B/header bytes, domain bytes, digest, assertion and possession-signature vectors. Cover changed candidate/identity/revision, wrong stage/domain/type, valid execution-proof substitution, malformed/duplicate fields, altered signed bytes, missing possession or passkey authorization, exact expiry, cancellation/late completion and stale commit. Wire commands, protected bootstrap/installation anchor, concrete isolation/storage enforcement, replacement/rotation profiles, physical enrollment UX and all remaining P04b/P06 gates stay open.
