# Design baseline

This document records implementation targets, not implemented guarantees. Feasibility gates can change the design before the v0 protocol is frozen.

## Stack and boundaries

Use a Cargo workspace with crates for mandate core, WebAuthn, policy, storage, GitHub enforcement, and CLI. Keep the core independent of network and storage I/O. Supply time, trusted keys, and state through explicit interfaces. Use a small locally served HTML/JavaScript approval UI. Evaluate a Swift helper only if Rust's Apple API integration cannot provide a small, maintainable key-storage boundary.

Rust's memory safety does not establish correctness of authorization logic. Maintained libraries, negative tests, and adversarial review remain necessary.

## Approval and signature coverage

Split the format into an immutable approval payload and an evidence envelope. The payload includes a format version, random mandate ID and nonce, issuer and verifier audience, principal and registered credential reference, agent key thumbprint, exact action and resource, typed constraints, issue and expiry times, and a versioned human-readable display model.

Derive the WebAuthn challenge from a fixed domain separator and the RFC 8785 canonical payload bytes using SHA-256. The payload must never include its own hash, WebAuthn evidence, or issuer signature. Randomness in the payload makes the challenge unpredictable. Registration uses its own random challenge and protected enrollment flow.

The envelope carries the payload and raw WebAuthn evidence. An issuer JWS covers that envelope. The verifier resolves credential and issuer public keys from a trusted registry, not keys supplied by the agent or envelope. It recomputes the challenge and independently validates the WebAuthn assertion. Origin, RP ID hash, assertion type, challenge, UP and UV, and credential association are mandatory checks.

Do not reserialize clientDataJSON before checking the WebAuthn signature. Reject duplicate JSON keys, unsupported versions and algorithms, unknown security fields, oversized inputs, and ambiguous numbers. Use integer timestamps and string resource IDs. Freeze exact byte encoding and library behavior in protocol vectors.

The issuer signature aids local packaging and provenance; it is not independent evidence of a person's intent. Retained WebAuthn evidence does not prove what the person saw. The display model binding detects later mutation, but a malicious UI can still misrepresent it.

## Agent and policy

A registered agent identity refers to a public key. A signed execution request binds the mandate, operation digest, verifier audience, freshness, and a server challenge. Select an existing signature container and freeze its encoding in an ADR before implementing it. Possession of the key identifies the configured agent credential, not a particular model or trustworthy software.

V0 permits one exact operation per mandate, no wildcards and no subdelegation. Default TTL is 120 seconds, maximum 300 seconds; pending approvals expire after 120 seconds and require a new proposal. The verifier checks time at dispatch and uses server-side pending state to limit clock rollback effects. Persisted rollback detection and restart behavior need tests before release.

Policy evaluates to deny, allow read-only, or require mandate. Local policy can narrow approval but cannot expand it. Changes to policy or credential enrollment require a trusted administrative path unavailable through agent tools. No generic HTTP forwarding, shell execution, GraphQL passthrough, or gh command passthrough is exposed.

## State, revocation, and failures

Persist pending approval, credential status, mandate revocation, and execution state in SQLite. Reserve a mandate atomically before dispatch. The state machine is approved, reserved, then succeeded, failed, or unknown. A reserved mandate cannot be reused even after a crash or timeout. Persist the reservation before the network request.

Exactly-once remote execution is not promised. A timeout may mean GitHub completed the operation. Reconcile remote state before proposing another approval; never automatically retry a write. Read-only queries may retry with bounded backoff. Record errors without secrets and distinguish expired, revoked, invalid evidence, agent mismatch, policy denial, replay, stale resource, and unknown remote result.

Revocation is local. Check mandate revocation, credential and agent status, and policy version in the same serialized authorization decision that reserves the mandate. Reservation is the revocation cutoff: revocation that commits first prevents reservation; reservation that commits first may proceed even if revocation arrives before network dispatch. Revocation cannot reliably recall an authorized remote operation. Credential disabling and agent-key rotation invalidate mandates that have not yet been reserved. A verifier without current revocation and replay state may inspect evidence but must not authorize execution. Tests must exercise both orderings of concurrent revocation and reservation, including credential disabling and agent-key rotation.

Audit events record the operation digest, mandate ID, policy decision, lifecycle transition, and sanitized GitHub result. Local hash chains cannot prevent deletion, rollback, or rewriting by a local attacker. Keep assertion evidence out of routine logs and define retention/export separately.

## GitHub demo

Use an explicitly selected disposable repository and a documentation-only PR. The first low-risk operation is reading PR metadata. Commenting is deferred because writes are not automatically low risk.

Approve repository identity, PR number, expected head SHA, base branch, and merge method. Confirm the GitHub merge API's current precondition guarantees before implementing the adapter. Bind the expected head SHA in the actual API request. A preflight read alone is insufficient. Document any base-branch race the API cannot atomically prevent; require repository rules where needed rather than claiming complete TOCTOU protection.

Default demo mode is simulation. Actual mutations require an explicit live command and a repository marker established during deliberate fixture setup. No repository deletion, secrets changes, branch protection changes, workflow dispatch, or release publishing in the initial demo. No automatic cleanup that destroys user data.

## Feasibility gates

1. Prove platform WebAuthn on localhost with exact origin/RP validation in Safari and Chrome, including cancel, missing UV, wrong challenge, and replay. Physical Touch ID interaction requires the user. If one browser fails, document a narrower support matrix. If localhost fails entirely, investigate local HTTPS and its trust setup as a separate change; do not silently replace WebAuthn with a biometric API.
2. Prove protected P-256 issuer-key creation and signing with Apple APIs, including cancellation and signature encoding. Prefer non-exportable key material; distinguish Secure Enclave backing from ordinary Keychain storage. If hardware requirements cannot be met, document the limitation before choosing a fallback.
3. Confirm a maintained Rust WebAuthn implementation supports the required challenge binding, registration policy, stored state, and validation. Do not bypass library validation to force compatibility.

## Standards documentation gate

Recheck primary Datatracker and RFC sources before drafting standards claims. The conversation's research summary is a lead, not a verified repository artifact. Record exact draft names, authors, versions, document dates, status, retrieval date, field mappings, and gaps. Cover AAE, agentic trust, OAuth actor/delegation chains, authorization evidence, transaction tokens, GNAP, WebAuthn/FIDO boundaries, and x401 separately. Clearly distinguish individual submissions, WG drafts, published RFCs, and external projects. Never claim conformance without implementation and tests.
