# P06 candidate architecture

Status: **PROPOSED**, 2026-10-01. This package prepares P06 in parallel with P04b. It does not accept an ADR, freeze a protocol, complete P04/P06, or authorize P07 implementation. Existing experiments remain experiments. Read the [design baseline](../design-baseline.md), [helper assessment](../helper-assessment.md) and [candidate contract](mandate-contract.md) together.

## ADR candidate 1: ownership and evidence

Propose Rust-owned transport, enrollment, immutable operation construction, registry, clock, policy, issuer signing, reservation, audit and GitHub execution. A private, one-shot SimpleWebAuthn helper performs full WebAuthn verification against Rust-supplied expectations. Retain the tested launcher and bounded lifecycle rather than create another transport. Registration is a separate, not-yet-implemented helper operation.

The helper is trusted verification code. Rust rehashing an operation and checking response correlation is not independent signature verification. A malicious helper can lie; issuer signing does not repair that. A later verifier must use its own trusted WebAuthn implementation and registry to validate retained raw evidence. For the local v0 service, that trusted implementation is the helper. Its runtime, dependencies and installation/update integrity are release security dependencies.

Keep raw WebAuthn evidence in an issuer-signed envelope. Choose challenge binding to the entire canonical approval payload, rather than one ceremony authorizing an issuer key to sign arbitrary later mandates. Each consequential operation requires its own assertion. The issuer key provides local provenance, not a replacement for that assertion or an extra biometric identity claim. Issuer signing does not require a second Touch ID prompt by default; any change to that policy needs explicit review.

Reason: the custom-challenge experiments demonstrate a maintained public API and preserve library verification. The cost is a second runtime and a larger trusted computing base. An issuer-only alternative is simpler to verify but loses direct credential binding to each operation; it is not an automatic fallback.

## ADR candidate 2: narrow local authority

One mandate authorizes one exact GitHub PR merge by one enrolled agent key at one local executor. No wildcard, delegation chain, generic URL, arbitrary shell, MCP forwarding or OAuth endpoint. Read-only PR metadata remains a separate policy path. Simulation never calls the write adapter, and a simulated result is not evidence of a live merge.

Use a registered agent P-256 key and ES256 JWS for execution proof, sharing maintained JOSE primitives with issuer verification. This identifies the configured key holder, not a model, process identity or trustworthy agent. Agent key storage must not expose the executor's GitHub credential. The local executor must control the only write credential available in the demonstrated agent environment; a same-user agent with direct credential access can bypass it.

Enrollment is an explicit administrative ceremony outside agent tools. A protected local bootstrap creates executor/issuer/principal identities, then enrolls the passkey and agent public key. Agent-submitted public keys, origins, audiences, repository identities or helper outputs never become trust roots. Key replacement/rotation is a new administrative operation, not a claim made by a mandate. P04b assesses issuer-key protection, not the protection of every registry file or GitHub token.

## ADR candidate 3: reservation, not exactly-once execution

SQLite stores pending approvals, approved records, registry revisions, revocations, execution challenges and reservations. The authoritative key is `(issuer_id, mandate_id)`, not signature bytes: alternative ECDSA encodings/signatures must not create another execution slot. Persist the approved payload digest and envelope digest with that key. A different artifact for an existing key is an error, never an update.

Before dispatch, one transaction checks current identity/key status, revocations, policy revision, approved record, agent challenge and expiry, then consumes the execution challenge and reserves the mandate. Revocation committed first prevents reservation. Reservation committed first may proceed despite later revocation. No network or helper call occurs while holding that transaction; optimistic checks must fail if relevant state changes during verification.

The only write transition is `approved → reserved → succeeded | failed | unknown`. Every reserved record remains consumed, including definite failure. A timeout, crash after reservation or incomplete result becomes `unknown`; reconcile with read-only GitHub queries before proposing a fresh operation. Never release a reservation or retry a write automatically. A crash before dispatch may burn approval; this is preferable to a possible second merge request.

Pending ceremonies and outstanding execution challenges do not survive process restart. Candidate v0 also refuses pre-restart unreserved approvals, while retaining their IDs and all reservations. This conservative recovery policy avoids extending a short approval lifetime when monotonic time is lost. Detect backward wall-clock movement within a session and fail closed. Persist a wall-clock high-water mark and refuse authorization on startup below it; do not claim this detects arbitrary database or whole-machine rollback. A live authorization requires available, current state; offline inspection never grants execution.

## Evidence and acceptance gates

| Gate | Required evidence before acceptance | Current boundary |
| :--- | :--- | :--- |
| Helper architecture | Explicit acceptance of trusted helper; complete library checks, launch/runtime integrity plan, registration design | Assertion experiments support feasibility; no production enrollment |
| P04b | Restart lookup, denied access, locked-device behavior and signed identity/entitlement matrix on supported Mac | Ephemeral P04a success does not establish durability or access isolation |
| Canonical contract | Independent exact byte/hash/signature vectors and parser limits; resolve candidate details below | Documented candidate, no frozen vectors |
| Standards | Refresh dated source register and mappings before accepting P06 | Existing 2026-09-20 snapshot, no draft compliance claim |
| State/enforcement | Crash/concurrency/rollback tests, controlled GitHub credential, current API precondition assessment | Implementation follows P06; not supplied by signing or helper success |

P04b code and software tests can proceed concurrently with document review. Hardware identity, entitlement, restart and denial claims require actual results. P07 starts only after a follow-up accepted P06 change records the gate results and frozen vectors. Packaging can remain a documented release gate, but a usable protected issuer-key path cannot be presumed from temporary signing.

## Decisions and who can settle them

| Question | Proposed default | How to settle |
| :--- | :--- | :--- |
| Helper trust | Accept reviewed SimpleWebAuthn as trusted verifier, not independently verified by Rust | Architecture/adversarial review; ask user if this changes desired trust boundary |
| Durable issuer identity | Protected non-exportable Apple P-256 path, no silent software fallback | P04b physical evidence; user choice only if fallback or new distribution requirement is necessary |
| Signing identity availability | No assumption that a paid developer identity or entitlements are available | P04b inventory; ask before account/purchase/signing changes |
| Agent algorithm and lifetime | ES256; 120-second default, 300-second maximum | P06 review and vectors, within baseline scope |
| Restart recovery | Invalidate unreserved approvals; retain consumed state | P06 review and later crash tests; no manual reapproval bypass |
| Supported resources | github.com merge only, ASCII branch/display profile initially | Adapter/API assessment; explicitly reject unsupported inputs, do not normalize them |

No user decision is needed to review this proposal. A failed hardware gate must be reported rather than replaced with an unapproved trust model. These files intentionally add no production code or cryptography.
