# P06 candidate architecture

Status: **PROPOSED**, revised 2026-11-01. The maintainer approved separating portable contract acceptance from deployment qualification. This changes sequencing, not the acceptance status of these ADR candidates: it does not freeze a protocol, complete P04/P06, or authorize P07 implementation today. Existing experiments remain experiments. Read the [design baseline](../design-baseline.md), [helper assessment](../helper-assessment.md) and [candidate contract](mandate-contract.md) together.

Follow-up proposals cover [trusted enrollment and recovery](enrollment.md), the [deployment/bootstrap decision ledger](deployment-bootstrap.md) and [GitHub merge preconditions](github-preconditions.md). The maintainer accepted the limited disposable-repository no-retargeting assumption for the first live demo on 2026-10-03; its safeguards remain unimplemented. This does not accept P06 or waive the remaining gates.

On 2026-11-01 the maintainer selected an isolated agent VM with the executor and approval UI on the host as the reference design direction. The concrete VM, communication path, shared-resource restrictions and bootstrap mechanism still require design and review. This selects neither a qualified implementation nor permission to configure a VM or change the host.

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

P06 now has two separately recorded acceptance decisions: P06a portable contract acceptance and P06b deployment qualification. Neither is accepted by this revision. A portable freeze permits implementation against a reviewed interface; it does not declare that a real deployment protects that interface.

| Gate | Required evidence before acceptance | What acceptance permits |
| :--- | :--- | :--- |
| P06a portable contract | Accepted ownership/evidence ADRs, exact schema and independent vectors, maintained-library assessment, enrollment and state/provider contracts, dated standards mapping | P07 and subsequent portable implementation, including test-only providers and a simulated executor |
| P06b deployment qualification | Accepted concrete isolation/bootstrap design, demonstrated agent denial of credentials/state/admin/runtime access, qualified real issuer provider, applicable physical P04b results | Real-provider operation and live-demo claims only after their integration and operation-specific gates also pass |
| Integrated state/enforcement | Crash/concurrency/restart/revocation tests, deadline checks, consumed-state retention and no automatic write retry | Milestone C acceptance; not implied by either document freeze or signature success |
| Live demo and release | Qualified deployment plus integrated browser/issuer evidence, controlled GitHub credential and current API precondition assessment; release additionally needs packaging/onboarding integrity | Milestone D live MVP and then milestone E experimental release, not GA |

Milestone A owns the portable decision and reference deployment design. Milestone B delivers the integrated simulated flow after the portable freeze; native qualification can continue alongside B and C. D and E cannot inherit protection claims from fake providers. Hardware identity, entitlement, restart and denial claims require actual results. A screen-lock observation alone does not establish Keychain lock behavior.

Test-only providers must be unmistakably scoped to tests or an explicitly simulated integration harness, use disposable synthetic identities/state, and have no live write adapter or real GitHub credential path. They are not a runtime fallback when a real provider fails. Simulation validates orchestration, not OS isolation, protected storage, physical user verification or a live merge. The issuer-signed envelope and per-operation WebAuthn evidence remain the candidate design; no signature layer is removed here.

### Remaining portable decisions and next bounded task

The next bounded task is a P06a portable acceptance packet, not production implementation. It must resolve or explicitly defer unsupported features with corresponding denial behavior:

1. Select and assess maintained JCS/JOSE implementations; freeze parser limits, ES256 encodings, domain-separated payload/envelope/agent proof fields and independently generated byte/hash/signature vectors from [the candidate contract](mandate-contract.md).
2. Accept the trusted-helper boundary and exact verification interfaces. Resolve signed-client-data ambiguity handling and retained assertion re-verification against original counter/backup context, without repeatedly mutating registry counters. Specify failure behavior and credential-ID equality at registration ingestion.
3. Freeze the minimum bootstrap, credential activation, agent enrollment and disable interfaces and administrative proof vectors. Decide which replacement/rotation proposals are deferred and rejected, rather than requiring their implementation for MVP. No caller-supplied trust roots or implicit enrollment.
4. Specify provider results and transaction invariants for issuer identity, installation anchor, registry revisions, pending ceremonies, execution challenges and durable reservations. Define bootstrap phase ordering and read-only reconciliation using abstract provider operations; physical storage mechanisms remain deployment qualification work. No assumed atomic transaction across providers.
5. Record the exact supported operation, display and TTL profile, the accepted disposable-repository no-retargeting limitation, and current standards mappings. Identify test-only substitutions and every claim they cannot support.

The packet needs independent adversarial review and an explicit acceptance record naming the frozen documents/vectors and permitted implementation scope. A remaining ambiguity in one of these security contracts is a blocker, not permission for an implementation to invent a default. Later contract changes require reviewed revisions and updated vectors. This is the gate for P07; P04b no longer blocks that portable freeze solely because physical qualification is pending.

## Decisions and who can settle them

| Question | Proposed default | How to settle |
| :--- | :--- | :--- |
| Helper trust | Accept reviewed SimpleWebAuthn as trusted verifier, not independently verified by Rust | Architecture/adversarial review; ask user if this changes desired trust boundary |
| Durable issuer identity | Protected non-exportable Apple P-256 path remains the candidate real provider, no silent software fallback | Portable review defines required provider semantics; P04b qualifies the real provider. Changing protection requirements or selecting an alternative requires a separate reviewed decision |
| Signing identity availability | No assumption that a paid developer identity or entitlements are available | P04b inventory; ask before account/purchase/signing changes |
| Agent algorithm and lifetime | ES256; 120-second default, 300-second maximum | P06 review and vectors, within baseline scope |
| Restart recovery | Invalidate unreserved approvals; retain consumed state | P06 review and later crash tests; no manual reapproval bypass |
| Supported resources | github.com merge only, ASCII branch/display profile initially | Adapter/API assessment; explicitly reject unsupported inputs, do not normalize them |

No user decision is needed to review this proposal. A failed hardware gate must be reported rather than replaced with an unapproved trust model. These files intentionally add no production code or cryptography.
