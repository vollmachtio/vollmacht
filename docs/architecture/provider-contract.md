# Candidate provider and bootstrap contract

Status: **PROPOSED**, 2026-11-01. This supplies the missing abstract provider/state portion of P06a for review. It accepts no ADR, freezes no API and implements no provider. Read with the [mandate contract](mandate-contract.md), [enrollment proposal](enrollment.md) and [deployment boundary](deployment-bootstrap.md). P06b must separately qualify the actual storage, issuer and VM/host mechanisms. Test providers cannot qualify them or serve as production fallback.

Scope is one installation, principal, active passkey and enrolled agent, with the existing exact merge action. Credential replacement, agent rotation, migration, backup restore and reset are unsupported. Disabling narrows authority and never deletes consumed state. Interface names below describe trusted in-process operations, not agent-accessible HTTP commands or a new wire protocol.

## Common provider rules

Every operation uses an executor-configured provider namespace and bounded typed inputs. Callers cannot select a path, account, key tag, database or provider through mandate fields. Installation/issuer/executor/principal IDs use the existing `id` profile; revisions are positive bounded integers that reject overflow rather than wrap. State and issuer binding reads return a coherent snapshot or an error, not partially trusted records.

Use typed results:

| Result | Meaning and required caller behavior |
| :--- | :--- |
| `present(value, revision)` | Verified provider lookup succeeded; caller still checks expected bindings and state |
| `absent` | Definitive lookup absence in the configured namespace; not permission to initialize or proof that no installation ever existed |
| `committed(receipt)` | Mutation durably acknowledged under the provider's documented crash model; receipt identifies the exact operation and resulting revision |
| `conflict` | Expected revision/state differs; no mutation from this call; restart the enclosing authorization only with fresh approved context |
| `denied`, `unavailable`, `invalid_state` | No authorization may proceed; these are never treated as absence |
| `indeterminate(operation_id)` | A mutation may have committed, but no definitive acknowledgement is available; do not repeat it or report success; allow only read-only reconciliation |

A provider must not label an uncertain mutation as a definite no-write failure. Receipt and operation IDs are correlation data, not bearer authority. Reads after an indeterminate result must consult authoritative durable state, not a stale cache. There is no generic retry wrapper. Public API errors remain the bounded categories in the mandate contract; provider detail belongs only in redacted trusted diagnostics.

The service holds one exclusive executor lease for its configured namespace before startup reconciliation or mutation, including first bootstrap. Lease acquisition is independent of database existence and cannot implicitly create an anchor, key or database. Its independently configured ownership mechanism must provide non-expiring OS process ownership: no deadline, heartbeat timeout or stale-owner heuristic may transfer ownership while the old process is alive, including when suspended. A second process fails acquisition rather than waiting for a timeout that could leave an old dispatch permit usable.

The lease handle is private to the coordinator and must not be inherited by helpers, children or the agent. It remains held through all tasks that can dispatch, including cancellation and shutdown cleanup. Voluntary release is allowed only after all such tasks have quiesced and every in-memory dispatch permit is invalidated; otherwise ownership ends only at process exit. Unexpected loss stops new authority and dispatch and fails qualification if another process could acquire ownership while an old task can still dispatch. This lease cannot exclude a compromised administrator or remote GitHub writers. No provider call may silently create missing storage on open.

## Abstract operations

| Provider | Operations and constraints |
| :--- | :--- |
| Executor lease | `acquire_exclusive(configured_namespace)` returns a private process-owned handle or a bounded failure; it does not require or create the database. A conflicting live owner denies acquisition. `release_quiesced(handle)` is permitted only under the shutdown rules above. No renewal, expiration, takeover or caller-selected namespace |
| Installation anchor | `inspect()`; `claim_absent(operation_id, identities)`; `bind_key(expected_revision, operation_id, public_key_binding)`; `mark_ready(expected_revision, operation_id, bootstrap_commit_id)`. Mutations are create-only or compare-and-set, monotonic through `claimed → keyed → ready`; no delete, rewind or repin operation |
| Issuer | `inspect_namespace()` returns absent, exactly one bound key, or invalid/ambiguous state; `create_once(bootstrap_operation_id, identities)` only after durable anchor claim; `open_exact(binding)`; `sign_exact(handle, signing_input)` using the reviewed ES256 interface. No export, replace, delete, key discovery from a request or automatic create-on-open |
| State store | `open_existing()`; `create_once(bootstrap_operation_id, identities, key_binding, process_session, wall_high_water)` after durable keyed anchor; `snapshot()`; scoped transactions below; `lookup_operation(operation_id)` for read-only reconciliation. Creation atomically persists the initial bootstrap process session and clock mark with prepared state. No arbitrary upsert, import, reset or deletion of mandate IDs |
| Session clock | `sample()` supplies wall and monotonic time for the current process session; service compares against prior samples and durable wall high-water mark. Restart creates a fresh session identity; no caller-supplied clock or session |

`public_key_binding` contains installation ID, issuer ID, configured provider reference and validated public P-256 key. The provider reference is an opaque configured locator, not authority or a filesystem path. Retain and compare the full public key; a displayed fingerprint is diagnostic, not a replacement for this comparison. The ready anchor also pins executor/principal identities and the immutable bootstrap commit ID. It does not mirror every registry revision or claim to detect every older database.

The issuer provider establishes key identity and signs exact bytes; the trusted coordinator supplies policy enforcement. An opaque key handle alone is not a capability safe to expose to an agent. Only the reviewed issuer path may call it after full approval verification. A real provider must meet the accepted confinement requirements; an in-memory fixture key demonstrates only interface behavior.

## Bootstrap write order

Bootstrap begins only through the protected, operation-scoped administrative flow described in enrollment. The trusted operator authorizes initial setup, and all three providers must report definitive absence in the configured namespace. Absence alone cannot prove freshness after privileged deletion. P06b must establish that the demonstrated agent cannot erase all three stores or select another namespace; otherwise fresh setup cannot be distinguished from reset. Do not infer that guarantee from an empty directory.

Generate one bootstrap operation ID and immutable identities in memory. The capability, pending registration/activation stages and their original deadline remain session-bound. Perform the following sequence without holding a database transaction across issuer or browser calls:

| Step | Durable state after acknowledgement | Next permitted action in the same uninterrupted bootstrap |
| :--- | :--- | :--- |
| 1. Claim absent anchor | Anchor `claimed`, identities and bootstrap operation ID retained | Create the dedicated issuer key once |
| 2. Create issuer key | Key bound to those identities and operation ID | Validate returned public key and bind it to the anchor |
| 3. Bind anchor key | Anchor `keyed` with immutable public-key binding | Create state store once with matching identities/binding |
| 4. Create state store | Database `prepared`, bootstrap operation ID, binding, current process session and sampled wall-clock high-water mark retained atomically; no enabled principal | Run registration and candidate activation under the original administrative deadline |
| 5. Commit principal | One database transaction records verified enrollment/provenance, activation counter and bootstrap commit ID; database `principal_committed` | Mark the matching anchor ready |
| 6. Mark anchor ready | Anchor `ready` pins the database bootstrap commit ID | Re-read matching anchor/key/database; only then report bootstrap success |

The system is initialized only when the ready anchor, exact issuer key and `principal_committed` database agree on all identities, key binding and bootstrap commit ID. `principal_committed` is not independently sufficient to issue authority. No separate database ready write is needed. New-agent enrollment is a later scoped administrative operation and must complete before any merge mandate can issue.

Registration and activation must finish within the original capability deadline. Step 5 rechecks that deadline and consumes authorization atomically; steps 6 and the final read can only finish publication of that already committed bootstrap, not enroll another principal or renew the capability. If publication fails or its result is uncertain, stop. No background retry completes it later. A new session may only inspect and report the persisted state under the rules below.

Cancellation, expired ceremony, issuer failure or interruption after step 1 may leave an intentionally blocked installation. Do not erase the anchor/key/database, repeat creation or start replacement bootstrap. A future separately reviewed recovery procedure is outside MVP. This sacrifices availability rather than silently creating a second identity. Fake tests must make this operational cost visible; real hardware setup needs an explicit operator warning.

## Startup and uncertain-result reconciliation

Acquire the lease, inspect providers without mutation and compare bindings before admitting any administrative or agent operation. The only normal initialized combination is the matching ready triple defined above. All other partial, denied, mismatched or ambiguous combinations block new authority and remain preserved for investigation.

| Observation | Outcome |
| :--- | :--- |
| All three definitively absent | Uninitialized; only a newly authorized bootstrap may proceed |
| Claimed anchor, with or without an issuer key | Incomplete; no create, bind, resume or automatic cleanup |
| Keyed anchor, absent/prepared/principal-committed database | Incomplete; no automatic mark-ready |
| Ready anchor with missing key/database, wrong binding or wrong bootstrap commit ID | Invalid installation; no repin or reset |
| Database or key exists without its matching anchor | Invalid installation; never infer a fresh namespace |
| An indeterminate step can be read back as its exact committed result | Report that observed state only; it does not authorize repeating the mutation or continuing an interrupted bootstrap |
| Indeterminate final mark-ready, but later ready triple matches exactly | Report initialization observed committed; admit normal startup only after the checks below, without replaying enrollment |

For a ready installation, validate the durable clock high-water mark, then atomically record the new process session and invalidate earlier-session pending ceremonies, execution challenges and unreserved approvals. Retain their mandate IDs and all consumed reservations. If this startup transaction is indeterminate, do not admit authority in that process; read-only inspection is permitted, and a subsequent clean startup may establish its own session. Outstanding reserved records become consumed `unknown` for operational reporting. They never become executable again.

Persist the wall-clock high-water mark in each authority-changing transaction. Reject wall time below that mark or backward movement observed within the process; require monotonic deadlines as well. Forward clock jumps may expire approvals. These rules are not a trusted time service and cannot detect consistent restoration of all relevant state.

## Scoped transaction invariants

State transactions compare expected installation, process session and relevant record revisions. A revision mismatch denies; no transaction silently substitutes a newer record. Mutations, audit transition records and operation receipts commit together. Do not hold transactions over helper, signing or network work.

- **Bootstrap principal commit:** require `prepared` state, matching bootstrap operation, active matching registration/activation result, original deadline and unique credential ID. Persist original verification context and resulting counter/backup state, provenance and commit ID atomically. The anchor remains the separate publication gate.
- **Agent enrollment:** require the exact pending administrative proposal and possession proof from the existing profile, current enabled principal/credential and revision snapshots, and an empty lifetime agent slot for the installation. Atomically claim that unique slot, insert the previously unknown agent key and provenance, update administrator counter/backup state and consume the operation together. An existing slot rejects every new enrollment, even for a different key or when the retained agent is disabled. Disabling never clears the slot. This prevents second-key enrollment from acting as unsupported replacement or rotation; concurrent first enrollments have exactly one winner.
- **Mandate issuance:** claim the pending finish once before helper work. After verification and exact-envelope signing, compare all captured revisions/status, deadlines and session; atomically consume the pending ceremony, apply the credential update once and insert the approved record and retained verification context. A unique `(issuer_id, mandate_id)` is never overwritten. Return the artifact only after definitive commit acknowledgement. A signature produced before a failed/uncertain commit is not authority: execution requires the trusted approved record.
- **Execution challenge:** allow one active challenge per approved mandate; store its exact digest/agent/audience binding and capped deadline. Reject parallel challenge creation rather than replace the existing challenge. Claim a matching submission once before verification; failed proof consumes it. Unrelated challenge IDs cannot consume another challenge. A matching bad proof can burn that pending challenge, as in the existing contract; a fresh challenge requires the mandate still be approved/unexpired and passes rate limits. No replacement challenge while a submission is being verified.
- **Reservation:** require successful verification of retained evidence against original verification context without updating counters, valid agent proof, fresh policy/resource preflight and unchanged snapshots. Atomically consume the verified challenge and move the approved record to reserved, rechecking status/revocation, time and session. Return a dispatch permit only on definitive commit acknowledgement. An indeterminate reservation grants no dispatch permit, even if a later read finds it committed.
- **Dispatch and completion:** use the permit once in the current executor session, recheck local expiry immediately before dispatch and send only the fixed adapter request. Never reconstruct a permit from stored state. Expiry before dispatch records consumed failure; network ambiguity or process loss records consumed unknown. Persist bounded outcome and audit data. An uncertain completion write never causes a second network call.
- **Disable:** protected administrative scope may disable principal, credential or agent, increment affected revisions and invalidate unreserved authority. It never enrolls, deletes records or rewinds reservations. A reservation committed before disable may already execute, as in the existing cutoff policy.

The dispatch permit is an internal one-use control, not a public token. The store and executor must together enforce at most one dispatch attempt per reservation. This does not claim exactly-once remote execution: a crash between durable reservation and network dispatch may burn approval without making a request, and a network timeout may hide a successful merge. Read-only reconciliation informs a separately approved future operation; it never re-arms this reservation.

## Acceptance tests and limits

Reuse existing candidate payload/envelope/agent/enrollment fixtures in `spikes/canonicalization/fixtures` and their Rust/Node comparison tests. New provider tests need event/state assertions, not new cryptography generators. After this contract is reviewed and accepted, fake-provider integration must cover:

1. Every bootstrap boundary: crash before/after mutation, lost acknowledgement, mismatched receipt/binding, denied lookup and concurrent bootstrap. Only one coherent ready triple admits startup; incomplete states remain blocked without retries or cleanup.
2. Definitive absence versus denied/unavailable lookup, untrusted namespace selection, multiple issuer matches and stale cached readback. No error becomes fresh setup.
3. Startup session change, pending-state invalidation, retained consumed IDs, backward time and uncertain startup commit. No pre-restart permit or approval executes.
4. Helper success after cancellation, counter/revision races, candidate mutation, duplicate enrollment, concurrent first-agent enrollment and different-key enrollment after disable. Only one lifetime agent slot may ever be claimed; deferred replacement/rotation reject. Failed publication does not expose an artifact or enrolled authority.
5. Concurrent execution proofs, reservation versus revocation ordering, uncertain reservation acknowledgement and crash at every dispatch/completion boundary. Assert zero writes without a definitive permit and at most one attempt with it; all reserved outcomes remain consumed.
6. Test-provider wiring cannot reach a live adapter or real credential. Simulated success is labeled simulated; missing real providers never select fixtures automatically.
7. Lease acquisition with no database creates no installation state. A live or suspended owner prevents second-process acquisition without timeout takeover; child/helper handle inheritance is denied. Shutdown retains ownership until all dispatch tasks quiesce and permits are invalidated. Initial bootstrap state includes its process session, so first-run commit checks cannot rely on an absent session field.

Independent review must assess whether the real provider can implement each required operation and durability result. A fake demonstrates orchestration, not durable storage under power loss, non-exportability, administrator separation, physical verification or arbitrary rollback detection. SQLite configuration, filesystem durability, concrete anchor protection and issuer lookup semantics remain P06b qualification obligations. No requirement can be fulfilled merely by naming a provider trustworthy. Acceptance must identify any unsatisfied operation instead of weakening its result semantics.
