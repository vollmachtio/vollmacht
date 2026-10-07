# Candidate reservation transition assessment

`tests/reservation_model.rs` is an isolated executable model of the [proposed reservation rules](../../docs/architecture/README.md#adr-candidate-3-reservation-not-exactly-once-execution). It is not production authorization code, a SQLite implementation, concurrency proof or P06 acceptance evidence sufficient to complete a gate.

The synthetic store is keyed by `(issuer, mandate)`. Payload/envelope fingerprint pairs are immutable once inserted. Signature bytes are deliberately not identity: all 256 synthetic signature values fail to recreate the same row. Changed fingerprints under an existing ID fail both insertion and reservation. Separate issuer/mandate pairs remain separate rows. These small integers are test labels, not cryptographic digests, keys or valid mandates.

| Sequence or boundary | Modeled outcome |
| :--- | :--- |
| Revocation, disabled status or changed policy before reservation | Reservation denied |
| Those changes after reservation | Existing reservation may dispatch; cutoff is reservation |
| Deadline expires before reservation | Reservation denied |
| Deadline expires after reservation but before dispatch | Consumed failure, no dispatch |
| Repeated reservation or dispatch | No second reservation or dispatch |
| Definite failure | Consumed; no release or automatic retry |
| Timeout or crash after reservation | Unknown; remains consumed even if dispatch never happened |
| Restart with unreserved approval | Invalidated, ID retained; no recreation of that ID |
| Restart with terminal result | Result and consumption retained |

The only execution path is `Approved → Reserved → Succeeded | Failed | Unknown`. `Invalidated` models refusal of pre-restart unreserved approvals without deleting their identities. A definite failure can occur before dispatch; success requires a modeled dispatch. A timeout remains unknown even if a later success event arrives. There is no reconciliation implementation or automatic write retry. Creating a genuinely new operation after external reconciliation is outside this model.

Four tests cover literal ordered sequences, pre/post-dispatch restart, identity binding and exhaustive event sequences of lengths one through four over 14 events (41,370 checked transitions). Invariants check immutable records, at most one reservation/dispatch per identity, monotonic consumption and no terminal-state escape. These generated sequences exercise the implemented finite model; they are neither exhaustive over a real system nor independent proof that the model includes every required rule.

Reservation is assumed indivisible. Persistence across modeled restart is assumed by retaining the in-memory map. The assessment does not test threads, transaction isolation, disk corruption, process crashes, database rollback or remote GitHub execution. It also assumes an already validated one-use agent challenge; it does not store or consume that challenge. Deadline validity is a supplied Boolean, not a trusted clock. Signature verification, registry provenance, actual challenge consumption, revocation transactions, crash recovery and immediately-before-dispatch checks require implementation and separate tests.

Run the `reservation_model` integration test in package `vollmacht-helper-probe`. No new dependency, helper process, hardware operation, signing identity or GitHub credential is used. Existing production boundaries are unchanged.
