# One-shot diagnostic plan

This pure coordinator prepares a future locked-screen assessment. It has no Security or LocalAuthentication imports, native backend, timer, UI or key operations. It does not alter the restart experiment or the user's Xcode project.

The caller supplies immutable item identity, a trusted public pin, an already pinned opaque handle and a run ID unique to the eventual coordinator owner. The identity initializer checks only bounded strings and public-key encoding shape, not cryptographic key validity or enrollment trust. The message is fixed to the existing diagnostic message, never arbitrary caller data or a mandate.

## Lifecycle

`idle → armed → attempting → attempted → complete`, with `armed → cancelled` as the only cancellation transition. Arm rejects duplicate calls and windows beyond two minutes. Early polling returns `notDue` without consuming the attempt or doing backend work. There is no internal polling, scheduling or retry. Once an actual attempt begins, even denial or timing failure consumes it. Terminal plans cannot be rearmed.

The synchronous, serialized coordinator invokes three independent backend probes: record read, fresh exact key lookup, and fixed-message signing with the handle retained before arming. Denial or mismatch in one probe does not suppress the others, because distinguishing these access paths is the purpose of this diagnostic. Fresh lookup never substitutes its result for the retained handle. This is not an authorization workflow: independent diagnostic signing must never be reused to bypass failed production validation.

Clock evidence is sampled before and after operations. Early polls retain their last observed instant, so rollback or a continuity change between polls consumes an inconclusive attempt without backend calls. Late start, overrun, backwards time or changed continuity marks the attempt inconclusive and skips any remaining probes. Window endpoints are inclusive. Skipped outcomes are absent, not fabricated denials. The backend interface is synchronous and nonthrowing; any future adapter must map bounded failures to outcomes. This pure model cannot interrupt a blocking call, impose an OS timeout, or accept cancellation during a synchronous operation.

Completion requires the matching run ID and accepts only one result. Supplied verified screen-lock evidence must bracket the entire attempt in the same clock continuity domain. Missing or unverified evidence is inconclusive even when all probes succeed. `intervalConclusive` describes only this timing/evidence condition; it does not mean the operations succeeded, the key is secure, or the Keychain was locked. Screen lock and Keychain lock are not interchangeable.

## Deferred native wiring and manual sequence

1. Independently review any native adapter before adding it to the app. Use only the existing dedicated test identity. Validate the retained public pin and obtain the exact key handle while unlocked; do not create or replace a key as part of this diagnostic.
2. Map record-read and exact-lookup results independently, including missing, ambiguous, denied and pin-mismatch results. For retained-handle signing, preserve noninteractive authentication policy, sign only `DiagnosticMessage.bytes`, and verify against the retained public pin before reporting success. Never fall back to an alternate key or prompt mode.
3. Supply a trusted monotonic clock that accounts for suspension, plus a continuity token that changes on observed sleep or loss of reliable timing evidence. The pure model does not detect sleep. Implement bounded native calls and serialized ownership before using it unattended. Do not route untrusted callbacks by a reusable run ID.
4. After explicit user authorization, arm one short attempt, lock the screen manually and record reliable lock interval evidence. Do not automate locking/unlocking or infer Keychain lock state. If suspension, lateness, unknown lock boundaries or missing evidence prevents attribution, retain the outcomes but label the run inconclusive.
5. Unlock manually to inspect the report. A separate explicitly authorized experiment is required for any new attempt; no automatic retries, cleanup, key regeneration or deletion occur.

These are proposed integration steps, not implemented or validated native behavior. Fake tests exercise 216 independent outcome combinations, lifecycle denial, stale completion, skipped probes, timing discontinuity and missing/unverified lock evidence. Compile only `DiagnosticPlan.swift` and `DiagnosticPlanTests.swift` together for this fake suite; no native source is required.
