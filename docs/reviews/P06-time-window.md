# P06 candidate time-window review

Reviewed 2026-10-05 by independent reviewer `adversarial_p02`, separate from author `mandate_design`.

## Scope and disposition

No blockers found in the two assessment files identified below. The local model matches the proposed mandate and execution-proof time rules: positive bounded intervals, checked subtraction, safe-integer timestamps, pending containment, proof containment and half-open current-time membership. Shorter proof windows are allowed without permitting extension of pending authority.

The session, wall-clock high-water and monotonic conditions are additional trusted-context inputs, not implemented clocks or authenticated state. The source and documentation explicitly assume safely capped deadline construction and do not claim real rollback detection, restart recovery, deadline persistence or concurrency protection. Equality at signed expiry or monotonic deadline denies, and changed sessions deny.

The tests provide positive controls and deterministic endpoint comparisons. The small exhaustive range comparison checks interval behavior only. No JSON parser, signature verifier, challenge consumption, live dispatch or production API is introduced. Unrelated native runtime/UI work is excluded from this review.

## Independent validation and remaining gates

All eight `time_window` integration tests passed independently using locked cached dependencies. Compared the rules with `docs/architecture/mandate-contract.md`, `docs/architecture/README.md` and the design baseline. No elevated commands, hardware operations, dependency audit or full-workspace rerun were performed.

Production work must still construct and cap real monotonic deadlines safely, define failure handling for unavailable clocks, maintain authenticated current state/high-water observations, serialize reservation and revocation checks, and recheck immediately before dispatch. These are accurately left open rather than demonstrated by the numeric fixture. Exact-head CI remains required before merge.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
1ede8f8bacd9f2f3cec4cfcf185d8121a2e52ec5f3b8b3ba0656ebb6dc0101e1  spikes/helper-protocol/tests/time_window.rs
84fcff00950e7959cc664d9af6837de6360fabe026bfe38eaae1f0da9a4ba5c5  spikes/helper-protocol/TIME-WINDOW.md
```
