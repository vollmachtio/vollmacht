# Candidate reservation model review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the two assessment files. No production state implementation or P06 closure is established.

## Scope and conclusions

Compared the finite model with the design baseline and proposed architecture/mandate contract. Reservation is the modeled cutoff for revocation, credential status and policy revision; deadline validity is separately rechecked before dispatch. Expiry after reservation burns the slot rather than releasing it. Success requires dispatch, while definite failure or an unknown outcome remains consumed. A late success cannot revive an unknown record.

Issuer/mandate identity is separate from signature bytes and immutable fingerprints. An existing identity cannot be reinserted with changed signatures or digests. Restart invalidates unreserved approvals, preserves their identities and consumption, and turns outstanding reservations into unknown outcomes. The bounded sequence exploration checks monotonic counters, immutable fingerprints, at most one dispatch and absence of terminal-state escape.

These transitions assume serialization and persistence rather than implementing them. The supplied deadline Boolean, globally modeled status flags and assumed valid agent challenge do not verify time, cryptography, actual registry state or challenge consumption. The documentation accurately excludes database isolation, real concurrency/crashes, disk rollback, remote execution and complete authorization. No runtime API or authority is widened.

## Independent verification

All four `reservation_model` integration tests passed independently using locked offline dependencies. The exhaustive test checked the declared 41,370 transitions across event sequences of lengths one through four. Inspected ordered cutoff cases, pre/post-dispatch expiry/restart behavior, changed-identity inputs and terminal-state handling against the proposed rules.

No full-workspace or Clippy rerun was performed by this reviewer. No database, helper process, hardware, network or Git mutation was invoked. Concurrent native-runner and inventory changes are excluded from this review.

## Reviewed source SHA-256

Hashes are recorded below from the final reviewed source bytes.

```text
5ff4c900272cba0866b677115661ed23d63167402efadc53aa1adce7d9e2aafb  spikes/helper-protocol/tests/reservation_model.rs
6fc67720d1226778662d8c065536eb5ac9936359f19f3a5e6aa2b66d42c48e9c  spikes/helper-protocol/RESERVATION-MODEL.md
```

## Inventory integration follow-up

Both assessment source hashes remain unchanged after integration with main `fa76dd6`. The only manifest addition classifies `spikes/helper-protocol/tests/reservation_model.rs` as `assessment_model` and `unmeasured`, matching its scope without asserting coverage. No existing classification changes. The reviewer independently ran the inventory CLI successfully: 84 indexed sources, including 79 unmeasured sources, four raw Swift fake-test sources and one attribution-only source. No integration blockers found; runtime tests were not repeated for this classification-only delta.

Reviewed `coverage/sources.json` SHA-256: `8ff8b445e26ed82a1e13d6fd419a3f1df9286ef257fed18489a51902d3da56ce`.
