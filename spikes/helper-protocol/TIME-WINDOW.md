# Candidate time-window assessment

Assessment only, 2026-10-05. `tests/time_window.rs` models a narrow part of the [proposed P06 contract](../../docs/architecture/mandate-contract.md). It does not implement a server validator, accept P06 or begin P07. No runtime module imports this test-local model.

Eight deterministic tests cover positive mandate lifetimes up to 300 seconds, positive pending/proof lifetimes up to 30 seconds, pending containment in the mandate, proof containment in pending state, inclusive issuance and exclusive expiry, future-issued proofs, safe-integer bounds and checked subtraction. A shorter proof interval is permitted by the candidate phrase “within that pending lifetime”; exact equality is not presumed. Expiry has no grace.

| Boundary | Candidate model result |
| :--- | :--- |
| Mandate TTL 1 or 300 seconds | Eligible if other checks pass |
| Mandate TTL 0, negative ordering or 301 seconds | Denied |
| Pending/proof TTL 30 or 31 seconds | 30 permitted; 31 denied |
| Wall time exactly issuance / expiry | Issuance permitted; expiry denied |
| Proof shorter than pending / extending it | Shorter permitted; extension denied |
| Timestamp at safe-integer maximum / above it | Maximum permitted with valid lifetime; above denied |
| Monotonic time exactly deadline | Denied even with current wall time |
| Different session or observed wall-clock rollback | Denied |

The model also requires independently supplied trusted session identity, a nondecreasing observed wall time and an unexpired monotonic deadline. Equality at the deadline denies. Fake numeric ticks let tests exercise boundaries without sleeping. They do not demonstrate a real monotonic clock, deadline conversion/capping, persisted high-water mark, rollback detection, restart recovery or concurrent reservation. The test's local context is trusted by assumption, not authenticated by this code. Unsigned constants are not authorization evidence.

Run the `time_window` integration test for package `vollmacht-helper-probe` with Cargo. No network, hardware, new dependency or unmerged envelope/agent fixture is required. All fixtures are local synthetic values. The small exhaustive check compares half-open membership against Rust range semantics; it is not a security proof or fuzz campaign.

The model does not parse JSON, validate signatures, compare challenge/digest/identity fields, consume a nonce, mutate a registry or permit dispatch. A passing result means only that these candidate time conditions hold. Real issuance, reservation and immediately-before-dispatch checks, overflow-safe deadline construction, durable state, revocation and clock-source failure behavior remain implementation and review gates. The existing fixed approval deadline must not be renewed by helper completion; that state transition is outside this assessment.
