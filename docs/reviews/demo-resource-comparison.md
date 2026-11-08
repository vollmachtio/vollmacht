# Demo resource comparison review

Base: `e8697f611448517cb9c2b7f5f4d4d16ae47418d0`. Core author: `contract_revision`. Independent integration author: `p06_acceptance_audit`. Coordinator added fixed-vector core cases and runner/docs changes. Independent adversarial reviewer: `adversarial_roadmap_november`.

Disposition: no unresolved blockers. A coordinator-selected provider supplies current resource facts; exact repository ID/label, PR, head/base and supported method are compared with the verified candidate. Current method restrictions and policy revision are checked. A trusted clock callback runs after metadata retrieval and enforces session, proof/pending/approval expiry and original monotonic deadlines. The private result borrows the candidate and is not a reservation input or dispatch permit.

The existing fresh demo invokes comparison while retaining its acknowledged claim receipt. Twelve negative scenarios produce no recorder event, persist rejection and deny replay after same-session reopen. They cover head/base/repository identity/label/PR, method support, provider failure, policy revision/method, expiry, monotonic deadline and session changes. Fixed-vector core cases independently test the comparisons and post-provider clock ordering. Existing tests remain intact.

Review required precise boundaries before implementation: no invented freshness interval, disposable-marker format, preflight boolean or full-policy claim. Current API eligibility, live fixture qualification, full policy evaluation, provider deployment and final atomic registry/policy checks remain unfinished. Reading current facts does not prevent later remote changes. Demo wording was narrowed to “method restrictions.”

Validation: reviewer independently passed full core tests, ten runner tests and the eight-stage actual demo. Coordinator full `scripts/check.py` passed after correcting a test helper's formatting. The added core cases share the existing one-time verifier initialization rather than initializing the process-global provider twice. No dependency or coverage-policy changes; the new source is explicitly inventoried as unmeasured trusted core. Required exact-head CI remains the merge gate.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `README.md` | `be116820c0e0d8e1517b5f83496a3c44f01116be860fbe51152c347641a1e2f7` |
| `coverage/sources.json` | `b9a0314f2792c468c0b0639f0c691f75cf803c80ec39d52596001c659fe10fad` |
| `crates/core/src/lib.rs` | `a1420d015e4b0099df2c0e969c821b98a092df8f3258d6231db0e95798f5568b` |
| `crates/core/src/preflight.rs` | `a46a5c68a7cff36986ecebacebcf0cc701b8aeab393b13ed8a56ae41a64d9f73` |
| `crates/core/tests/execution.rs` | `326d7345b670df29369db565987402fa15a01ff777922d096aa97875460cdd8d` |
| `docs/development.md` | `5fc40c90191a6b486a2a8842bb46df6aec5fbd3a58889182b666a582a290a745` |
| `docs/implementation-plan.md` | `a050c95606464d82eee6643fc67781e0d489e75882a26992d6caf3ad5e063c0a` |
| `scripts/demo.py` | `e0b304a848cbf48b1f27c1e368a18ceb0dbf40143bd0a031ef324bd7c48e1877` |
| `scripts/test_demo.py` | `b01d2658ae2831a50c85ae81b41160286f3597556962312cb9ef53d0ee8128e4` |
| `spikes/helper-launcher/tests/fresh_simulated_merge.rs` | `7cec76bb595d418a0696c9752939153b4ee3bd609896a5de8016203a83aa627b` |
