# Durable simulated flow review

Base: `0d69a7cf41e6644245f3f690b0085a2d82e96d9a` (PR96). Author: `contract_revision`. Independent test audit: `p06_acceptance_audit`. Adversarial reviewer: `adversarial_roadmap_november`.

Disposition: no unresolved blockers. Existing fresh synthetic issuance now feeds a disposable SQLite attempt ledger before core and real helper verification. Captured digests, agent identity, audience and revisions are compared against trusted context. Failed verification appends rejection; a failed rejection write stops without retry and leaves the claim consumed. Successful verification records only a candidate and leaves state claimed. No reservation, dispatch, live GitHub operation, production bootstrap or qualified process-restart path is introduced.

Acceptance checks cover committed claim visibility before the helper, replay after same-session reopen, tampered and expired proofs, unrelated challenge preservation, digest/agent substitutions, audience/revision denial, concurrent claims with one helper/candidate, append-only audit and rejection-write contention. Separate fixed-vector tests remain. Synthetic evidence and software signing remain test-only; neither demonstrates human approval or protected native authority.

Reviewer corrected misleading failure terminology: a rejected BEGIN caused by write contention is definite unavailability, not proof of ambiguous commit. Both independent auditor and adversarial reviewer ran the integrated test successfully. Coordinator full `scripts/check.py` passed, including strict lint, formatting, workspace tests, inventory and release build. Required exact-head CI remains a merge gate.

Only development dependency edges to already-locked `vollmacht-state` and `rusqlite` were added. No third-party version changes, test exclusions or lowered coverage thresholds. The fixture is explicitly classified as unmeasured test support.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `Cargo.lock` | `c9e7153ff566e7a91a1af3c1c6c405ed9dfcf062d5a4b17434249575a440f7cf` |
| `coverage/sources.json` | `83180be97578c008c345a987bf6d931ded9b7d278582e546e32f34c53b515271` |
| `docs/development.md` | `b903057fc9180ffcb5ef8d0a6edbc4c866feb7f8ec7de136a7ea928ebc7ccdd9` |
| `docs/implementation-plan.md` | `3e084f8b3241a784d7f7088febbdd145d693f0c661863951eb843a2935563a6e` |
| `spikes/helper-launcher/Cargo.toml` | `5a99a1f8d9243341bfcd74f70166ef3e5236158df1dc78a029c4822e0bc1b4df` |
| `spikes/helper-launcher/tests/fresh_simulated_merge.rs` | `2ba8931ec9e2423f8dbcef25e541377b8115996cf7c4cade07b36515538cf5ff` |
| `spikes/helper-launcher/tests/support/attempt_fixture.rs` | `1cb5277d00d065fb885e40bd6f1a39bc5e813fbbda219e98caccd185133fb78d` |
