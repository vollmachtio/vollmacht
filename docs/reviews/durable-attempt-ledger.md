# Durable attempt ledger review

Base: `55ee287f0642e33da8e8bdd4224d022a4694f35f`. Production author: `contract_revision`. Independent integration-test author: `p06_acceptance_audit`. Adversarial reviewer: `adversarial_roadmap_november`.

Scope: existing-database matching claim, rejection and append-only audit, captured bindings, and informational operation lookup. No reservation, dispatch, provisioning, enrollment, lease acquisition or native provider integration. The caller must authenticate provenance, enforce its authority boundary and supply trusted time. Opening a database and comparing its fields cannot establish those properties.

Review findings addressed: lifetime mandate/challenge uniqueness would prevent a new challenge after rejection, so uniqueness now covers only pending/claimed challenges. Claim and rejection retain separate operation/audit rows. Tests cover competing connections, stale revisions/session/time, unrelated challenges, denied schema/bindings, actual mid-write rollback, actual COMMIT failure and a lost acknowledgement after committed state. Read-only reconciliation must also reject an active transaction so uncommitted rows cannot be presented as committed history.

## Dependency decision

Pinned `rusqlite` 0.41.1 uses safe Rust APIs over bundled `libsqlite3-sys` 0.39.1. Default features are disabled; only `bundled` is selected. No Rust extension-loading API or bindgen feature is enabled. The two additional iterator dependencies are `fallible-iterator` 0.3.0 and `fallible-streaming-iterator` 0.1.9. Existing dependency versions remain unchanged. Package manifests, enabled features, native build script and transitive changes were inspected; the locked dependency advisory/license/source checks passed without policy changes.

The selected native source contains SQLite 3.54.1. Bundling reduces reliance on the system SQLite version but is not runtime integrity evidence: native build environment overrides can select system libraries or extra flags. Trusted build/runtime provenance remains a deployment prerequisite. No unsafe workspace code or custom cryptographic primitive is introduced.

Immediate transactions serialize writers. DELETE journal mode, EXTRA synchronous mode and fullfsync are requested and checked. See the primary [SQLite PRAGMA documentation](https://www.sqlite.org/pragma.html) and [atomic commit explanation](https://www.sqlite.org/atomiccommit.html). Readback and portable failure tests do not prove filesystem or power-loss durability. A commit error or simulated lost acknowledgement poisons the writer; lookup is informational and cannot reconstruct a claim receipt or dispatch permit.

## Validation and disposition

Independent reviewer disposition: no unresolved source blockers. Reviewer ran three private fault tests, nine ledger integration tests and twelve coverage-inventory tests successfully. Coordinator full `scripts/check.py` passed, including workspace tests, strict lint, formatting, tracked-source inventory and release build. Dependency checks passed. Required exact-head CI remains a merge gate.

SQL schema files now require explicit coverage inventory classification, with a regression test. The new crate remains explicitly unmeasured; this change does not claim coverage enforcement or reduce any threshold. Existing tests are retained.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `Cargo.toml` | `497fcb5818893082d38a584f036ac7e7caf4b23a735e676c29ebbd2f71629b63` |
| `Cargo.lock` | `66db800f1cd344c7d8f11223b8647115cc9b1b3205265868a78d5cb7200d131f` |
| `crates/state/Cargo.toml` | `d16cab27852902da1a01fd78a3e194a2c1be89204609c3d51f71f92ac388b473` |
| `crates/state/src/lib.rs` | `90b844ed85da42a747bbb5b446b0081d5600546c97bacce5471b499fd405043a` |
| `crates/state/src/schema.sql` | `6f02d72b40c0a4f9f79569f8a0b48d4f21e11aa33226470b048616d47cc87702` |
| `crates/state/tests/ledger.rs` | `cfce5ba4c7b5f0e77e248649af5d40cea12c5b0fcc9c0235c44ebc5399cadfc7` |
| `coverage/sources.json` | `cb3601e9563593dfbf9c854953693bb8c6cd1664e793e0c58e262906f62b7c31` |
| `scripts/coverage_inventory.py` | `49e0359173526618b100328a86702cef75f334d259a4b351e1687352eb2d6805` |
| `scripts/test_coverage_inventory.py` | `64f3d34af7631583476c4e01f04e86d3cec2d237a9d6e674697bab0c07b85fc0` |
