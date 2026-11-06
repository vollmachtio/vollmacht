# Portable execution verification review

Implementation author: `contract_revision`. Independent tests and integration: `p06_acceptance_audit`. Independent adversarial reviewer: `adversarial_roadmap_november`. Base: `bb2c728ac755e16fd2047d0b517e1f337a2e8760`.

Disposition: no unresolved blockers. Reviewer read all seven final files and the accepted surrounding contracts. The new core path validates retained record, issuer and agent signatures, original evidence context, digest/profile/audience bindings and captured time. Its private-field candidate is explicitly not a dispatch permit. Trusted context provenance, matching-attempt claim/consumption, fresh state checks and durable reservation remain coordinator responsibilities. The evidence adapter is a trusted computing boundary, not a type-system guarantee of WebAuthn verification.

Resolved findings:

1. Medium: candidate discarded the actual proof interval, preventing later enforcement of an expiry narrower than the pending window. Candidate now retains both proof timestamps. A freshly software-signed shorter proof tests this behavior; the simulated final transaction checks those bounds.
2. Medium: evidence adapter lacked the effective trusted deadline. The request now exposes it; integration caps the helper budget by that deadline and five seconds.
3. Low: retained nonzero counter progression could be inconsistent. Constructor now rejects equal/decreasing nonzero counters while allowing zero/zero, with regression tests.

Independent reviewer ran all core tests successfully, including three execution tests. Independent test author ran core execution tests, real-helper simulation and strict Clippy for both packages. Coordinator ran the full final `scripts/check.py` successfully, including formatting, lint, workspace tests, 138-source inventory and release build. Reviewer did not independently run the Node integration. Initial accessor naming lint failure was corrected by naming the WebAuthn challenge explicitly, without suppression.

No third-party dependency, frozen contract, coverage threshold or existing test was weakened. No native keys or live GitHub effects were used. Fresh user approval/issuance, enrollment, durable enforcement and live deployment remain incomplete. Exact integrated-head required CI must pass before protected merge.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `coverage/sources.json` | `53a0cbbd3f9d814d7008f1ae4091a49a6999334bd3a6c42d53ff192ddb36c2a9` |
| `crates/core/src/execution.rs` | `af290b10bba65dfab47e78e2fc8ac987dd564d12cd55429a3a947549fa0b65d4` |
| `crates/core/src/lib.rs` | `fac6ffe3fcb1a0ee62284e5de1b1d9e0dd469bdc49d150e1aa5f6ffbd1ca23fa` |
| `crates/core/tests/execution.rs` | `d0284402a65af3bfa7ffe1ac6e69dd5816ebe2794127d7d7208733eabd020f27` |
| `docs/development.md` | `bc71097264d217162a772b3b859115cd57571bad4867cdb579b32a58bb10a1d7` |
| `docs/implementation-plan.md` | `4b54c913f40f83fa0d0ff0eec16ec96c039c5514cf3e8088d40f6fe1973288c8` |
| `spikes/helper-launcher/tests/simulated_merge.rs` | `b3558be6ec27068ea6f75e37393bae22252549b902ab5ce6fc977fb16ecec15d` |
