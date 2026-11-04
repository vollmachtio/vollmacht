# Simulated merge integration review

Implementation: `contract_revision`; independent public fixture adapter: `p06_acceptance_audit`; CI, inventory and documentation: coordinator. Independent adversarial reviewer: `adversarial_p02`.

Disposition: no remaining blockers. The harness connects real core issuer and agent signature checks, original-byte client-data validation and the actual Node assertion verifier through the existing coordinator/launcher. Only a fixed in-memory merge recorder receives successful execution. Trusted fixture setup is not enrollment or issuance.

The reviewer found that downstream state failures could leave a matching proof challenge reusable. The author moved consumption to proof-processing entry and added regression checks showing restored policy, status, time or metadata cannot revive it. A valid signed proof with the wrong trusted pending context now exercises the binding rejection branch. Expired and early test clocks deny; nested time windows mean these are overall rejection checks, not isolated approval-time branch coverage.

Independent final validation: targeted simulation, strict launcher Clippy and 136-source inventory passed. Coordinator final full `scripts/check.py` passed, including existing tests, formatting, lint and release build. CI installs the existing locked Node dependencies before workspace tests; the only Cargo dependency delta is a local development dependency on core. No tests or coverage gates were weakened. Initial inventory failure from unstaged new sources was corrected by tracking those sources, then rerunning validation.

Scope excludes fresh approval, mandate issuance, production enrollment, durable/concurrent replay storage, native keys and GitHub effects. This is not milestone B completion or the live MVP. Required exact-head CI must pass before protected merge.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `.github/workflows/ci.yml` | `cb88b6f26d8197014648534b4052b063d117e0725270c900a9a243aedc9109f9` |
| `Cargo.lock` | `4291cc593f6aeee5e00513b0cfab4fc771341d882038c3b5982907ad56255bda` |
| `coverage/sources.json` | `b9764b9bbaedcbaf533b7c002b42bd7e6992ce6889922254b3b49b846ebff3b2` |
| `docs/development.md` | `e369a8956d1e787941060bf1c19ce824afcccc2f1c395efdc0433cbc56493139` |
| `docs/implementation-plan.md` | `1ec68e422fc934af0a975954425d9e38e9b3d299ac034aaef6c3556bd4107df3` |
| `scripts/check.py` | `06521da0f62c13a8c5ea95eea3a374b19cb38239f804c41b0014bf59c82b51fa` |
| `spikes/helper-launcher/Cargo.toml` | `674216b2672ac6240cc6e0e8ffbf0ad50e8dea87aeff7c328c181dc148a0edb5` |
| `spikes/helper-launcher/tests/simulated_merge.rs` | `d5dbaac622e442532ad3cdc81676e89069bf1ada47f0df77c8c66bd383a2b330` |
| `spikes/simplewebauthn/simulation-context.mjs` | `9890558aa7355f48c5dabdb6db69316b1f03f837fbc6a4108ef60419f7478b17` |
