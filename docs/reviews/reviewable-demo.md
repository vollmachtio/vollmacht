# Reviewable demo

Base: `dd46cb04b4ffeff33ee40973bdba5f301718b41a` (PR97). Coordinator authored the runner and documentation; `contract_revision` authored opt-in test trace points; `p06_acceptance_audit` independently authored runner regressions; `adversarial_roadmap_november` reviewed the integrated changes.

The developer command runs the existing synthetic test, not an alternative verifier. It reports seven fixed stages only after successful test exit and an exact ordered transcript. Missing, reordered, duplicate or unexpected events and nonzero exits deny a successful walkthrough. Output explicitly distinguishes synthetic approval, verified candidate and absent GitHub dispatch. No production configuration, native provider or credential operation is introduced.

Resolved reviewer finding: timing out Cargo alone could leave test/helper descendants running. The runner now owns a separate process group and terminates it on timeout or interruption, with bounded pipe/reap cleanup. Independent tests cover these paths without launching processes. Documentation notes that interruption can leave temporary synthetic test files and that Cargo may fetch/build locked dependencies; the command does not install runtimes.

Independent reviewer ran all ten runner tests and the actual demo successfully. Coordinator full `scripts/check.py` passed, including the new runner tests and actual walkthrough, existing workspace tests, inventory, strict lint, formatting and release build. No dependency changes, removed tests or reduced coverage thresholds. New developer/test files are explicitly unmeasured in the inventory. Mandatory exact-head CI remains required before merge.

This is an early review checkpoint, not the live MVP. It deliberately postpones polish and optional abstractions while preserving requirements for real approval, final preflight/reservation and qualified live deployment.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `README.md` | `cc46bac86312aee3e47d25afcd1699357c67ffefa2d2e4e3a1ff1c22c782d41c` |
| `coverage/sources.json` | `af1bb3fc57470524f4f17533f6fb36b2808ae63ac0db53e530650cc7ea2fdf58` |
| `docs/development.md` | `33b2c6925974bbfad9d59ef49a33d96291957ea4ab05900868966aa49042da05` |
| `docs/implementation-plan.md` | `94d69292df762347b6ed02ad7ad2de41fc2774f8bd8e70994a3f8ad8c3ed72e7` |
| `scripts/check.py` | `53fc014c4e6f32eb1efbb39a028423f17214e9b98535889b7c26dc9efd9f2e7c` |
| `scripts/demo.py` | `5cb4b08869b8613c6e5a41ca32c80e27503855af4047ef5102a4b07dcbffed38` |
| `scripts/test_demo.py` | `fb5dcbf96b6c6b4410a3baea786c393dacb5f64d56b86c8c03afd0f0d4063cdb` |
| `spikes/helper-launcher/tests/fresh_simulated_merge.rs` | `2c226504195860c4169fbc231a92a58fb8653c40649d1f4003c2f8934e3f5f35` |
