# P06 client-data cross-runtime gate review

Reviewed 2026-10-03 by independent reviewer `adversarial_p02`, separate from the implementation and integration authors.

## Scope and disposition

No blockers found in the six files identified below. This is a test-harness composition of the existing candidate syntax validator and actual Node verifier function, not a production ingestion change. Other working-tree changes are excluded.

The Rust example caps reads at one byte beyond the accepted bound, validates before emitting evidence, and echoes the original bytes. It accepts no command arguments. It has no internal process deadline; the documented caller obligation is implemented by the Node harness through direct execution, closed stdin, a three-second timeout, SIGKILL and bounded output. The harness requires successful exit, empty diagnostics and exact byte equality for acceptance. Only exit code one with the fixed diagnostic and no evidence output is classified as syntax rejection; launch, timeout and other failures fail the tests. This is a trusted single-process test executable, not hostile-process supervision.

Signed controls demonstrate both existing helper acceptance and candidate-gate rejection for duplicate and invalid-UTF-8 evidence. Callback assertions show rejection happens before invoking the verifier. Valid Unicode/unknown values retain the original signature; equivalent reserialization fails. Wrong origin still fails downstream verification. The corpus and exact-size process cases are included, without claiming registration, transport or controller coverage.

CI builds the explicit release example with the locked graph and runs the new script on both existing platforms. Permissions remain contents-read-only, checkout credentials remain disabled, and no new action, dependency, secret access or privileged event is added.

## Independent validation

Independently confirmed the locked debug example builds. All 28 cross-runtime tests passed using the pinned Node 24.21.0 binary and the absolute debug driver path. Existing Node Web Crypto experimental warnings appeared; no tests failed. No elevated commands, hardware actions, advisory refresh or full-workspace rerun was performed by this reviewer. Hosted exact-head CI remains required before merge.

The test executable and harness are not production APIs. Runtime integration, signed-client-data policy adoption, registration coverage, installation integrity and durable authorization remain separate gates. Timeout/output behavior is inspected here, not exhaustively fault-injected against substitute executables.

## Reviewed source identity

SHA-256 of reviewed working-tree files:

```text
bd1455ffe65f092071c984c8a30b536e72a8be763745c7fbe7941e266986d946  spikes/helper-protocol/examples/client-data-gate.rs
b108247bdd1058e63d4ec724501a630a8f60a73e877c5b85a74d334d0eab5c05  spikes/simplewebauthn/client-data-gate-test.mjs
42c27e3f4c0a9f606a652d8125f1da7fdb3dd3edb9807de3d83d9a359462a123  spikes/simplewebauthn/CLIENT-DATA-GATE.md
273a8ce4317b8a7d5897538cffc2af019c01ec1c064dbcf6ed6503075d305317  spikes/helper-protocol/CLIENT-DATA.md
33f9412161d3d18e23125b642ce2202a88513f494a0123047601b0919241d95b  spikes/simplewebauthn/package.json
bf6804fc8f92e038f0288e4d19286493ff10cb98f5de3a1d482abade1c3b7247  .github/workflows/ci.yml
```
