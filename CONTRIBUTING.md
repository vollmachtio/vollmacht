# Contributing

Deliver one coherent change per pull request. Keep unrelated refactoring out of security changes. Link the corresponding task in the execution plan and document observable behavior, validation, limitations, and remaining work.

## Required adversarial review

Every PR, including documentation PRs, requires a separate reviewer execution. The author cannot satisfy this gate by reviewing their own changes. The reviewer inspects the actual diff and relevant surrounding code, seeks counterexamples, and reports concrete bugs and missing tests. An automated reviewer is useful evidence, not certification of security.

For protocol and enforcement changes, review parsing ambiguities, signature coverage, key trust, credential registration, audience and agent binding, replay races, crash recovery, policy widening, credential leakage, bypasses, and GitHub state changes.

Record the reviewed commit or tree, reviewer identity, scope, findings with severity and reproduction details, author dispositions, and validation results in a review report. Fix blocking findings and have the reviewer check the resulting changes. If the final diff differs materially from the reviewed diff, repeat review of that delta. No unresolved critical or high-severity findings may pass; any remaining issue needs an explicit rationale and tracking task.

Before handoff, the PR description links the review report and identifies the exact reviewed revision. Required tests must pass. Do not claim that a passing test suite or review guarantees freedom from bugs.

## Implementation conventions

Use small Rust modules with explicit trust boundaries and typed errors. Keep cryptography behind maintained libraries; never implement primitives. Prefer a minimal dependency graph. Document any unsafe Rust or native FFI and isolate it behind a narrow interface.

Validate untrusted input at boundaries and deny unknown operations. Keep credentials, assertion bytes, and private repository data out of routine logs and fixtures. Unit and integration tests must demonstrate security properties or observable behavior, rather than mirror internal implementation.

Use deterministic fake authenticators only in tests. Clearly distinguish simulated WebAuthn testing from physical authenticator testing on a Mac.
