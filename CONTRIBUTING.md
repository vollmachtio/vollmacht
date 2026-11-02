# Contributing

Deliver one coherent change per pull request. Keep unrelated refactoring out of security changes. Link the corresponding task in the execution plan and document observable behavior, validation, limitations, and remaining work.

## Required adversarial review

Every PR, including documentation PRs, requires a separate reviewer execution. The author cannot satisfy this gate by reviewing their own changes. The reviewer inspects the actual diff and relevant surrounding code, seeks counterexamples, and reports concrete bugs and missing tests. An automated reviewer is useful evidence, not certification of security.

For protocol and enforcement changes, review parsing ambiguities, signature coverage, key trust, credential registration, audience and agent binding, replay races, crash recovery, policy widening, credential leakage, bypasses, and GitHub state changes.

Record the reviewed commit or tree, reviewer identity, scope, findings with severity and reproduction details, author dispositions, and validation results in a review report. Fix blocking findings and have the reviewer check the resulting changes. If the final diff differs materially from the reviewed diff, repeat review of that delta. No unresolved critical or high-severity findings may pass; any remaining issue needs an explicit rationale and tracking task.

Before handoff, the PR description links the review report and identifies the exact reviewed revision. Required tests must pass. Do not claim that a passing test suite or review guarantees freedom from bugs.

## Coordinated delivery

Independent tasks may run in parallel with explicit file ownership. Keep separate PRs for coherent changes; do not implement dependent protocol code against an unfrozen contract. A coordinator integrates changes and obtains a separate adversarial review for each PR.

The maintainer has authorized automatic merging of in-plan PRs after review findings are resolved and all required checks pass on the exact head revision. Pause for clarification, material plan deviations, new permissions or user-assisted hardware work. Automatic merging does not waive these gates or authorize live GitHub demo operations, credential changes or Keychain mutations. If branch protections or another required review block merging, report the blocker rather than bypassing it.

Keep incomplete PRs and PRs awaiting a maintainer decision, permission, review or required manual evidence in draft, with the blocker stated in the description. Do not mark them ready until that gate is resolved. A PR may document a deferred gate without being blocked by it only when that gate is outside the PR's acceptance scope; never imply that deferred evidence has passed.

For ready, in-plan PRs with completed independent adversarial review and no unresolved approval gates, enable GitHub auto-merge as soon as only required CI remains. Use normal protected squash merging, never an administrative bypass. Auto-merge must retain all required checks and current-base requirements. The coordinator follows through on branch updates, failed checks and integration conflicts, verifies that the reviewed diff remains intact, obtains review for material changes, and confirms the eventual merge. If new changes or blockers invalidate review or authorization, disable auto-merge and return the PR to draft before proceeding.

## Implementation conventions

Use small Rust modules with explicit trust boundaries and typed errors. Keep cryptography behind maintained libraries; never implement primitives. Prefer a minimal dependency graph. Document any unsafe Rust or native FFI and isolate it behind a narrow interface.

Validate untrusted input at boundaries and deny unknown operations. Keep credentials, assertion bytes, and private repository data out of routine logs and fixtures. Unit and integration tests must demonstrate security properties or observable behavior, rather than mirror internal implementation.

Use deterministic fake authenticators only in tests. Clearly distinguish simulated WebAuthn testing from physical authenticator testing on a Mac.
