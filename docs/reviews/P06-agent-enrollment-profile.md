# Candidate agent-enrollment profile review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in the two reviewed proposal documents. The profile remains unfrozen and unimplemented; this review does not close P06 or authorize enrollment operations.

## Scope and conclusions

Compared the new profile and enrollment cross-link with the existing enrollment lifecycle and mandate encoding/agent-proof contracts. Trusted Rust state fixes the administrative identities, revisions, nonce, times and immutable candidate. A validated candidate public key is not trusted enrollment merely because its holder can sign.

The administrator assertion binds the exact canonical proposal through a separate administrative domain. Candidate possession follows that authorization and binds its digest, installation, executor, principal, thumbprint and new stage/challenge. Exact pending-context equality and a distinct protected JWS type prevent interpreting execution proofs or arbitrary candidate-selected payloads as enrollment consent. Verification uses the pending candidate key, not a proof-supplied trust anchor.

Both stages and commit retain the original capability deadline. The shorter possession interval must fit within the approved interval; neither stage success nor candidate input refreshes it. Matching finish claims, failures, cancellation, expiry and restart consume the operation. Stale identifiers and wrong capabilities cannot consume another operation. Current revisions, enabled status, immutable proposal/key equality and uniqueness are rechecked at final serialized commit. Deferred credential-counter updates cannot overwrite newer state because changed snapshots reject rather than silently rebasing approval.

Administrative capability relay to the agent is explicitly prohibited. Existing protected bootstrap, local isolation, registry integrity and transport boundaries remain prerequisites. The proposed profile neither introduces a new unauthenticated agent endpoint nor grants a GitHub capability. Rotation, reactivation, replacement and recovery remain separate. Evidence retention is described as a protected-storage requirement, not proof that storage protection exists.

## Validation and limits

Read the complete new profile and existing enrollment document, inspected the two-line cross-link delta, and checked local link destinations and the referenced encoding heading. Git whitespace validation passed. Field sizes, nesting and original/shorter deadline relations were inspected for consistency.

This documentation-only review ran no source tests, generated no protocol vectors and performed no cryptographic, browser, hardware, storage or Git operations. Independent byte/signature vectors, concrete runtime parsing and state-race tests, physical UX and remaining P04b/P06 decisions are still acceptance gates.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `docs/architecture/agent-enrollment-profile.md` | `8185eb81d047da6be8be115e000318c86da90034a23b67f659911da58196f58b` |
| `docs/architecture/enrollment.md` | `2486fb3e657f83d03335cbee0f1ff5568999e4cc6ce33eb8579755ae2b94e4a7` |
