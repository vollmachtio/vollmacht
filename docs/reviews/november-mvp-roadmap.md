# November MVP roadmap adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from the authors. Scope: five documentation sources compared with base `a1eb48010695358b8343b7d6fd43a2093ac6a99b` (`origin/main`). No production code, protocol acceptance or deployment qualification is included.

## Reviewed source identity

SHA-256 hashes identify the final reviewed working-tree bytes before commit. The report itself is not part of this source manifest.

| Source | SHA-256 |
| :--- | :--- |
| `docs/implementation-plan.md` | `be9581e303ec7fffb59388db2d5709dd18c165dd363bd9f97750a465ed8e4ae2` |
| `docs/release-v0.1.md` | `2087d4f2a509dd056762a6fb1b07978f9809e74de3d3a08273c505dd35825015` |
| `docs/architecture/README.md` | `3cb3cd0ae9bacfbe81ddee654854516e2ad1b1a1dffa1e785e69e8987dbbc8ab` |
| `docs/architecture/deployment-bootstrap.md` | `de0c8df7d2d5338e01cd8faa80037ac5d48c5f70410d550c901673bf87ab96b7` |
| `docs/architecture/enrollment.md` | `17acfdf6ed67a3cfb477f33986082f21bb0f33c0385215d59d274477fc49abf9` |

## Findings and dispositions

1. **Medium, resolved: deferred replacement still imposed unconditional acceptance tests.** The initial enrollment acceptance paragraph required replacement cancellation and concurrent replacement tests even when the revised roadmap deferred replacement. Reproduction: select a supported administrative profile without replacement, then apply the original unconditional acceptance paragraph; the narrowed MVP still cannot satisfy it. The coordinator relayed this peer finding and corrected the paragraph. This reviewer checked the final text: replacement-specific tests apply only when supported; otherwise rejection must occur without ceremony creation or state changes. Enrollment confirmation, cancellation, timeout, concurrency and failure tests remain mandatory for supported operations.

No unresolved blocking findings were identified in this documentation scope. This is not a finding that the proposed protocol or deployment is secure or complete.

## Adversarial checks

- The split does not label P06a or P06b accepted. P07 still requires a separately reviewed acceptance record and frozen interfaces/vectors; ambiguous security semantics cannot become implementation defaults.
- Native provider qualification no longer blocks portable acceptance solely because physical evidence is pending. Real-provider and live claims still require concrete protection evidence. A changed deployment assumption affecting a frozen interface requires contract revision and review.
- Test providers are restricted to disposable synthetic state and tests or explicitly simulated integration. They cannot reach a live write adapter, receive real GitHub credentials or become a runtime fallback.
- The VM direction is design approval only. The documents retain separate setup authorization, authenticated narrow transport design, host administration isolation and restrictions on shared resources. Host execution of agent-controlled build hooks is explicitly recognized as a boundary crossing.
- Existing raw WebAuthn evidence and issuer provenance remain; the revision does not replace per-operation approval with issuer-only authority. Replay reservations, disable/revoke ordering, uncertain-outcome consumption and restart behavior remain required.
- The no-retargeting GitHub limitation remains explicit. A VM label, successful signature, screen lock or fake provider test is not accepted as proof of the stronger deployment properties.
- Mandatory exact-head CI, independent review, existing tests and trusted-base coverage enforcement remain gates. The plan does not treat coverage collection or PR count as completion.

## Validation and limits

Read `CONTRIBUTING.md`, the complete changed sources, the diff against the named base and relevant surrounding baseline/mandate-contract requirements. Independently ran the Git whitespace diff check successfully. A read-only Ruby check confirmed every relative Markdown file target in the five reviewed sources exists; it did not validate fragment anchors or remote URLs. Re-read the corrected enrollment acceptance paragraph and calculated the final source hashes above.

No executable behavior changed, so this reviewer did not run code suites. The coordinator separately reported 25 canonicalization and 20 JOSE tests passing; those are author-reported results, not independently reproduced results from this review. No native probe, Keychain, VM configuration, signing operation, GitHub write or physical test was performed. Required CI must still pass on the final integrated PR head. Any material source change after these hashes requires review of the delta.
