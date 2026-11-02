# Provider contract adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from the provider-contract author. Scope: new `docs/architecture/provider-contract.md`, including the author's revisions following this review. This is review of a proposed abstract contract, not P06a acceptance or native/provider qualification.

## Reviewed source and context

Final source SHA-256: `186d3b70d599748b5cc4b17ee690f2a86e51b6cbe1373f163ce493446a092377`.

Review uses the revised-roadmap context at commit `be8d74342bb9c7986faf358a9e95bd459d72b4c4`, rather than assuming the current working branch contains that roadmap. Relevant reference hashes at that revision:

| Reference | SHA-256 |
| :--- | :--- |
| `docs/architecture/mandate-contract.md` | `face6db14a8265cb5d045c4cb8930e63ea0a0555ecb104a08e96f8132147e89c` |
| `docs/architecture/enrollment.md` | `17acfdf6ed67a3cfb477f33986082f21bb0f33c0385215d59d274477fc49abf9` |
| `docs/architecture/deployment-bootstrap.md` | `de0c8df7d2d5338e01cd8faa80037ac5d48c5f70410d550c901673bf87ab96b7` |
| `docs/architecture/agent-enrollment-profile.md` | `8185eb81d047da6be8be115e000318c86da90034a23b67f659911da58196f58b` |

## Findings and dispositions

1. **Medium, resolved: second-key enrollment bypassed the declared single-agent scope.** Initially, the transaction rejected an already known key but allowed any new key. Enrolling A then B, or disabling A and enrolling B, satisfied those rules despite unsupported replacement/rotation. The author added a lifetime installation agent slot claimed atomically with first enrollment. Any retained slot, including disabled, rejects a different key; disable cannot clear it. Required tests now cover competing first enrollments and different-key enrollment after disable. This narrows the candidate MVP and does not imply those tests are implemented.

2. **Medium, resolved: fresh-bootstrap ownership and session establishment were underspecified.** Initially, the state provider had to provide a lease before startup or mutation even when no database existed, and scoped transactions required a session that was only explicitly persisted during initialized startup. A fresh installation therefore needed an invented implicit creation or ownership exception. Lease expiry/takeover semantics also left a suspended old coordinator and its dispatch permit ambiguous. The author added an independent configured-namespace lease provider, explicitly usable without creating installation state; no timeout takeover while an owner remains alive or suspended; no inherited handles; release only after dispatch tasks quiesce and permits are invalidated. State creation now atomically records the bootstrap session and clock high-water mark. Corresponding acceptance cases were added. Concrete OS ownership and shutdown behavior still require provider qualification.

Both fixes were re-read in the final source identified above. No unresolved blocking findings remain within this proposed-document scope.

## Additional adversarial checks

- Absence is not inferred from denied/unavailable lookup, and the document does not claim to distinguish fresh setup after privileged deletion of all relevant state. The demonstrated agent must be unable to perform that deletion or choose a replacement namespace.
- Partial bootstrap stops without recreation, automatic completion or cleanup. Exact ready-state observation after an uncertain final publication permits validated startup, not replay of enrollment. The intentional availability cost is explicit.
- Provider indeterminacy cannot mint a dispatch permit. Later readback of a committed reservation cannot reconstruct one. A permit remains process-local and one-use; restart consumes outstanding reservations rather than rearming them.
- Signing before an unsuccessful issuance commit does not grant authority because execution requires the trusted approval record. Retained assertion verification cannot mutate counters again.
- Disable retains the existing reservation cutoff; a later disable cannot recall an already reserved operation. Clock checks, revision checks and fixed dispatch requirements remain present.
- Fake providers cannot reach real credentials or a live adapter. The proposal freezes no API and does not waive native evidence, architecture acceptance, concrete storage durability or deployment isolation.

## Validation and limits

Read the complete proposal before and after fixes, `CONTRIBUTING.md`, and relevant candidate mandate/enrollment/deployment context. Independently checked relative Markdown file targets and whitespace/final-newline formatting with read-only Ruby checks; all passed. The new-file Git whitespace check emitted no whitespace diagnostics; its difference exit status was not treated as a test failure. Reference content hashes were calculated from the named context revision.

No code or physical tests were run: the acceptance cases above are specifications for future tests, not passing evidence. No source edits, native actions, VM changes, signing operations or external writes were performed by this reviewer. The only file written was this report. Final integrated-head CI and review of any material delta remain required before merge; implementation still waits for explicit P06a acceptance.
