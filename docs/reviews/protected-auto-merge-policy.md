# Protected auto-merge policy review

Date: 2026-11-01

Reviewer: independent adversarial agent `/root/review_auto_merge_policy`.

## Scope and revision

Reviewed the complete `CONTRIBUTING.md` diff against base commit
`c90042f3e8d475daa562a5f8bb0c0d6156917a1d`, including the surrounding review
and coordinated-delivery requirements.

Reviewed source SHA-256:

| File | SHA-256 |
| --- | --- |
| `CONTRIBUTING.md` | `4e4fce79cc1c6d50f2872b1121716bab9913b10d8db456c7162ddbbd34984b4b` |

## Findings

No blocking or nonblocking findings identified in the reviewed change.

The policy keeps incomplete work and unresolved maintainer or manual-evidence
gates in draft. Auto-merge requires completed independent review and no unresolved
approval gates. Required CI, exact-head validation, current-base requirements and
normal protected squash merging remain mandatory. Material changes require
additional review; invalidated review or authorization requires disabling
auto-merge and returning to draft. Deferred evidence outside a PR's acceptance
scope is not treated as passed.

No author dispositions are required.

## Validation and limitations

Inspected the diff and full contributing policy; the whitespace check passed.
This is a documentation-only review. No runtime tests were necessary or run.
The change does not itself configure GitHub settings or prove that repository
protections enforce these requirements. The coordinator must verify those
settings and actual checks before enabling auto-merge. This report is not a
guarantee that future PRs satisfy the policy.
