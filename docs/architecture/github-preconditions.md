# GitHub merge precondition assessment

Status: API assessment dated 2026-10-01; constrained disposable-demo assumption accepted by the maintainer on 2026-10-03. No adapter or live demo implemented. This concerns Vollmacht's proposed protected demo operation, not the maintainer-authorized development PR workflow.

The synchronous [REST PR merge endpoint](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request) accepts an expected head `sha`, but no expected base name or base commit. The [GitHub-maintained GraphQL schema](https://github.com/octokit/graphql-schema/blob/master/schema.graphql) similarly exposes `expectedHeadOid` for `mergePullRequest`, not an expected base. These checks protect the head, not the complete candidate operation.

Inference: a fresh metadata read followed by merging leaves a race if another authorized actor retargets the PR between those calls. A local lock cannot exclude remote writers. GitHub says conditional mutation requests are unsupported unless explicitly documented; [conditional-request guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests) does not establish an `If-Match` workaround here.

The maintainer explicitly chose the disposable-repository assumption described below. This resolves the demo-scope choice, not the missing server precondition. Simulations can test stale-base rejection but cannot establish atomic remote enforcement. Live execution remains unimplemented and must stay disabled until its separate implementation, review and test gates pass.

Do not silently substitute asynchronous merging, a merge queue or direct branch merging. These have different execution and policy semantics; they are not interchangeable implementations of the currently proposed exact PR action. Unknown outcomes remain consumed and must not trigger an automatic write retry.

## Accepted constraint for the first live demo

The maintainer's decision permits a deliberately constrained demo in a user-selected disposable repository, under an explicit operating rule that nobody retargets the PR during approval or execution. It does not authorize production-repository use or assert that Vollmacht can enforce that operating rule against another authorized remote writer.

Simulation remains the default. Future live mode must be a deliberate opt-in for an identified disposable fixture, with the normal per-operation human approval. This decision does not itself select a repository, create resources, grant credentials or approve a particular merge.

The adapter must still resolve the numeric repository identity, perform fresh head/base checks, reject observed changes, and send the approved head SHA as the merge request's server-enforced precondition. Do not represent a preflight read as atomic base protection. If the operator cannot maintain the no-retargeting assumption, use simulation rather than claiming the live demonstration satisfies the full base constraint.

Before implementing the live-demo milestone, recheck the current documented API profile and carry this limitation into the fixed approval display, adapter tests, threat model and quickstart. Cover stale-head and observed stale-base rejection, require the disposable-fixture marker, and retain the consumed/unknown-result behavior without automatic write retry. These are pending implementation criteria, not completed safeguards.

The rest of P06 remains proposed. This narrow decision does not waive protected key storage, trusted enrollment, current-state checks, replay resistance or any other architecture acceptance gate.
