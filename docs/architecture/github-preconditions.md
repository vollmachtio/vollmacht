# GitHub merge precondition assessment

Status: research gate, 2026-10-01. No adapter or live demo implemented. This concerns Vollmacht's proposed protected demo operation, not the maintainer-authorized development PR workflow.

The synchronous [REST PR merge endpoint](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request) accepts an expected head `sha`, but no expected base name or base commit. The [GitHub-maintained GraphQL schema](https://github.com/octokit/graphql-schema/blob/master/schema.graphql) similarly exposes `expectedHeadOid` for `mergePullRequest`, not an expected base. These checks protect the head, not the complete candidate operation.

Inference: a fresh metadata read followed by merging leaves a race if another authorized actor retargets the PR between those calls. A local lock cannot exclude remote writers. GitHub says conditional mutation requests are unsupported unless explicitly documented; [conditional-request guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests) does not establish an `If-Match` workaround here.

Keep live PR merging disabled until either an effective server precondition is established, the user explicitly accepts a disposable-repository assumption excluding concurrent retargeting, or another consequential operation is selected. The latter choices change the guarantee or adapter scope and need user direction. Simulations can still test stale-base rejection but cannot establish atomic remote enforcement.

Do not silently substitute asynchronous merging, a merge queue or direct branch merging. These have different execution and policy semantics; they are not interchangeable implementations of the currently proposed exact PR action. Unknown outcomes remain consumed and must not trigger an automatic write retry.

Before the live-demo milestone, recheck the current documented API profile and record the chosen limitation or operation in an accepted ADR, fixed approval display, adapter tests and threat model. No weaker live guarantee is accepted by publishing this assessment.
