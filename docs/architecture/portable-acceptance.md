# P06a portable contract acceptance record

Status: **PROPOSED acceptance record**, 2026-11-02. Authoring this record does not accept P06a or authorize production implementation. It becomes effective only when the PR containing this exact reviewed record and its manifest passes separate independent adversarial review, resolves all blocking findings, passes every required check on its exact integrated head, and is merged through the protected workflow. Until then P07 remains blocked. The merged record accepts the full portable contract described here, not a P07-only exception or P06b qualification.

The maintainer approved revising sequencing to separate portable acceptance from deployment qualification. This record exercises that approved scope; it does not authorize account changes, VM setup, native key operations, paid services or a live GitHub action. Review evidence must be linked in the accepting PR with its exact reviewed revision. Required CI and merge state are external evidence, not assumed by this document's presence.

## Normative scope and precedence

Upon effectiveness, the following manifest freezes the portable interpretation of the listed candidate documents. Their historical `PROPOSED` labels and statements that P06a remains pending describe their authoring stage; they do not independently undo this later acceptance. No historical experiment becomes production code or deployment evidence. Later byte or semantic changes require a reviewed contract revision and updated manifest/vectors.

Resolve only these documented overlaps as follows:

1. [Portable decisions](portable-decisions.md) settles library/provider ownership, exact parsing bounds and branch subset, fixed Rust-owned browser options, client-data policy, key validation APIs and supported MVP scope. Its choices supersede earlier unresolved-choice wording on those subjects.
2. [Cryptographic profiles](crypto-profiles.md) and [deterministic headers](deterministic-headers.md) define current profile binding and exact header bytes. They supersede historical JCS-sorted headers and payloads missing `crypto_profile`. No legacy implicit default or second accepted algorithm exists.
3. [Provider contract](provider-contract.md) defines process ownership, bootstrap phases, single lifetime agent slot and durable mutation/dispatch semantics. It supersedes earlier prose that might allow a second distinct agent key after disable or recover partial bootstrap automatically.
4. [Enrollment](enrollment.md), [agent enrollment](agent-enrollment-profile.md), [registration helper](registration-helper-profile.md) and [mandate contract](mandate-contract.md) retain their remaining exact schemas, trust and lifecycle requirements. Supported administrative operations are exactly `bootstrap`, `enroll_agent` and `disable_identity`. `replace_credential`, rotation and recovery operations reject before ceremony creation or state mutation. Replacement/rotation passages are future design context only; no replacement profile needs implementation for this release. The provider's retained lifetime slot remains authoritative.
5. The experimental assertion protocol contributes its version 1 wire fields, framing, child lifecycle, response/counter rules and fail-closed boundary only. Experiment-specific coordinator state and synthetic trust inputs are not portable production enrollment or durable replay protection. The separate signed-client-data policy is required on both production ingestion paths; it is not already integrated by this record.

This is not a general permission to resolve new contradictions by convenience. An unlisted material semantic conflict blocks the affected implementation until independently reviewed. No token-format provision can waive provider protection, current-state checks, registration activation or per-operation approval evidence.

## Normative document manifest

Paths below are repository-relative. Hashes identify complete UTF-8 file bytes, including their historical labels. **Refresh hashes and review material deltas before the accepting merge if any source changes.** In particular, the new portable decision packet and architecture index may still change during integration. This record does not include its own hash; the PR's reviewed revision binds it.

| Document | SHA-256 |
| :--- | :--- |
| `docs/architecture/portable-decisions.md` | `c725069be1484c5006f27363b6b2c5ffffb874a0c2b3096c41644940d8cbf405` |
| `docs/architecture/README.md` | `21ffb4ae6047a31d6033b03acfe993bd01d5c83c68a9f44887a6e1d031387d76` |
| `docs/architecture/mandate-contract.md` | `8f9e755c01b930aa408c6f7e8036baa5f3aae8db3fb9c842a3401756b84ec63f` |
| `docs/architecture/crypto-profiles.md` | `60b8d7409bca42e51e576f8f84cbbf32117352762f26522cf08522c2195d358a` |
| `docs/architecture/deterministic-headers.md` | `ae882f6a4e1209811100ecc6a2461f1e965c9fdfae51636bf3619b1bc1ee1b47` |
| `docs/architecture/enrollment.md` | `c9b6ba4efa9dd5ebfe64ccda9792149d4b905bb10a6bfaaef0fa1583cda0ba72` |
| `docs/architecture/agent-enrollment-profile.md` | `5450b2043178a061254a6e9071c61e8d37ea417d7d978eb170303aaab412b810` |
| `docs/architecture/provider-contract.md` | `186d3b70d599748b5cc4b17ee690f2a86e51b6cbe1373f163ce493446a092377` |
| `docs/architecture/registration-helper-profile.md` | `fa8daa2fcde9c1dfc04838d4bf7c1b28cdc7a719b5caeef4665c03280dcdca6e` |
| `docs/architecture/github-preconditions.md` | `e464cec7cfbfddf3822105fa9f4f99dda342962ee0f940778d7ba6d26cc98034` |
| `spikes/helper-protocol/README.md` | `4e8fa4cc669fafb5c07e4c0b991e3d80705ebb2aede7073bd628ce9e8b282bb5` |
| `spikes/helper-protocol/CLIENT-DATA.md` | `273a8ce4317b8a7d5897538cffc2af019c01ec1c064dbcf6ed6503075d305317` |

Only the adopted sections identified above are normative where a listed document also reports historical experiments. Linked references outside this manifest remain supporting evidence or separately qualified deployment work, not silently accepted implementation.

## Fixture manifest and interpretation

| Fixture | SHA-256 | Accepted interpretation |
| :--- | :--- | :--- |
| `spikes/canonicalization/fixtures/candidate-profile-vector.json` | `b5660d224a1dd6f07366bf002f91a317141bbba5256c16dc531b7c984b191215` | Current canonical payloads, deterministic headers, cryptographic profile and independently generated synthetic signatures/digest links for all three JWS roles |
| `spikes/helper-protocol/registration-vectors.json` | `036cd70624573010ab652cb0520a0a6aa58afad0d9e90f5ef9ac8131aae07278` | Version 2 structural request/result examples only; placeholder attestation/key bytes and simulated success are not valid enrollment evidence |
| `spikes/helper-protocol/vectors.json` | `003bf9bd2b3f0250cf88c6c898e82a85d4dd49677a53a6ff2d0f20a9e3fb7405` | Version 1 framing and transport examples only, not credential trust or authorization |
| `spikes/simplewebauthn/client-data-vectors.json` | `a5241a7339faa19dd911db606efd8b8362599bf6e9d1c94cec124c36b635a5ba` | Raw-client-data syntax acceptance/rejection only; syntax success does not establish WebAuthn validity |

These are minimum regression oracles, not exhaustive conformance suites. Registration fixtures and their model share authorship; independent review compares their meaning against the contract without claiming independent cryptographic validation. Historical `candidate-payload`, `candidate-expected`, `candidate-envelope`, `candidate-agent` and `candidate-enrollment` fixtures remain historical compatibility/negative evidence, not a second accepted current profile. New canonical payloads must preserve the profile field; a valid historical signature does not permit execution.

## Selected versions and evidence

The proposed adoption baseline is Rust 1.98.1; `serde_jcs` 0.2.0 via `to_vec`; `jsonwebtoken` 11.1.0 with default features disabled; OpenSSL Rust bindings 0.10.81; SimpleWebAuthn server 14.0.3; and Node 24.21.0. Existing serialization/base64 dependencies remain governed by the locked graphs and dependency policy, not replaced implicitly. The OpenSSL binding version does not identify or certify the platform's linked native library; implementation/release checks must record and audit that resolved backend. Dependency updates require their normal review/checks and compatibility tests, not a wire-profile change by accident.

Evidence includes [canonicalization assessment](../../spikes/canonicalization/README.md), [encoder assessment](../../spikes/jose/JSONWEBTOKEN.md), [verifier assessment](../../spikes/jose/VERIFIER.md), [registration API assessment](../../spikes/simplewebauthn/REGISTRATION-API.md), [registration transport model](../../spikes/helper-protocol/REGISTRATION-VECTORS.md) and their independent review reports. These establish the cited compatibility observations, not the existence of production guards or native qualification.

The dated standards mapping remains interoperability context, not draft compliance. Reviewed snapshot hashes: `docs/standards.md` = `5aa934ffcf2c17a7f275b1417b28b26968943569f3b301b3118046e4e14afd74`; `docs/standards-sources.md` = `0a0de3c2445da00751a1b97548387640af748762cff43adb3488092a27688b78`. No standards adapter or multi-hop delegation enters this acceptance.

## Allowed implementation and per-PR tests

Once effective, P07 and subsequent portable work may implement the full accepted interfaces in small coherent PRs. Each PR still needs independent adversarial review and exact-head required CI without weakening tests or coverage policy. Incomplete components cannot be exposed as an authorization system.

| Task | Required tests before that implementation is delivered |
| :--- | :--- |
| P07 bounded parsing and canonicalization | Duplicate decoded keys at each depth, integer lexical restrictions, UTF-8/surrogate/BOM errors, unknown/missing fields, exact raw/canonical byte and root-counted depth boundaries, base-ref boundary/forbidden cases, canonical equality and current independent digest vectors; property tests for accepted/rejected mutations |
| P08 issuer JWS/provider boundary | Original encoder callback bytes, fixed headers, profile/type/algorithm/key-ID/public-key/handle binding, one-time provider startup and failed initialization, unknown/expired handles, raw signature and wrong-key controls, malformed/signature-valid incompatible artifacts, no generic JWT-policy substitution; no runtime software fallback |
| P09 registry and WebAuthn evidence | Version 1/2 separation, independent valid/invalid cryptographic registration/assertion evidence, exact options bytes/deadline caps, three-way IDs, full key validation, dual client-data policy agreement, original-byte preservation, activation before enrollment, counter/revision races, late/cancelled helper results, current profile/status and read-only evidence recheck |
| Integrated provider/state work | Every specified bootstrap interruption and indeterminate result, preserved partial state, exclusive ownership through shutdown, one lifetime agent slot, no pre-restart approval/permit reuse, reservation/revocation races, at most one dispatch attempt and no dispatch after uncertain reservation; fake providers cannot reach live adapters |

Some P09 requirements land across the enrollment/helper sub-PRs and are integration exit criteria, not reasons to claim an isolated parser implements them. Track unimplemented interfaces explicitly. Review failures in semantics require contract revision; missing implementation tests must be completed with the affected code rather than reported as already passing during this document freeze.

## Gates not accepted here

- P06b concrete VM product, guest/host transport, shared-resource policy, runtime integrity, credential isolation, bootstrap-anchor mechanism and actual OS process-ownership enforcement.
- Physical P04b issuer restart/denial/lock-state and signing-identity qualification. Screen lock is not Keychain-lock evidence. No native provider or key-storage fallback is approved by portable adoption.
- New Chrome/Safari enrollment/activation and operation approval tests. Earlier browser experiments do not qualify the new fixed option profile or full flow.
- Live GitHub adapter/current API assessment, protected credential and disposable fixture. The accepted no-retarget assumption is not an atomic base-branch precondition and is not permission to execute a merge.
- Clean-machine distribution, supported native crypto/runtime versions, installation/update integrity, complete coverage enforcement, release artifacts and experimental v0.1 acceptance. GA remains outside scope.

All existing manual prohibitions and preservation of the personal `VollmachtSigningProbe` project remain unchanged. No further portable product-choice question is identified by this record; independent review may still find one. Until this record satisfies its effectiveness conditions, it is only a proposed full acceptance manifest.
