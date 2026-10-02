# P06 canonicalization assessment review

Scope: isolated serializer fixture tests and locked dependencies, with explicit workspace-check and dependency-audit integration. No production parser, accepted mandate schema or JOSE choice.

Independent reviewer: `mandate_design`, separate from spike author `durable_key_contract` and root integration author. No blocking findings. Reviewer checked installed serializer source, fixture claims, dependency isolation, audit option placement, CI invocation and ignored build artifacts. Independently ran formatting, strict Clippy and the fixture tests.

An optional coverage improvement was implemented and re-reviewed: a deliberately reverse-ordered map now tests sorting independently of serde_json's already-sorted map. All eight final tests pass. Duplicate-key collapse and numeric lexical erasure tests intentionally demonstrate unsafe pre-parser behavior; they do not approve those inputs for mandates.

Root independently reproduced the canonical fixture with Node 24.21.0 JSON.stringify over explicitly ordered ASCII members and computed both digests with Node crypto. Results match the committed literal byte/hash expectations:

- Experimental domain-separated digest: `31f269124304456ecda5c9e25beb7df82899f7727856d7f3589dce5836703258`
- Required-member EC thumbprint: `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`

Full workspace checks passed before the final additional test; the complete standalone formatting/lint/test checks were rerun after it. Both locked dependency graphs passed cargo-deny 0.20.2 against the repository policy. Existing duplicate-version warnings and policy entries unused by the smaller graph remain warnings, not waived advisory failures. Hosted exact-head CI remains required before merge.

Limits: these are experimental serializer vectors, not full JCS conformance, full mandate vectors or key-validation tests. Dependency unsafe code is outside the local crate prohibition. Strict bounded lexical parsing, complete independent protocol vectors, JOSE library assessment and P04b evidence still gate P06 acceptance and P07 implementation.
