# November standards refresh adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from the standards author. Scope: the uncommitted changes to `docs/standards.md` and `docs/standards-sources.md` against HEAD `be8d74342bb9c7986faf358a9e95bd459d72b4c4`. Other worktree changes, including provider-contract design, are outside this review.

## Reviewed source identity

| Source | SHA-256 |
| :--- | :--- |
| `docs/standards.md` | `5aa934ffcf2c17a7f275b1417b28b26968943569f3b301b3118046e4e14afd74` |
| `docs/standards-sources.md` | `0a0de3c2445da00751a1b97548387640af748762cff43adb3488092a27688b78` |

Hashes identify reviewed source bytes before commit; the report is not included in its own source manifest.

## Findings and disposition

No actionable findings or unresolved blockers identified within this documentation scope. No author correction was required. This review does not certify any draft's security or Vollmacht's interoperability.

## Independent primary-source checks

Opened all eleven current Datatracker entries linked from the register and checked revision, author, date and maturity metadata. For changed or new entries, also inspected relevant current document headers and body passages:

- [Actor Chain 03](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/): November 1 header and five authors match. Individual submission with intended Standards Track status, not an adopted standard. Sections 5 and 6 support the six-profile distinction, actor evidence and authorization-server acceptance; task success and live presenter binding remain separate.
- [Transaction Tokens for Agents 03](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/): October 31 header, Ashay Raut and intended Informational status match. The body includes `agentic_ctx` and token-service replacement at agent transitions. The mapping does not equate that context with human approval.
- [Authorization Evidence Chain 08](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/): October 4 header, Iman Schrock and intended Informational status match. The abstract and verification section distinguish evidence satisfaction from executor authorization and effects.
- [Hulea Agent Mandate 01](https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/): November 1 header, Claudiu Hulea and individual Standards Track intent match. Checked the authority/grant separation and `principal`, `cnf.jkt`, `perms` and `mandate+jwt` mapping references. These are explicitly conceptual correspondences, not equivalent identifiers, trust roots or wire formats.
- [Asor Agent Delegation Chain 03](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/): October 27 header, Rafael Asor and individual Standards Track intent match. The scope-vocabulary and principal-standing limitations support the interoperability cautions; offline chain validation does not replace local stateful enforcement.

The other six retain the listed revisions. In particular, [Identity Chaining 17](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) remains in the RFC Editor queue awaiting first editor, while [Transaction Tokens 11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) remains at WG Consensus: Waiting for Write-Up. Their August 21 status-update dates are distinguished from document dates. Replacement links agree with the register.

The review used current Datatracker pages containing document headers and bodies. It does not claim to have fetched every versioned HTML endpoint. The author's Actor Chain endpoint limitation is retained rather than converted into a successful-retrieval claim. Published RFC, WebAuthn and x401 observations remain explicitly dated October 1; this review did not independently refresh their unchanged substantive mappings.

## Scope and gate checks

The refresh does not claim standards implementation, expand MVP to multi-hop delegation, import new protocol dependencies or accept P06a/P06b. It retains local replay, current trust and revocation limitations, preserves the separation of cryptographic validity from authorization and execution, and requires independent interoperability tests before future external-profile claims.

Independently ran the Git whitespace diff check for these two files successfully. A read-only Ruby check confirmed all relative Markdown file targets exist; fragment anchors were not validated. No code suites were run because no executable behavior changed. No source edits, native actions or external writes were performed. Exact integrated-head CI remains required, and material changes after these hashes require review of the delta.
