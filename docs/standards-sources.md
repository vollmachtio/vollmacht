# Standards source register

Checked 2026-10-01 against primary document headers and Datatracker status pages. This is a metadata snapshot, not an archived copy of each source. Versioned links pin the researched text; status links are live. Dates below are document-header dates, not necessarily upload or last-change dates. Intended status is an aspiration, not publication or endorsement.

| Versioned document | Authors | Document date | Status at check |
| :--- | :--- | :--- | :--- |
| [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/html/draft-kroehl-agentic-trust-aae-02) | Lars Kersten Kroehl | 2026-09-06 | [Individual, active; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/) |
| [draft-ietf-wimse-aims-00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00) | Pieter Kasselman; Jeff Lombardo; Yaroslav Rosomakho; Brian Campbell; Nick Steele; Aaron Parecki | 2026-09-15 | [WIMSE WG document; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) |
| [draft-mishra-oauth-agent-grants-02](https://datatracker.ietf.org/doc/html/draft-mishra-oauth-agent-grants-02) | Sanjeev Kumar | 2026-08-30 | [Individual, active; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-mishra-oauth-agent-grants/) |
| [draft-mw-oauth-actor-chain-01](https://datatracker.ietf.org/doc/html/draft-mw-oauth-actor-chain-01) | A Prasad; Ramki Krishnan; Diego Lopez; Srinivasa Addepalli | 2026-06-15 | [Individual, active; intended Standards Track; I-D Exists](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/) |
| [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11) | Atul Tulshibagwale; George Fletcher; Pieter Kasselman | 2026-07-30 | [OAuth WG; intended Standards Track; WG Consensus: Waiting for Write-Up; I-D Exists](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) |
| [draft-araut-oauth-transaction-tokens-for-agents-02](https://datatracker.ietf.org/doc/html/draft-araut-oauth-transaction-tokens-for-agents-02) | Ashay Raut | 2026-05-22 | [Individual, active; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/) |
| [draft-ietf-oauth-identity-chaining-17](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17) | Arndt Schwenkschuster; Pieter Kasselman; Kelley Burgin; Michael J. Jenkins; Brian Campbell; Aaron Parecki | 2026-07-19 | [OAuth WG; header: Standards Track; Datatracker intended: Proposed Standard; RFC Editor Queue, awaiting first edit; not yet an RFC](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) |
| [draft-schrock-ae-challenge-08](https://datatracker.ietf.org/doc/html/draft-schrock-ae-challenge-08) | Iman Schrock | 2026-09-28 | [Individual, active; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/) |
| [draft-schrock-ep-authorization-evidence-chain-07](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-evidence-chain-07) | Iman Schrock | 2026-09-28 | [Individual, active; intended Informational; I-D Exists](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/) |

The agents Transaction Tokens document's header says May 22 while Datatracker's last-update date says May 21. These are recorded as distinct metadata, not silently reconciled. Other status pages can likewise have changes after the document date. Some Datatracker intended-status fields are unset even when a document header declares an intended status; the table uses the header for that column.

Replacement tracking: AIMS replaces `draft-klrc-aiagent-auth`; the araut Transaction Tokens document replaces `draft-oauth-transaction-tokens-for-agents`; Authorization Evidence Chain replaces `draft-schrock-ep-action-evidence-graph`. Do not treat replaced documents as separate current protocols.

Other primary sources and precise mappings are linked in [standards.md](standards.md). WebAuthn Level 3's dated Recommendation is pinned there. x401's live specification is explicitly unversioned in this snapshot and requires rechecking before an adapter is designed.

## Refresh notes, 2026-10-01

All nine Datatracker entries were rechecked. Seven retain their previously recorded revisions and maturity; the two Schrock drafts above advanced. Identity Chaining remains in the RFC Editor queue, not a published RFC. WebAuthn's latest published Level 3 still points to the August Recommendation. x401's live page was rechecked for the evidence-transport and optional agent-binding comparison; no immutable release is inferred from its URL.

Evidence Challenge 08 specifies atomic nonce/capacity accounting and bounded refusal state (section 2.7). Evidence Chain 07 separates native cryptographic verification from relying-party acceptance under pinned trust inputs (sections 5, 6 and 18). These are useful review questions for Vollmacht, not new dependencies or conformance claims. The source set is a targeted follow-up, not an exhaustive survey of every new agent draft.
