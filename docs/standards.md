# Standards and interoperability

Research snapshot: 2026-09-20. Vollmacht does not currently implement an agent authorization standard or expose OAuth/GNAP endpoints. The [design baseline](design-baseline.md) describes a proposed local protocol, not a released interoperable format. The [source register](standards-sources.md) records exact draft revisions, authors, dates and maturity.

## Position

Vollmacht's first integration is a local enforcement service using GitHub's existing API. GitHub need not understand a Human Mandate. The service must retain control of the write credential; an agent with equivalent direct GitHub access can bypass it. Standards adapters come later, behind explicit profiles and interoperability tests.

An approval assertion, an issuer signature, agent authentication, policy authorization and successful execution are separate facts. None substitutes for the others. A remote verifier cannot infer local replay consumption, current revocation state or successful GitHub execution from a signed artifact alone.

## Emerging IETF work

These are proposed mappings, not conformance claims. Individual submissions are not IETF consensus. Even working-group drafts can change before publication.

| Work and source sections | Possible relationship | Gap before interoperability |
| :--- | :--- | :--- |
| [Agent Authorization Envelope, revision 02](https://datatracker.ietf.org/doc/html/draft-kroehl-agentic-trust-aae-02), section 2 | Mandate action and constraints resemble `credentialSubject.aae.mandate.actions` and `constraints`; agent identity resembles `credentialSubject.id`; lifetime and consumption relate to `validity`. | AAE uses a VC/DID model and requires EdDSA/Ed25519 in its JOSE profile. Vollmacht proposes a local trust registry and Apple P-256/ES256. Field similarity is not wire compatibility. Its single-use state also cannot make independently deployed verifiers share a consumption decision. |
| [AI Identity Management System, revision 00](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims-00), sections 6, 7, 10 | Separates workload identity, credentials and delegated authorization. This supports keeping the agent key distinct from the person's passkey. | The WIMSE draft expects WIMSE identifiers and credential provisioning. A local enrolled key is not automatically a WIMSE identity. This is the adopted successor to `draft-klrc-aiagent-auth`, not merely the older individual proposal. |
| [Agent grants, revision 02](https://datatracker.ietf.org/doc/html/draft-mishra-oauth-agent-grants-02), section 6 | Consent, resource restriction, sender-constrained tokens and attenuated exchange resemble the desired authorization boundaries. | It profiles OAuth/JOSE. Vollmacht has neither an authorization server nor OAuth token issuance. A future bridge must preserve principal, current actor, resource and expiry without widening authority. |
| [Actor chain, revision 01](https://datatracker.ietf.org/doc/html/draft-mw-oauth-actor-chain-01) | Differentiates declared history from cryptographically verified delegation steps. | v0 deliberately has one enrolled agent and no subdelegation. It implements none of the draft's chain profiles or actor-signed step proofs. |
| [Transaction Tokens, revision 11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11), sections 13.12 and 13.13 | A future service integration could carry transaction context after local approval. | A Transaction Token is neither a caller authentication credential nor an OAuth access token. Context propagation does not replace mandate verification, policy or execution reservation. |
| [Transaction Tokens for Agents, revision 02](https://datatracker.ietf.org/doc/html/draft-araut-oauth-transaction-tokens-for-agents-02) | Agent-specific `agentic_ctx` could describe a larger workflow surrounding an approved operation. | This is an individual extension, not the OAuth WG base draft. v0 has no token service, replacement flow or agent-chain context profile. |
| [Identity Chaining, revision 17](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17) | A later enterprise adapter could bridge an authorized principal/actor into another trust domain. | Token exchange and JWT authorization grants require participating authorization servers and explicit trust. Local credential enrollment alone supplies neither. |
| [Authorization Evidence Challenge, revision 07](https://datatracker.ietf.org/doc/html/draft-schrock-ae-challenge-07) | An executor could request missing evidence for an exact operation. | This application-level evidence challenge is not the WebAuthn challenge. Answering it does not itself authorize or reserve execution. No such transport is implemented. |
| [Authorization Evidence Chain, revision 06](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-evidence-chain-06) | A future profile could treat a Human Mandate as one evidence input with its own native verifier. | Satisfied evidence requirements are not an authorization or execution result. A profile must pin action semantics, trusted issuers, evidence requirements and executor policy. |

## Published building blocks

| Reference | Intended use or mapping | Important boundary |
| :--- | :--- | :--- |
| [RFC 8785, JCS](https://www.rfc-editor.org/rfc/rfc8785.html) | Canonical bytes for the proposed mandate digest. | Informational, Independent Submission stream; not an IETF Standards Track authorization protocol. P06 must define restricted inputs and vectors, including duplicate-key and number handling. |
| [RFC 7515, JWS](https://www.rfc-editor.org/rfc/rfc7515.html) and [RFC 7518, algorithms](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4) | Proposed issuer envelope using ES256 and fixed-width signature encoding. | A valid signature does not establish trust in an envelope-supplied key. P06 must pin algorithms, headers, signing input and registry rules. |
| [RFC 8693, Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1) | Principal could map to `sub`; acting agent to `act`. | Nested `act` already exists: outer actor is current; previous actors are informational, not access-control inputs. Nesting alone is not cryptographic proof of each delegation. No exchange endpoint exists in v0. |
| [RFC 9396, Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html) | A future `authorization_details` type could carry the GitHub action, resource and exact head SHA. | Requires an agreed type/profile. A request is not evidence of human approval and does not provide execution replay prevention. |
| [RFC 9449, DPoP](https://www.rfc-editor.org/rfc/rfc9449.html) | Future OAuth adapter could bind access tokens to an agent key. | DPoP binds method and URI, not arbitrary HTTP body contents or human intent. It cannot replace exact-operation mandate binding. |
| [RFC 9635, GNAP](https://www.rfc-editor.org/rfc/rfc9635.html) | Grant interaction, client keys and access rights offer a future delegation bridge. | v0 is not a GNAP client or authorization server. Translating a mandate needs explicit resource semantics and trust, not just renamed fields. |

## WebAuthn and FIDO boundary

[WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/) is a W3C Recommendation dated 2026-08-25, not an IETF draft. Sections 6 and 7 define authenticator data and verification. A successful assertion binds authenticator data to the hash of original client data, including the challenge and origin. User verification is not universal proof of humanity, a guarantee of Touch ID, or proof that the person understood the displayed operation. Biometric material is not delivered to the relying party. Synced credentials and signature-counter behavior must not be mistaken for unique-device or perfect clone detection.

Vollmacht proposes a challenge derived from domain-separated canonical mandate bytes containing a fresh random nonce. The browser spike currently demonstrates random-challenge authentication only. A supported custom-challenge API and independent negative vectors remain a gate; do not rewrite library-private state or change only the browser's challenge. Referencing Level 3 here does not claim complete Level 3 implementation by the selected library.

## x401 comparison

[x401's specification](https://x401.proof.com/spec/latest/) is a separate project, not an IETF standard. It describes HTTP proof requirements and presentations using OpenID4VP/DCQL. Its delegation/evidence discussion allows additional credential and actor-evidence mechanisms, but does not itself define Vollmacht's mandate format. Agent binding is optional in that specification; an adapter for agent authorization must require and verify the appropriate binding rather than assume it.

The useful distinction is evidence transport versus enforcement: x401 can describe how a service requests proof; Vollmacht intends to decide whether a particular locally mediated GitHub operation may execute. A later adapter would need an agreed credential/profile, audience and exact-action binding, trusted verification rules and replay handling. No x401 interoperability is claimed. This comparison uses the live specification as observed on the research date, not a frozen release.

## Decisions for P06

1. Keep v0 local, single-agent and single-operation. Do not import DID, VC, OAuth or chain machinery merely to resemble draft fields.
2. Freeze canonicalization and domain separation only after the mandate-derived challenge spike succeeds, or record a reviewed alternative with changed security claims.
3. Keep source credential evidence, issuer trust, agent proof, policy and atomic replay reservation separately testable.
4. Fail closed when an adapter cannot preserve action, resource, constraints, principal, actor, audience or lifetime. Unknown remote execution results must never become automatic retries.
5. Before claiming any external profile, add bidirectional vectors, independent implementation tests and negative cases for audience substitution, actor substitution, widening and replay.

Refresh the source register before P06 and before release: inspect each Datatracker status and latest revision, follow replacements, compare substantive changes, and update mappings through a reviewed PR. This research does not close the WebAuthn or durable Apple key-storage gates.
