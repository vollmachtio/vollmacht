# Deterministic header decision adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/adversarial_roadmap_november`, separate from the author. Scope: new deterministic-header decision and accompanying mandate/enrollment-profile edits against `2e691f3490aaae1211ec5581df70c280a728a9ef`. The maintainer approved the fixed-order direction with controlled agility. This review does not accept the full P06a package, choose a production library or qualify a provider.

## Reviewed source identity

| Source | SHA-256 |
| :--- | :--- |
| `docs/architecture/deterministic-headers.md` | `8eb9a20834b2e91eb20ed917e508a033dfbd34351c981ad1d9594cbba0302af1` |
| `docs/architecture/mandate-contract.md` | `dd16ce07a07698d113b263c17561c8077e1e2f73fe757b820b25355226ca6591` |
| `docs/architecture/agent-enrollment-profile.md` | `a6eb23f80671d6a1fe9c35db2b194f9082cc60e41fbdabea821703db512976ab` |

## Findings and disposition

No actionable findings or unresolved blockers identified within this design-decision scope. No author correction was requested. This is not evidence that the revised profile is implemented or that historical fixtures already test it.

## Adversarial checks

- The byte profile fixes all three members and their order, disallows whitespace/escapes/extra bytes, bounds decoded header size and requires canonical base64url. The permitted type and key-ID alphabets can be represented without escapes. Semantic JSON equivalence does not accidentally admit the prior ordering.
- Header shape and duplicate/unknown-field rejection precede general JOSE parsing. Original signing input must be verified; rewriting an attacker-supplied header to expected order is expressly prohibited.
- The expected type is operation-specific. Type, algorithm, key ID, trusted provider handle and registered public key must be bound before signing. A factory receiving only a handle cannot establish that binding. Existing execution and pending-enrollment key-resolution rules remain in their respective candidate contracts.
- Payload JCS, domain-separated digests, raw WebAuthn evidence, execution challenge binding and durable reservation identity are unchanged. The revision does not add issuer-only authorization, detached payloads, embedded keys or algorithm negotiation.
- ES256 remains the only supported algorithm. Future agility requires an authenticated discriminator, trusted profile selection, cross-profile/downgrade tests and an explicit retirement policy; a released version cannot silently change meaning. No trial verification or unknown-algorithm fallback is permitted.
- Revised independent vectors for all three JWS types, rejection of old-profile signatures and production strict-gate validation remain required. Historical fixtures are retained as old-profile evidence, not passed evidence for the revised profile. The jsonwebtoken experiment and OpenSSL verification do not imply generic decoder acceptance or complete JCS conformance.

## Validation and limits

Read all three sources and the actual tracked-file diff, including surrounding mandate and enrollment verification rules. Independently checked whitespace, final newlines and relative Markdown file targets for all three files; checks passed. Fragment anchors and external URLs were not revalidated in this documentation-only delta.

No new code tests were run for this decision because no executable behavior changed. In particular, passing historical byte/signature tests cannot validate the changed header profile. Future independent revised vectors and implementation tests remain acceptance work. No authored source, native state, signing configuration or GitHub state was changed by this reviewer; only review reports were written. Exact integrated-head CI and review of material deltas remain required before merge.
