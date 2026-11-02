# Candidate authenticated cryptographic profiles

Status: **PROPOSED**, 2026-11-01. The maintainer requested explicit algorithm versioning for future post-quantum migration and approved deterministic protected headers. This proposes the discriminator and binding rules now, not another algorithm, protocol freeze, library adoption or post-quantum guarantee. It supplements the [mandate contract](mandate-contract.md), [agent enrollment profile](agent-enrollment-profile.md) and [header decision](deterministic-headers.md).

## Schema version and cryptographic profile

Keep application `version: 1` for object-schema semantics. Add required string `crypto_profile`, bounded to 64 printable ASCII bytes, with the sole supported value `vollmacht-local-es256-v1`. The bound does not permit arbitrary names: every other value rejects. This identifier is an immutable named cryptographic suite, not a negotiation preference or semantic version to compare lexically. Future suite changes require another reviewed exact identifier; a schema change independently requires a reviewed schema version. A future profile cannot override incompatible field sizes or semantics merely by changing its name.

The field appears in exactly these signed or challenge-bound objects:

| Object | Location and authentication |
| :--- | :--- |
| Human approval payload | Top-level `crypto_profile`; included in JCS payload and domain-separated mandate digest, hence in the exact WebAuthn challenge |
| Issuer envelope | No second field; its payload contains the field, covered with retained evidence by the issuer JWS and envelope digest |
| Agent execution proof | Top-level `crypto_profile`; covered by the agent JWS, equal to the approved payload and trusted pending execution context |
| Agent-enrollment proposal A | Top-level `crypto_profile`; included in canonical A and the administrator's passkey challenge |
| Agent-enrollment possession proof B | Top-level `crypto_profile`; covered by the candidate JWS, equal to A and the trusted pending enrollment context |

Do not add the field to the operation object, display object, JWK or protected header. The operation digest remains a digest of the exact operation, not an authorization object by itself. Full mandate/envelope digests and proofs carry the profile binding. Header bytes remain exactly the approved `typ`, `alg`, `kid` order; `alg` must match the locally resolved profile's role, never select it.

## Initial profile, by role

`vollmacht-local-es256-v1` pins all of the following:

| Role | Required mapping |
| :--- | :--- |
| Issuer envelope signature | P-256 public key, JOSE ES256, original compact signing input, 64-byte raw `r || s` signature |
| Agent execution and enrollment possession | P-256 public key, JOSE ES256, original compact signing input, 64-byte raw `r || s` signature |
| WebAuthn approval, activation and administration | Enrolled EC2/P-256 COSE ES256 credential; complete maintained WebAuthn verification with required UP/UV and trusted RP/origin; original signed byte strings retained |
| Mandate, operation, envelope and administrative binding digests | SHA-256 with the domain bytes already specified by the corresponding contract |
| Agent public-key identifier | RFC 7638 SHA-256 thumbprint of the required public EC JWK members |
| Serialization | Restricted application objects canonicalized with JCS; exact deterministic protected headers; strict original-byte validation before cryptographic verification |

This mapping separates roles without introducing multiple negotiable fields. A future profile could change one role while retaining another, but must name every mapping and its security limitations. In particular, a post-quantum issuer signature cannot make a classical agent proof, passkey or delegation chain post-quantum secure. No post-quantum profile, hybrid combiner or algorithm is selected here. Synced passkeys and user-verification limitations are unchanged.

## Trusted selection and key/provider binding

Select the expected profile from administrator-controlled installation policy before constructing an approval or enrollment proposal. Registry records bind the profile, role, key type/algorithm, public key and current revision. Issuer metadata additionally binds the registered key ID to its configured provider and exact opened handle. Stored pending ceremonies, approved records and original evidence-verification context retain the expected profile and relevant revision snapshots. Submitted profile strings are never registry updates or provider-selection instructions.

At signing, compare the local profile, role, requested JWS type, header algorithm/key ID, registered public key and selected signer handle before constructing exact header bytes. A signer claiming an algorithm is not evidence that it holds the intended key. A mismatch denies without selecting another signer. At verification, strictly bound and parse the object, then require its profile to equal the locally expected allowed profile before selecting that profile's verifier. Resolve keys only through the already authorized issuer/agent registry or immutable enrollment context. Compare the fixed header mapping and verify original signing-input bytes. Cryptographic success does not substitute for those comparisons.

Credential activation occurs before the credential is enrolled. Its pending trusted bootstrap context already fixes the profile and permitted credential algorithm; registration cannot negotiate an alternative through browser input. The random registration/activation challenges and their existing state binding remain unchanged. A profile field in a mandate does not retroactively validate an enrollment performed under another algorithm policy.

Recheck the profile and policy/registry revisions at issuance, enrollment commit and reservation. A policy change invalidates unreserved authority under the existing revision rule rather than relabeling old records. Retained assertions are rechecked with their original profile/context and current permission to use that profile, without updating counters again. An artifact supplied without a trusted approval record remains non-executable.

Missing, malformed, unknown, disabled or context-mismatched profiles deny. Missing legacy fields are not filled with the initial value; unsupported artifacts are never retried under another algorithm or old header profile. Header algorithm mismatch, wrong key type and cross-role proof substitution deny even if a general library verifies the signature. Agent-facing denial remains `unsupported_profile` for unsupported profile selection and the existing bounded categories for other failures; no raw cryptographic diagnostics leak.

## Future migration and acceptance evidence

Before enabling a second profile, independently review its role mappings, schemas/size bounds, cryptographic libraries, key enrollment/provenance, providers, exact signing inputs, verification rules and security claims. Define administrative enablement and retirement, affected policy/registry revisions, explicit handling of outstanding approvals and retained evidence, and downgrade/cross-profile tests. Old and new acceptance, if ever concurrent, must be explicit trusted policy, not header-driven trial verification or automatic fallback. Key replacement and rotation remain unsupported in this MVP; this field does not implement a migration command.

The next revised fixtures must include the field in all four payload objects and therefore regenerate affected challenge digests, raw signed assertions, envelope/proof bytes and signatures. Preserve historical fixtures under their historical names. Existing fixtures without this field do not validate the new proposal. No new domain strings are necessary for this pre-release proposal: the complete canonical object authenticates the field, and missing-field old objects are rejected.

Acceptance tests must include missing/unknown/disabled profiles, mutation without resigning, validly re-signed profile disagreement with trusted state, A/B and mandate/execution mismatches, header/key/provider role mismatches and legacy deterministic-header artifacts without a profile. Test that an unsupported selection never invokes another verifier/provider. Reuse the existing independent fixture generators and comparison paths rather than implement new primitives. This document remains proposed until reviewed successor vectors and the remaining P06a decisions are explicitly accepted.
