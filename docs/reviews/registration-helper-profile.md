# Registration helper profile adversarial review

Date: 2026-11-01. Reviewer: independent agent `/root/contract_revision`, separate from author `/root/p06_acceptance_audit`. Scope: proposed `docs/architecture/registration-helper-profile.md`, including the author's correction after review. This is a document review, not P06a acceptance or implementation qualification.

Reviewed source SHA-256: `fa8daa2fcde9c1dfc04838d4bf7c1b28cdc7a719b5caeef4665c03280dcdca6e`.

Also reviewed the coordinator's two-paragraph consistency delta in `docs/architecture/enrollment.md`, final SHA-256 `c9b6ba4efa9dd5ebfe64ccda9792149d4b905bb10a6bfaaef0fa1583cda0ba72`. This delta replaces original/raw COSE representation claims with validated library-returned key bytes and separately retained original registration evidence. No acceptance or enrollment authority is added.

## Finding and disposition

**Medium, resolved: original COSE key bytes were promised although the selected library re-encodes them.** The initial proposal required the helper to return original extracted key bytes rather than a reconstructed key. Installed SimpleWebAuthn 14.0.3 `esm/helpers/parseAuthenticatorData.js` decodes the credential CBOR and re-encodes it before returning `credentialPublicKey`; `verifyRegistrationResponse` exposes that value in its result. Treating this result as exact original evidence was an unsupported contract and could motivate an unreviewed custom extractor.

The author changed the response to the maintained verifier's validated COSE representation, explicitly distinguished it from original attestation encoding, and retained the complete original attestation object and client data as separate evidence. Exact original credential-key subbytes are not required. The coordinator also reconciled the earlier enrollment wording; both changed paragraphs were reviewed against this distinction. The final source was re-read; this resolves the blocker for the proposed-document scope.

No unresolved blocking findings remain in that scope.

## Adversarial checks

- Registration version 2 and assertion version 1 have separate exact schemas and trusted operation selection. There is no retry using another decoder, inferred version upgrade or registration mode inserted into the assertion interface.
- The 16,384-byte attestation and 4,096-byte key bounds are proposed compatibility limits, not claims established by past browser tests. Full frame limits and encoded/decoded bounds still apply. Oversize evidence rejects.
- The `none` restriction is explicit and narrower than general WebAuthn. The installed verifier rejects nonempty `attStmt` for `none`; the proposal additionally requires the verified returned format and does not mistake requested options for evidence of authenticator provenance. Fresh candidate activation remains mandatory.
- Both coordinator and helper must apply the reviewed client-data syntax policy. Its 12,288-byte and 16-container limits match the existing assessment, and signed data remains separate from the narrower eight-container outer protocol. Cross-runtime agreement and registration-path integration remain required, not assumed from the experiment.
- Three-way credential ID equality is required, closing the exact mismatch documented by the registration characterization. Maintained key validation must check curve membership, not merely coordinate widths or COSE labels; the actual API remains an acceptance task.
- A matching helper response can create only a pending candidate after deadline, stage and revision checks. It cannot enroll, replace a registry key or authenticate an administrator. Registration does not authenticate a user handle; trusted pending state provides that association.
- Activation and retained-evidence checks use version 1 fields with separately trusted context. Rechecking uses original counters and cannot mutate them again. Profile/status/revision checks remain with the coordinator; absent profile fields in the unchanged assertion wire do not select a new profile.
- Controller lifecycle, capability consumption, delayed success and commit-failure cases remain required. Native qualification, the new browser flow and the option-generation boundary are not marked complete.

## Evidence and validation limits

Read the complete proposal before and after correction, relevant enrollment/provider/cryptographic-profile contracts, the experimental assertion protocol, client-data syntax assessment, registration identity-binding assessment, current helper implementation and registration characterization tests. Inspected installed SimpleWebAuthn 14.0.3 source directly:

| Source | SHA-256 |
| :--- | :--- |
| `esm/helpers/parseAuthenticatorData.js` | `625f27deea6f080a883351a2e444061526d420004bcac313d3cd1f035a9bf433` |
| `esm/registration/verifyRegistrationResponse.js` | `15651d05448b8623cf06c8abbadd9c1679342f9d34151c75d7d6fe3473ecf8e5` |

These are source observations tied to the installed package, not a fresh library audit or new runtime evidence. No tests were run, no native service or credential was accessed, and no authored source was edited by this reviewer. Only this report was written. Exact-head CI, independent fixtures, API qualification and explicit P06a acceptance remain required before implementation. Material source changes require delta review.
