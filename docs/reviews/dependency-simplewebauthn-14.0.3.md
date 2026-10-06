# SimpleWebAuthn 14.0.3 dependency assessment

Reviewed 2026-10-05. Status: source assessment complete with the limits below; updated dependency execution and mandatory CI remain pending. This is not blanket merge approval.

## Reviewed artifact

Dependabot branch `origin/dependabot/npm_and_yarn/spikes/simplewebauthn/simplewebauthn/server-14.0.3`, commit `623c48c8670b9002f550d25abf4e299c5ca20fd3`. SHA-256 values computed from `git show` bytes, not the installed dependency tree:

- `spikes/simplewebauthn/package.json`: `5bc3b68f9966b76904d41e6116e24a50a333456ece0f9a5135e97bc51d56f956`
- `spikes/simplewebauthn/package-lock.json`: `5fd11b0e26ba668c3ff6237211c310a90bd4ff2a0e200737a1025f42aa7cb4fe`

The dependency delta changes the server pin from 14.0.2 to 14.0.3 and the corresponding resolved package URL and integrity. It does not update transitive package versions.

## Upstream evidence and downstream compatibility

The [14.0.3 release](https://github.com/MasterKale/SimpleWebAuthn/releases/tag/v14.0.3) and [upstream PR 809](https://github.com/MasterKale/SimpleWebAuthn/pull/809) describe deferring PQC capability detection from module initialization until a caller needs it. This is not universal warning suppression or a claim of PQC support by Vollmacht.

The coordinating reviewer retrieved PR 809's API file diff and supplied these exact changes for this assessment:

- `generateRegistrationOptions.ts` replaces the default algorithm array with `getDefaultSupportedAlgorithmIDs()`, which checks PQC support when called.
- `verifyRegistrationResponse.ts` imports and calls that function for its default algorithm list.
- `settingsService.ts` removes eager constructor detection and lazily caches the capability boolean using nullish assignment.

The independent reviewer directly read the published release and PR explanation. Its separate web retrieval of the file diff failed, so the three-file diff description above is coordinator-provided evidence, not an independently downloaded package-source comparison.

Downstream source inspection found no imports of `SettingsService`, the removed default array, or its replacement function. `session.mjs` passes `supportedAlgorithmIDs: [-7]` explicitly to both registration-options generation and registration verification. Consequently, those JavaScript default expressions are not selected by our calls; the upgrade should not widen our registration algorithms. This is a source-based inference pending execution.

`helper.mjs` separately checks COSE key type EC2, algorithm ES256 and curve P-256 before authentication verification. PR 809's described changes do not alter those checks or directly change authentication verification. This assessment does not prove the contents of the newly published npm tarball match the upstream diff.

The publisher's [SSRF advisory](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-j3h4-m3m2-7p7j) and [CRL-cache advisory](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-2g3p-m8c9-hhwh) list 14.0.2 as patched. This update is not described as newly fixing those issues. Fresh whole-lockfile advisory checks are still required.

## Required validation before merge

On the rebased PR with pinned Node 24.21.0, run the existing Ubuntu and macOS CI matrices without reducing coverage:

1. Install from the reviewed lockfile, run the package source/integrity/license checks and a fresh npm audit.
2. Run the full npm suite, including registration-options behavior, malformed evidence, helper recheck and original signed client-data tests.
3. Run the real Rust-launcher helper E2E tests, client-data syntax-gate integration and `dev.py measure` against the updated package.
4. Preserve all existing Rust checks, Swift checks and coverage collection. Confirm the final dependency diff and lockfile hashes before merge.

Any claim that live Safari or Chrome Touch ID was retested must have separate human-run evidence. Synthetic CI does not establish that result. No dependency installation, upgraded-version execution, hardware access or repository mutation other than this review document was performed by the independent reviewer.
