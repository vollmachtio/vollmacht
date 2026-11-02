# First release: v0.1

Status: release acceptance plan, revised 2026-11-01, not implemented guarantees. Version 0.1 is an experimental macOS developer release, not general availability or a sole production security control. The [execution plan](implementation-plan.md) separates P06a portable contract acceptance from P06b deployment qualification. No contract is frozen by this update; P04b physical evidence remains required for the corresponding live and release guarantees.

## Outcome

A developer can install Vollmacht on a supported Mac, enroll a platform passkey and an agent key, and run a repeatable demo in a disposable GitHub repository. The agent can read PR metadata without prompting. A merge requires a fresh approval of the exact operation, verified evidence, proof of the enrolled agent key, and a durable single-use reservation before GitHub receives the request. The initial product promise is protected execution with verifiable human approval, not a universal agent identity or delegation protocol.

Vollmacht receives no biometric data. WebAuthn user verification, including Touch ID when offered by the platform, is not proof of biometric identity, universal humanity, or comprehension of the displayed operation.

The executor must control the GitHub write credential independently of the demonstrated agent environment. If the agent can read that credential or invoke GitHub directly with equivalent authority, the demo does not establish enforcement. Same-user malware is outside the claimed isolation boundary.

The approved reference design direction places the agent in an isolated VM and the trusted executor and approval UI on the Mac. This records design approval only, not permission to configure a VM or evidence of a qualified deployment. Product selection, transport, shared resources and agent-denial tests remain part of P06b.

## Supported scope

- Local macOS first, initially Apple Silicon; publish the exact tested OS, browser, toolchain and hardware matrix. Do not infer support for untested versions or Intel Macs.
- Rust CLI and local service, a browser approval UI, a narrowly scoped trusted SimpleWebAuthn helper, and the Apple issuer-key path only after architecture acceptance.
- One enrolled principal and one configured agent are sufficient for the walkthrough. Registry checks must still reject unknown, disabled or mismatched credentials and agents.
- One exact capability: merge a benign documentation PR on github.com in an explicitly marked disposable repository. Read-only PR metadata is a separate policy path.
- One mandate, one exact operation, one configured executor audience, no delegation chain. Proposed lifetimes remain 120 seconds by default and at most 300 seconds, subject to P06a acceptance.
- Simulation is the default. A live merge requires a deliberate live invocation and physical approval. No destructive cleanup is automatic.
- The constrained live demo requires the documented no-retargeting rule throughout approval and execution. GitHub's atomic head-SHA condition does not establish an atomic base-branch condition. See [GitHub preconditions](architecture/github-preconditions.md).

## Release gates

All gates require evidence at the release revision. Test-only experiments are inputs to implementation, not substitutes for integrated behavior.

| Gate | Acceptance evidence | Execution tasks |
| :--- | :--- | :--- |
| R1: architecture and protected key lifecycle | Accepted P06a schema/vectors and provider contracts plus qualified P06b deployment, bootstrap and authority boundary; supported signed-key path with physical restart, denied-access and required lock-state results. Screen lock alone is not Keychain-lock evidence. Resolve failures before accepting any separately reviewed fallback; test providers never qualify for live use. | P04b, P05 refresh, P06a, P06b |
| R2: mandate and agent verification | Production parsing, canonicalization, issuer and WebAuthn verification, trusted enrollment and agent proof. Reject tampering, unknown keys, wrong origin/RP/challenge/audience/action/resource, missing UV, malformed signed data and expiry. Independently produced vectors and property tests exercise the contract. | P07 through P10, P13 |
| R3: durable single-use execution | SQLite state and migrations; concurrent attempts permit only one reservation. Crash/restart, revocation races, credential/agent disable, stale registry bindings and clock rollback tests fail closed. Reserved operations are never reused; uncertain remote outcomes are not automatically retried. Advanced rotation tooling is deferred, not these invalidation checks. | P11 through P13 |
| R4: usable human approval | Protected enrollment and admin path; exact immutable operation display; loopback defenses; cancellation and timeout recovery; complete browser-to-issuer integration. Physical Chrome and Safari matrix, with explicit support restrictions if needed. No second Touch ID prompt merely for issuer signing by default. | P14 through P17 |
| R5: constrained GitHub enforcement | Fixed policy, narrow API adapter and protected write credential. Request carries approved head SHA; altered resources fail. Demonstrate that the configured agent lacks a direct write bypass. Safe simulation and explicit live-mode guards are tested. | P18 through P21 |
| R6: repeatable demo | Scripted read, denial without approval, approval, successful execution and replay rejection; stale-head, expiry, cancellation and uncertain-result scenarios. Mocked failure tests plus a recorded physical live run in the constrained disposable repo. No secrets or assertion evidence in routine output or recording. | P22 through P24, P33, P34 |
| R7: developer onboarding | Tested install on a clean supported Mac; another developer completes the protected workflow using only the quickstart. Configuration checks, useful typed errors, redacted diagnostics, inspect/audit commands and documented disable/revocation and safe recovery limits. Explain local signing requirements and any distribution limits rather than hiding them. | P25 through P27, P36 |
| R8: documentation and release | README and GitHub Pages provide overview, architecture, quickstart, demo, threat model, standards mappings, roadmap and contribution guide. Dated primary standards sources; no unimplemented conformance claims. Versioned artifacts, checksums, SBOM, provenance, release notes, security reporting and support policy. | P28 through P31, P35, P37, P38 |
| R9: quality controls | Every PR independently reviewed and required CI green on its exact head; all existing suites retained unless an independently reviewed equivalent replacement is justified. Required coverage comparison against the trusted base, complete source accounting, negative controls, and no unapproved reductions. Fuzz/property, integration and crash/concurrency tests supplement coverage. | Coverage rollout, P32 through P35 |

Coverage percentages are not security guarantees. The comparison must include unexecuted code and document unsupported metrics and manual-only paths; instrumentation must not weaken runtime isolation. A hosted CI run cannot establish physical Touch ID or Keychain behavior. Coverage collection alone does not satisfy R9.

## Explicit non-goals

- Production GA, external certification or a claim of being vulnerability-free.
- Hosted multi-tenant service, Windows/Linux runtime support or universal agent identity.
- MCP gateway, arbitrary gh commands, shell execution or generic HTTP/GraphQL forwarding.
- Releases, secrets changes, branch-protection changes, repository deletion or other GitHub write capabilities.
- Multi-hop delegation, wildcard mandates, offline execution authorization or exactly-once remote execution.
- Advanced rotation/recovery workflows and standards transport adapters. Safe failure, credential disable and durable consumption remain mandatory; no automatic reset or silent re-enrollment is an acceptable recovery shortcut.
- Protection against compromised local administrator, malicious trusted verifier/UI, or an agent with independent GitHub write credentials.
- Paid Apple membership, notarized distribution, or a new signing/account requirement without a separate decision. If the tested local-development path cannot support a usable release, report that blocker rather than silently changing the trust model.

## Delivery order and parallel work

1. **A: baseline and contracts.** Resolve dependency failures, refresh standards mappings, and independently accept P06a before portable production implementation. Specify stable trust, enrollment, bootstrap, signing and provider failure semantics; unresolved semantics still block affected code. Track P06b isolation and native qualification separately.
2. **B: simulated vertical slice.** Integrate proposal, exact-operation approval, evidence and agent verification, fixed policy and consumed simulated execution. Test-only providers cannot be selected by live configuration. Synthetic evidence and browser/hardware observations remain distinct.
3. **C: durable enforcement.** Prove persistence, concurrency, restart, disable/revoke races, expiry and ambiguous outcomes with adversarial integration tests. Independent modules may proceed in parallel only against accepted interfaces.
4. **D: constrained live MVP.** Join the portable path with qualified P06b deployment, P04b physical evidence and P17 native integration. Prove agent-denied bypass paths, then the deliberately invoked disposable-repository demo with the maintainer. This is the working MVP, not the packaged release.
5. **E: experimental v0.1.** Finish onboarding, website and redacted demo assets against stable commands. Complete every R1–R9 gate, independent security review, coverage enforcement and clean-machine packaging before tagging.

Native qualification may proceed alongside B and C, but cannot be simulated away. The approved VM design direction authorizes no setup, signing/account change or weaker production key provider. A deployment choice that changes a frozen portable contract requires explicit contract revision and review before dependent implementation continues. Security testing accompanies every milestone rather than being postponed to E.

## Release decision

Maintain a release checklist linking each gate to its merged implementation, automated results and dated manual evidence. Any unresolved critical or high-severity finding blocks release. Other findings require explicit disposition and tracking; release-blocking acceptance failures cannot be relabeled as known limitations. Never bypass CI or claim a gate is complete from a PR count.

GA is a separate future decision after operational experience and a broader assurance review. This release plan makes no GA date or PR-count estimate.
