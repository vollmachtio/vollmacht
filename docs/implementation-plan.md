# Execution plan

Implementation proceeds through small PRs. Tasks are sequential unless explicitly independent. Every row requires the adversarial review process in CONTRIBUTING.md. A checked task means its acceptance criteria were verified, not merely that files were created.

## First ten PRs

| ID | Scope and likely files | Acceptance and validation | Depends on |
| :--- | :--- | :--- | :--- |
| P01 | README, contribution rules, security boundary, this plan, design baseline | Documentation links resolve; independent review of claims and execution gates | None |
| P02 | Minimal Cargo workspace, toolchain lock, CI, dependency policy | Clean build, formatting, lint, meaningful smoke test; review workflow permissions and dependency choices | P01 |
| P03 | Isolated localhost WebAuthn spike in spikes/webauthn | Real registration and assertion on supported macOS browser; negative server-side validation tests; explicit physical-test result | P02 |
| P04 | Apple issuer-key spike in spikes/macos-key | Non-exportable P-256 key path verified; valid signature checked independently; denial/error handling and platform limits recorded | P02 |
| P05 | docs/standards.md and source snapshot | Current primary sources and exact metadata verified; mappings and gaps; no unsupported compliance claims | P01 |
| P06 | ADRs and schema/ payload/envelope specification | P03/P04 evidence settles key and WebAuthn choices; canonicalization vectors, TTL, trust registry, and enrollment contract frozen | P03, P04, P05 |
| P07 | crates/core parsing and canonical digest module | Valid vectors; duplicate keys, ambiguous numbers, altered fields, size/depth limits rejected; property tests | P06 |
| P08 | Issuer JWS module and key-provider interface | Round-trip and independently produced vectors; wrong key, algorithm, header, and payload mutation rejected | P07 |
| P09 | Credential registry and WebAuthn evidence verification | Protected bootstrap and credential disable; wrong origin/RP/challenge/UV/credential tests; original clientDataJSON preserved | P03, P07 |
| P10 | Agent request proof and verifier orchestration | Unknown agent, wrong audience/operation, stale request, invalid evidence and issuer trust fail; typed errors | P08, P09 |

P03 and P04 must remain experiments until findings are incorporated in P06. Do not publish production claims based on simulated authenticators. Pin dependency and toolchain versions only after checking current maintenance and advisory information.

P03 is split for review: P03a adds an executable library compatibility probe and dependency checks; P03b adds the local browser ceremony and physical testing. P03a does not complete P03. Custom mandate-challenge support is a separate gate from successful random-challenge authentication. See [probe findings](../spikes/webauthn/README.md).

P03c establishes synthetic custom-challenge feasibility with SimpleWebAuthn in an isolated Node experiment. P03d adds its opt-in [real-browser assessment](../spikes/simplewebauthn/BROWSER.md). The user-reported Chrome/Safari functional matrix, including replay rejection, is complete; historical environment versions and cleanup were confirmed on 2026-09-29. Observation limits remain documented. Neither step selects a production Node helper or resolves P04b protected key storage. The [helper assessment](helper-assessment.md) defines proposed P03e protocol and P03f packaging spikes before the P06 decision.

P04 is also split: P04a tests a temporary Secure Enclave key, independent signature verification and encoding; P04b evaluates durable protected storage, signed identity/entitlements, restart and denied-access behavior. Ephemeral signing alone does not complete P04. See the [Apple key experiment](../spikes/macos-key/README.md). It can proceed independently while P03b physical browser evidence is collected.

## Remaining milestones

### Immediate execution queue after the browser and temporary-key experiments

1. P05: publish the [standards baseline](standards.md) and [dated source register](standards-sources.md), with independent review of maturity and compatibility claims.
2. P03c: isolate supported mandate-derived challenge generation and verification. Success requires a public library API, unchanged server-side validation, preserved raw client data, and tests rejecting changed payload, nonce, origin and credential. If unavailable, record the alternative and its trust tradeoff for review; do not patch serialized private state. Physical browser confirmation follows automated evidence.
3. P04b: test durable protected key storage, restart retrieval and process access restrictions. Start with a written identity/entitlement matrix and software tests. Real Keychain creation, signing identity changes and interactive denial tests wait for the user; temporary-key success is not evidence for these properties.
4. P06: resolve both gates in ADRs, then freeze schema and independent vectors. P07 parsing can start only after that review, not in parallel with an unsettled signing contract.

P03c research and P04b test design can proceed independently. Neither requires changing GitHub organization settings. No live GitHub write demo is needed until P22/P23.

| Milestone | Atomic PR tasks | Acceptance gate |
| :--- | :--- | :--- |
| M2 Core completion | P11 SQLite replay/revocation migrations; P12 reservation and crash recovery; P13 full verifier vectors and property tests | Concurrent execution yields one reservation; restart cannot reuse reserved mandate; revocation/status checks and reservation form one serialized decision; test both revoke-versus-reserve orderings; expired mandate fails |
| M3 Human approval | P14 loopback service and browser defenses; P15 registration/admin ceremony; P16 exact operation display and approval; P17 Apple signing integration | Exact origin/Host checks, CSRF protection, no cross-origin API access, bounded pending requests, cancelled/expired approval fails; physical macOS run |
| M4 Enforcement | P18 capability catalog and fixed policy; P19 GitHub read adapter; P20 merge adapter with preconditions; P21 credential storage and sanitized audit | No arbitrary transport escape; policy never widens authority; API request matches approval; ambiguous writes are not retried |
| M5 Demo | P22 disposable fixture preparation; P23 scripted deny/approve/execute/replay scenario; P24 stale-resource and failure scenarios | Simulation default; deliberate live merge of benign PR; explicit user approval at authenticator; no destructive cleanup |
| M6 CLI | P25 configuration and doctor; P26 inspect/audit commands; P27 fresh-machine quickstart | Useful typed errors; redacted diagnostics; working install and recovery guide |
| M7 Documentation | P28 protocol and architecture diagrams; P29 complete threat model and standards refresh; P30 GitHub Pages site; P31 redacted demo recording | README and site agree with actual behavior; links/build/accessibility checks; landing, concepts, architecture, demo, quickstart, security, standards, roadmap, contribution pages |
| M8 Hardening | P32 fuzz harness and corpus; P33 mocked GitHub integration and crash/concurrency tests; P34 physical macOS E2E matrix; P35 release security review | Findings resolved; deterministic tests separated from manual hardware evidence; current dependency advisory checks |
| M9 Release | P36 package and clean-machine install; P37 checksums/SBOM/provenance/release workflow; P38 v0.1 notes and support policy | Versioned experimental release; verified reporting channel; reviewed release revision and artifacts; documented limitations |

The runnable v0 prototype completes at M5. Version 0.1 is the packaged experimental release after M9, not a promise of production readiness. MCP, GitHub App credentials, additional platforms, external verifiers, multi-hop delegation, and more critical actions follow later. Standards transport adapters are separate from the v0 mandate format.

## Per-PR execution contract

Before editing, inspect the base revision, local instructions, and unrelated changes. Implement only the selected task. Run checks proportional to the change and capture commands/results. Request a separate adversarial review, fix findings, and obtain review of substantive fixes. Commit the reviewed state, push its branch, and open a PR with the review and validation evidence. The maintainer now authorizes automatic merging of in-plan PRs after independent review and required CI pass on the exact head revision. Pause for clarification, material deviations, permission blockers or user-assisted hardware steps; never bypass branch protections.

Independent workstreams may execute in parallel with disjoint file ownership and coordinated integration. P04b lifecycle software tests and P06 proposed design documents can proceed together, but proposed documents are not a frozen specification. P04b's native/hardware evidence remains a gate for accepting the architecture, and P07 still waits for that acceptance.

If GitHub authentication prevents PR creation, preserve the completed local branch and report the exact missing prerequisite. Never claim a PR exists until GitHub returns its URL. Dependent work can use explicitly stacked branches; PR descriptions must name their base and dependencies. Independent tasks can branch from the latest agreed foundation.

Critical path: P01, P02, P03/P04, P06 through P13, M3/M4, M5, M8, M9. P05 and documentation outlines can proceed independently of hardware testing. Site polish follows stable command names and a working demo.
