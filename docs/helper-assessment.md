# Rust and SimpleWebAuthn helper assessment

Status: preliminary design assessment, 2026-09-22. Not an accepted ADR or production integration. Keep the Rust core; assess a narrow SimpleWebAuthn helper before P06 selects the architecture.

## What the evidence establishes

The public SimpleWebAuthn API accepts and checks an operation-derived challenge. Synthetic tests cover tampering and replay/state failures. The [physical matrix](../spikes/simplewebauthn/BROWSER.md) records user-reported Touch ID success, recovery and replay rejection in Chrome/Safari. Historical environment versions and cleanup were confirmed on 2026-09-29. The matrix retains observation limits. This supports feasibility, not a production security claim.

The experiment hashes a fixed domain, separate random nonce and opaque payload bytes. This is not yet the canonical Human Mandate construction. P06 must settle RFC 8785 serialization, nonce placement, domain separation and evidence format, with cross-language vectors.

## Proposed ownership

| Component | Responsibility | Must not own |
| :--- | :--- | :--- |
| Rust coordinator | Immutable operation, nonce/challenge, trusted credential registry, enrollment authorization, deadlines, policy, agent binding, revocation, durable consumption, audit and execution | Treating a helper Boolean as independently verified evidence |
| Node helper | WebAuthn option generation and complete library-based registration/assertion verification against Rust-supplied expectations | Issuer private keys, GitHub tokens, capability selection, policy decisions or execution |
| Local approval UI | Display the exact operation supplied by Rust and invoke the browser authenticator | Choosing the operation or credential trust rules |

These are proposed boundaries, not implemented modules. The loopback browser endpoint still needs a design: prefer Rust-owned transport with the helper reached only through private pipes. Browser-origin, enrollment-token, CSP and request-size controls remain necessary; private helper pipes do not replace them.

The helper is part of the trusted computing base. Correlating its response with a request and digest prevents accidental mix-ups, not forgery by a malicious helper. A compromised helper can falsely report user verification. Rust is not an independent WebAuthn verifier merely because it recomputes the challenge. A separate process is not a sandbox against same-user malware.

Retain original assertion bytes so an independently trusted verifier can check them later. That requires a complete, reviewed WebAuthn verifier and trusted registry; do not introduce handwritten signature verification as a shortcut. Issuer signing alone does not make dishonest helper evidence truthful. P06 must explicitly accept this trust cost or reject the helper architecture.

## Proposed private protocol

1. Rust snapshots the operation and trusted credential state, generates fresh randomness, and stores the pending ceremony with its deadline. The agent cannot provide trusted keys, expected origin or RP ID.
2. Rust sends a versioned, size-bounded request containing a request ID, expected challenge, RP/origin expectations, credential public material and required verification policy. Registration is a distinct request, permitted only by Rust's protected enrollment workflow.
3. The helper verifies the raw browser evidence with the library and returns a typed outcome correlated to the request and challenge. Retain raw signed client data; never verify a reserialized replacement. Helper outputs remain untrusted input for parsing even though the helper's verification decision is trusted.
4. Rust checks response correlation, deadline, current registry/revocation state and operation identity. Only then may the separate policy/agent-proof and durable single-use reservation path authorize execution. A successful WebAuthn check alone never authorizes a GitHub operation.

The protocol spike must specify framing and exact limits, reject duplicate/unknown fields and unsolicited or repeated responses, and test malformed/truncated frames. Use one in-flight request initially. Bound both output streams and verification time. Timeout, crash, wrong protocol version, output overflow and any ambiguous response fail closed and invalidate the ceremony. Drain pipes, terminate and reap failed children. Restart never restores approval or retries an external write automatically.

Launch directly without a shell using explicitly configured absolute runtime/helper paths. Do not resolve a security helper from an agent-controlled working directory or ambient PATH. Use a minimal environment and exclude Node loader, inspector and injection settings, including NODE_OPTIONS and NODE_PATH. No credentials or assertions in process arguments or logs. Define installation/update ownership and integrity checks before calling paths trusted; absolute paths alone do not prevent replacement by their owner.

Registry writes stay in Rust and require authorized enrollment plus a verified result. Counter and backup-state updates need serialized compare-and-update rules so stale helper results cannot overwrite newer state. P04b must separately establish issuer-key protection; removing keys from Node does not prove that same-user processes cannot access them.

## Packaging choices and unresolved costs

| Option | Appropriate next use | Unresolved cost |
| :--- | :--- | :--- |
| Explicit external Node plus locked helper files | Developer-only protocol spike | Installation friction, runtime/path integrity and user-managed updates |
| Bundle a reviewed Node runtime and locked helper | Candidate for a later macOS distribution spike | Size, architecture coverage, patch cadence, licenses/SBOM, signed updates and Apple signing/notarization |
| Single-executable or embedded-runtime packaging | Deferred alternative, not assessed | Dependency compatibility, debugging, reproducibility and platform signing behavior |

Only Node 26.5.1 was tested locally. The earlier dependency-directory observation was about 6.9 MiB excluding Node; it is not a distribution-size estimate. P03f.1 now provides [repeatable developer preflight, inventory and process-latency measurements](../spikes/helper-protocol/DEVELOPMENT.md), explicitly distinguishing logical file bytes from allocated space and the Node executable from its shared libraries. Memory, complete packaged size and notarization remain unmeasured. Do not promise a standalone Rust binary, no Node requirement or production-ready installation yet.

Runtime lifecycle selection is a release gate, not a reason to silently change the experiment pin. Recheck upstream supported versions and advisories during the packaging spike, then run the full matrix on the selected runtime. Upstream [process documentation](https://nodejs.org/api/child_process.html) also illustrates why bounded/drained pipes and controlled process environments matter; the proposed parent implementation uses Rust process APIs, not Node-specific IPC.

## Next small PRs

| Task | Scope and likely files | Tests and acceptance | Dependency |
| :--- | :--- | :--- | :--- |
| P03e.1 | [Experimental assertion protocol and vectors](../spikes/helper-protocol/README.md) | Exact fields, framing, maximum sizes, state transitions, trust assumptions and failure codes; registration/options deferred, no production schema claim | This assessment |
| P03e.2a | Rust codec plus in-memory fake-helper round trip | Wrong ID/challenge, duplicate/unknown fields, invalid encodings, truncated/oversized frames and trailing data rejected; no lifecycle claim | P03e.1 |
| P03e.2b | Process harness plus fake child and in-memory coordinator | Stderr flood, timeout, crash, cancellation, late response, concurrent/replayed submissions and registry races all fail closed; children reaped | P03e.2a |
| P03e.2c | [Exec-only launcher](../spikes/helper-launcher/README.md) | File/socket leak negative controls, preserved PID/pipes, failure paths and lifecycle regressions on macOS/Linux | P03e.2b |
| P03e.3 | Wire real SimpleWebAuthn through the experimental harness | Existing negative verification tests plus end-to-end request/evidence correlation; no issuer keys or GitHub access | P03e.2c |
| P03f.1 | [Developer preflight and packaging baseline](../spikes/helper-protocol/DEVELOPMENT.md) | Fresh-checkout CI setup, missing/wrong runtime errors, measured process latency, dependency inventory and explicit signing/update gaps; not a complete distribution | P03e.3 |
| P03f.2 | Validate a current LTS runtime and propose the distribution approach | Verified isolated runtime, macOS/Linux regression matrix, native dependency/architecture assessment, repeat measurements and reviewed pin decision | P03f.1 |
| P04b | Durable Apple key-storage experiment | Restart, access-denied behavior and signed identity/entitlement evidence; no silent unprotected fallback | Independent of helper spikes |
| P06 | Accepted ADRs and canonical mandate/evidence specification | Browser evidence gaps addressed, helper trust explicitly accepted or rejected, storage and packaging findings incorporated | P03/P04 findings |

P03e.2b implements a single trusted-fixture coordinator and real fake-child lifecycle tests, not a reusable production registry or restart recovery. P03e.2c adds inherited-descriptor hygiene through a separately reviewed native exec boundary. Platform CI must pass before proceeding with integration; trusted artifact packaging and sandboxing are not established by these tests. See the [current implementation boundary](../spikes/helper-protocol/README.md#current-implementation-boundary) for test-only fault injection and cleanup limits.

P03e.3 adds a [one-shot SimpleWebAuthn assertion helper and integrated synthetic test driver](../spikes/simplewebauthn/README.md#p03e3-private-assertion-helper). Rust generates the expected experimental binding; the helper consumes that exact value through the existing launcher and private protocol. Independently signed test assertions exercise real library verification rather than a fake Boolean. The driver trusts fixture enrollment supplied on stdin and must never become an agent-facing API. The browser service remains separate. Neither durable replay protection nor production Human Mandates are established. P03f.1 establishes a developer baseline; P03f.2 runtime validation remains the next helper task. P04b key-storage work remains independent.

Success for the helper spikes means a bounded, testable integration with understood distribution costs, not production approval. If integrity, runtime support or fail-closed behavior cannot be established, stop adoption and revisit library/architecture options in P06. Do not silently fall back to a random challenge or issuer-only authorization. Each implementation PR requires independent adversarial review. No live GitHub writes are needed for these tasks.
