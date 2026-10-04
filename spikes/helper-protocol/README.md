# P03e.1: assertion-helper protocol

Status: experimental specification with the P03e.2a Rust codec and P03e.2b single-ceremony lifecycle harness. The `fake-helper` executable fabricates claims for testing only; it must never verify real credentials. No production mandate schema, enrollment service or execution authority is added here. This narrows the [helper assessment](../../docs/helper-assessment.md) to assertion verification against an already trusted test credential. Registration and option generation are explicitly deferred to a separately reviewed protocol extension. P03e.3 may use a synthetic trusted fixture; it must not silently import browser enrollment as trusted production state.

## Current implementation boundary

`cargo test -p vollmacht-helper-probe` runs the bounded frame decoder, strict parsing, snapshot checks, in-memory round trip and injected ownership-fault unit tests. `cargo test -p vollmacht-helper-launcher` runs real fake-child lifecycle and descriptor tests through the [exec-only launcher](../helper-launcher/README.md). Existing locked dependency versions are reused. Workspace CI includes both packages automatically.

`Request::parse` validates transport syntax only, not trusted enrollment, key algorithms, ID matching or signatures. It preserves base64url-encoded signed fields when serializing a request. `decode_response` returns a helper claim, never final authorization. Its checks use a snapshot, not a live registry. `FrameDecoder::finish` must only be called after the transport observes EOF; it does not observe process exit itself. Parse/framing errors carry fixed codes, not evidence or child diagnostics.

`Coordinator` owns exactly one trusted synthetic request with its immutable evidence and challenge. It atomically claims that request, launches a directly owned child with an empty environment, bounds both output streams, and accepts a helper claim only after EOF, zero exit and final serialized deadline/cancellation/registry checks. The simulated registry is captured at construction: changes before launch and during verification both reject. Successful counter updates happen only at final acceptance. A concurrent or repeated call cannot launch another child.

A dedicated owner thread survives caller timeout, including a blocked launch that returns late. After a one-second cleanup budget, unresolved ownership disables that coordinator and reports cleanup failure; the owner continues trying to reap the child. This cannot guarantee recovery from an OS call that never returns, process-wide termination, or malicious descendants. A new coordinator constructed manually from the same fixture is not durable replay protection. Restart/recovery, fresh challenge generation and global credential storage remain outside this harness; callers must not reconstruct pending approvals from old evidence.

Tests exercise real child failures, EOF/exit requirements, cancellation/concurrency, pre-claim and in-flight registry changes, output caps, request-size boundaries and absence of the child after normal cleanup. A one-byte in-memory pipe deterministically tests cancellation of blocked stdin writes. Delayed-launch and delayed-reaping unit tests use test-only faults to check disabled state and eventual reaping; they do not reproduce an actual kernel failure. Cleanup and runtime timing include ordinary scheduler tolerance.

P03e.2c adds an explicit `Launch.launcher` path and an exec-only native boundary to prevent arbitrary inherited file descriptors from reaching the target helper. It retains the child PID and private standard streams; no fallback direct launch exists. See the [launcher safety and platform limits](../helper-launcher/README.md). This is descriptor hygiene, not sandboxing. Launcher/runtime/helper file integrity and malicious-descendant containment are still not established. No WebAuthn library, issuer key or GitHub token is present in this harness.

## Security boundary

The separate [client-data syntax assessment](CLIENT-DATA.md) is test-only. It does not change this transport or the real helper's current verification behavior.

Rust owns the immutable operation, random nonce and challenge, credential selection, expiry and single-use state. Node performs complete WebAuthn verification using the existing reviewed library wrapper, with expectations supplied by Rust. The helper is trusted verification code: correlation prevents mix-ups, not a dishonest helper returning success. Private pipes are not isolation from same-user malware.

Rust retains the original evidence and operation in its pending record. The helper receives neither issuer keys nor GitHub credentials and never decides policy or performs an action. This experiment returns only a verification result. Agent proof, policy, durable reservation, registry revocation and issuer signing remain separate production gates.

## Transport and process lifetime

Use one directly spawned child per verification, no shell, no network helper endpoint, no handshake and no retries. One request travels on stdin and one response on stdout. Each frame is a four-byte unsigned big-endian byte length followed by that many UTF-8 JSON bytes. Length must be 1 through 65,536 inclusive; reject the prefix before allocating a larger body. Close stdin after writing the request. No BOM, trailing frame, trailing byte or stdout logging is permitted. JSON whitespace within the frame is allowed.

Success is provisional until the complete response, stdout/stderr EOF and exit code zero are observed. Nonzero exit, a signal, extra output, truncated data or missing response rejects even a preceding success frame. Read stdout and stderr concurrently while writing stdin so blocked pipes cannot deadlock the parent. Cap total stdout at 65,540 bytes and stderr at 8,192 bytes per child; exceeding either aborts. Discard stderr contents, never surface or log assertion data or arbitrary child diagnostics.

Rust uses its own monotonic clock. The complete child lifecycle, including launch and stdin writes, has a 5,000 ms budget capped by the pending ceremony's remaining lifetime. No wall-clock deadline crosses the wire. Check expiry before spawning and after receiving the final result; equality with the deadline is expired. Cancellation, expiry or any terminal attempt consumes the pending ceremony. A failure requires a new challenge, not resubmission of the old assertion.

On abort, close stdin, terminate the child and reap it. Bound cleanup to an additional 1,000 ms; if reaping cannot be confirmed, return a local cleanup failure, disable further helper launches in that coordinator instance and retain responsibility for eventual reaping. Never report verification success while a child is unresolved. The implementation must track/reap a process whose launch completes after cancellation. No descendant processes are supported; process separation is not a containment guarantee against malicious code.

Launch using explicit absolute runtime and helper paths with a trusted working directory. Start with an empty environment and only explicitly documented necessary entries; do not inherit PATH, NODE_OPTIONS, NODE_PATH, loader or inspector configuration. No evidence in arguments. Close unrelated inherited handles. P03f must assess file ownership, integrity and update policy: absolute paths alone do not make files trustworthy. P03e.2 tests lifecycle behavior with a fake helper, not installation security.

## JSON profile

Both sides reject duplicate member names at every object depth before deserialization can discard duplicates. Unknown or missing fields, nulls, invalid UTF-8, unpaired Unicode surrogates, wrong types and unsupported versions are errors. Depth is at most eight containers, counting the root as one. All integers below use JSON decimal integer tokens without fraction, exponent, sign or leading zeros except the single token `0`. Protocol strings are ASCII. Limits are decoded byte lengths unless described otherwise.

Base64url fields use only `A-Z`, `a-z`, `0-9`, `_`, `-`, without padding; decode then re-encode identically to reject noncanonical encodings. Each field is bounded before decoding using its maximum encoded size. This is transport validation, not RFC 8785 canonicalization. The parent never reserializes signed clientDataJSON or authenticatorData before verification.

### Request: exact fields

| Field | Type and rule |
| :--- | :--- |
| `version` | Integer `1` |
| `kind` | Literal `verify_assertion` |
| `request_id` | 32 lowercase hexadecimal characters; fresh 16 random bytes generated by Rust, never reused |
| `challenge` | Base64url, exactly 32 decoded bytes, copied from Rust's pending operation-bound ceremony |
| `rp_id` | Literal `localhost` in this experiment |
| `origin` | Literal `http://localhost:8374` in this experiment |
| `credential` | Exact object below, exclusively from trusted Rust state |
| `assertion` | Exact object below, adapted from the browser evidence without altering signed bytes |

`credential` has exactly: `id` (base64url, 1..1,024 bytes), `public_key` (COSE public key, base64url, 1..4,096 bytes), `counter` (integer 0..4,294,967,295), `user_handle` (base64url, 1..64 bytes), and `backup_eligible` (Boolean). Only enrolled ES256 credentials are supported; the library must reject other algorithms or malformed key material. Trust does not come from self-description in the browser response.

`assertion` has exactly: `id` and `raw_id` (each base64url, 1..1,024 bytes), `type` (literal `public-key`), `client_data_json` (base64url, 1..12,288 bytes), `authenticator_data` (base64url, 37..8,192 bytes), `signature` (base64url, 1..1,024 bytes), and `user_handle` (either an empty string meaning absent, or base64url, 1..64 bytes). No extension-result object is transported in version 1; the adapter supplies an empty client extension result object to the library. Signed authenticator extensions remain inside the original authenticator data for library validation. No extension-dependent feature is supported.

The helper requires both IDs to equal the trusted credential ID; a supplied user handle must match the trusted handle. Require UP and UV, exact challenge/origin/RP/type, valid signature and library counter checks. Reject crossOrigin unless absent or false, and reject any topOrigin, as in the existing probe. Require unchanged backup eligibility; synced credentials remain allowed. Do not treat a zero counter as replay protection or backup eligibility as hardware provenance.

### Response: exact tagged alternatives

Every response has `version: 1`, `kind: "verification_result"`, and the request's exact `request_id` and `challenge`. It then has one of these field sets, with no union of the two:

- Success: `outcome: "verified"`, `new_counter` (integer 0..4,294,967,295), `backup_eligible` (Boolean), `backed_up` (Boolean).
- Rejection: `outcome: "rejected"`, `code: "verification_rejected"`.

No raw library errors or supplied evidence are echoed. Reject a success where backed_up is true but backup_eligible is false. Rust checks unchanged backup eligibility and counter semantics again: if either stored or new counter is nonzero, the new counter must be greater than the stored counter. Both zero is permitted. These checks are not independent signature verification.

For an invalid request envelope, the helper emits no response and exits nonzero rather than reflecting an unvalidated correlation ID. A structurally valid request with evidence that fails verification produces the rejection response and exits zero. Both are failures to Rust.

## Coordinator state and acceptance

`pending -> verifying -> verified` or `rejected`; there is no transition back to pending. Rust atomically claims the pending ceremony before spawning. Concurrent attempts get `ceremony_unavailable` without disturbing an existing attempt. Cancellation of a verifying attempt is terminal and wins over a provisional helper success until the final acceptance transition has committed.

Retain in the claimed record: operation bytes, nonce/challenge, request ID, deadline, raw evidence and credential snapshot with registry revision. Responses cannot change these. Before committing success, match version/kind/ID/challenge, require complete process success, and atomically check deadline, cancellation, credential enabled state and unchanged registry revision. A stale registry snapshot rejects; never silently overwrite a concurrent counter or revocation update. Production success would serialize any counter update with this check. The harness uses an in-memory revision model and makes no durability claim.

After acceptance, cancellation cannot undo historical verification, and verification still grants no external execution authority. Restart loses pending approvals and cannot reconstruct them from captured helper responses. Audit only bounded local codes and nonsecret correlation metadata; do not retain raw evidence in general-purpose logs.

### Local failure classification

| Code | Meaning |
| :--- | :--- |
| `ceremony_unavailable` | Missing, expired, already claimed or consumed ceremony |
| `cancelled` | Explicit cancellation before final acceptance |
| `deadline_exceeded` | Ceremony or child deadline reached |
| `helper_launch_failed` | Child could not be launched |
| `helper_protocol_error` | Invalid framing/schema, wrong correlation, surplus/missing response or output overflow |
| `helper_exit_failed` | Signal or nonzero exit |
| `helper_cleanup_failed` | Child reaping not confirmed within cleanup budget; coordinator disabled |
| `verification_rejected` | Valid rejection response or failed credential-state/counter checks |

All codes deny verification. For competing failures, preserve the first terminal cause, except cleanup failure supersedes it. No caller may downgrade any failure to an issuer-only or random-challenge path.

## Vectors and implementation acceptance

The [vectors](vectors.json) are deterministic transport examples, not cryptographic evidence. They deliberately use repeated bytes and rejection outcomes; their values must never become live nonce defaults. The length-prefix examples include a structurally invalid empty object to separate framing acceptance from schema acceptance.

P03e.2a covers codec tests; P03e.2b must complete the lifecycle and coordinator tests below before real verification is wired:

1. Round-trip the rejection vector through Rust and a fake helper; verify bytes and big-endian length, fragmented reads/writes and exact EOF.
2. Reject zero/oversized prefixes, truncation, trailing bytes, second frames, invalid UTF-8/BOM, duplicate keys at every depth, unknown fields, depth overflow, invalid base64url, numeric edge cases and unsupported versions.
3. Reject mismatched request ID/challenge, unsolicited output and a success followed by crash, output flood or failure to exit. Exercise maximum-size valid input and stderr at/over the cap without deadlocks.
4. Cover timeout during launch/write/read/exit, cancellation races, deadline equality, cleanup timeout, no zombies on normal cleanup and no launch after cleanup failure.
5. Cover concurrent submissions, replay, stale registry revisions, disable during verification, counter regression, backup inconsistency and restart. Acceptance after cancellation or expiry must never occur.

P03e.3 must additionally rerun the existing synthetic WebAuthn negatives through the real helper and verify an independently generated valid assertion. The existing probe's `Ceremony` constructor generates its own nonce/challenge: do not instantiate it unchanged for this protocol. Extract or adapt its verification checks to consume Rust's exact expected challenge, with tests proving the helper does not substitute its own challenge. A fake helper returning success is lifecycle evidence only. Neither task includes a browser UI, durable enrollment, issuer keys or GitHub writes. P06 must review this experiment before any production reuse.

The P03e.3 [real-helper test path](../simplewebauthn/README.md#p03e3-private-assertion-helper) now implements this assertion-only integration. `helper.mjs` adapts the checks without instantiating `Ceremony`. Its independent strict envelope decoder and real ES256 verification are tested in Node, and the Rust example drives it through the native launcher on the macOS/Linux CI matrix. Input credential material is trusted synthetic enrollment, not agent input. In-memory replay checks remain scoped to one coordinator; restarting the helper does not create a durable replay store.
