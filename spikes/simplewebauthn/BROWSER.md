# P03d: real-browser assessment

Status: user-reported Chrome/Safari physical testing supports browser feasibility, with remaining evidence gaps below. This is not the Rust/Node production helper integration.

## Run on your Mac

Stop the old Rust probe first: both intentionally use the already-tested origin http://localhost:8374. From the repository root, using Node 26.5.1:

```sh
cd spikes/simplewebauthn
npm ci
npm run browser
```

Open http://localhost:8374 in Chrome or Safari. Paste the terminal token into the page and select **Use token**. Do not share that token or screenshots of it. The server listens on IPv4 loopback only; it does not start a browser automatically.

1. Select **Register test passkey** and complete the platform prompt. The account label is `vollmacht-binding-spike` for `localhost`.
2. Inspect the fixed simulated operation on the page. Select **Verify passkey (approve fixed test request)** and complete the prompt. Expect verified user verification. No merge is performed.
3. Start another approval and cancel the platform prompt, then retry. Retry should succeed. You may also use the page's cancel button when the browser allows returning focus to it.
4. Let a prompt expire, then retry. The browser might close its dialog earlier; this is distinct from the server's exact 120-second expiry, which automated tests cover.
5. In developer tools, you may resend the successful `finish_authentication` POST unchanged. Expect HTTP 409 with `missing_or_expired_ceremony`. Do not export the request or share its bearer token/assertion.
6. Stop the server with Ctrl+C. Restart before testing registration in the other browser, then repeat the matrix. A second registration in the same session is deliberately rejected.

Stopping loses the server's credential registry but does not remove passkeys from your provider. Afterwards delete only the `vollmacht-binding-spike` localhost test credential(s). Do not remove unrelated localhost passkeys or the older `vollmacht-local-spike` credential unless you separately intend to clean that experiment up.

## Security boundary and implementation

The terminal's fresh 256-bit token authorizes the initial enrollment. Same-user malware or a compromised browser remains outside this experiment's boundary. No claim of hardware provenance or biometric identity is made.

The page displays the same fixed UTF-8 operation literal used to derive the challenge. It is a simulation, not a canonical Human Mandate schema. There is no arbitrary operation endpoint, GitHub credential, persistent key, issuer envelope or outbound GitHub call.

The server reuses the existing tested browser JavaScript and CSS without modification. Session code adapts that script's extension-field naming to SimpleWebAuthn. Registration requires ES256, UP and UV with platform-authenticator preference. Assertions use the enrolled credential, validate any supplied user handle, maintain the in-memory signature counter, and reject changed device type. Synced passkeys are allowed; provider or device identity is not inferred.

One pending ceremony is permitted. Starts/finishes are serialized through asynchronous verification; matching finish and cancellation consume state even on failures. Stale IDs do not cancel current state. Monotonic expiry is checked before processing and again after verification. Restart invalidates every pending ceremony and forgets enrollment.

HTTP checks exact Host, Origin, same-origin Fetch Metadata, JSON content type and bearer token, rejecting duplicate security headers. API query strings and preflight are rejected. Request bodies are capped at 64 KiB, headers at 8 KiB, and request handling at five seconds; connections are bounded. Static content uses CSP, frame denial and no-store. Errors use fixed local codes rather than library messages containing assertion data.

The command body must match JSON.stringify's compact encoding exactly. This deliberately narrow browser transport rejects duplicate command keys and alternate whitespace/encodings; it is not RFC 8785 canonicalization. Raw signed clientDataJSON is preserved, not reserialized. Assertion parsing and signature checks stay in the library; no trusted-UI claim follows from a valid signature.

Automated tests use synthetic none-attestation credentials and loopback sockets. They cover registration UP/UV/origin/RP/cross-origin rejection, user-handle mismatch, replay, pending/cancel/expiry rules, concurrent enrollment, HTTP policy, size limits and security headers. The reused browser script has its existing seven tests in the workspace check. None of these is physical authenticator evidence.

## User-reported physical results

Reports received by 2026-09-22. These are the tester's reports, not independently observed hardware tests; exact test dates and environment versions were not captured.

| Browser and version | Register | Bound approval | Cancel/retry | Timeout/retry | Replay | Prompt method |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Chrome: version unrecorded | Passed | Passed | Passed | Passed | Returned `missing_or_expired_ceremony` | Touch ID reported for registration and approval |
| Safari: version unrecorded | Passed | Passed | Passed | Passed | Not reported | Touch ID reported for registration and approval |

The Chrome replay report confirms the error string, not an independently observed HTTP status or prompt count. Browser timeout/retry succeeded; the exact server deadline is covered by automated tests, not a timed physical measurement. Fresh server sessions per browser and test-passkey cleanup were not explicitly confirmed.

Remaining evidence: Safari manual replay, macOS and browser versions at test time, and cleanup confirmation. Do not infer historical versions from current installations. Do not record tokens, credential IDs, assertion bytes or biometric information. These gaps do not prevent further design assessment, but the manual matrix is not complete. P06 must still assess Node distribution, process trust, protected storage and physical findings before selecting this implementation. See the [helper assessment](../../docs/helper-assessment.md).
