# Security status

Vollmacht is experimental and currently contains planning documents only. No production security guarantees are offered. Do not rely on v0 as the sole control for production-critical operations.

## Intended protection boundary

The local enforcement service mediates a small allowlist of GitHub operations. It holds the upstream GitHub credential and checks policy, bounded approval evidence, agent key possession, expiry, and single-use state before dispatch.

An agent with independent GitHub write credentials can bypass this service. Arbitrary code running as the local user may access credentials, modify the approval UI or verifier, tamper with policy and storage, or invoke local key services. Keychain storage alone does not create a sandbox. Root, local malware, and a malicious enforcement service are outside the v0 guarantee.

The intended deployment gives the agent only the narrow tool interface and protects the service's configuration and upstream credentials from that agent. A same-user shell demo illustrates authorization behavior; it does not establish isolation against a hostile local process.

WebAuthn establishes credential possession and user verification under its relying-party rules. UV may be satisfied by mechanisms other than a fingerprint. Synced passkeys and counters do not reliably establish a unique physical person or device. The browser and operation display remain trusted. Human approval is not a guarantee that a change is safe.

## Reporting

Do not post credentials, exploit secrets, or private repository contents in public issues. A private reporting channel must be configured and verified before the first executable release. Until then, use GitHub's private vulnerability reporting feature only if the repository's Security page actually offers it. Do not assume a private channel is already enabled.
