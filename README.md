# Vollmacht

Verifiable human authority for AI agents.

Vollmacht is German for authority granted to act on someone else's behalf. The project aims to let an agent perform an explicitly bounded operation after a person approves it using an existing passkey.

Status: a runnable synthetic walkthrough, portable verification and transactional attempt storage are available. The live authorization workflow and first release are unfinished. Experimental v0 must not be the sole control for production-critical operations.

The first target is macOS: an agent proposes a GitHub pull request merge, a local approval page displays the exact operation, and a local enforcement service verifies and consumes a single-use Human Mandate before calling GitHub. Read-only operations can proceed under local policy without a prompt.

WebAuthn user verification may use Touch ID where available. Vollmacht receives no biometric data. A verified credential does not establish universal proof of humanity or prove that a person understood an operation.

## Try the review demo

With the [development prerequisites](docs/development.md) installed, run from the repository root:

```sh
python3 scripts/demo.py
```

This runs the actual synthetic integration and presents its checked stages: proposal, synthetic approval, signed mandate, durable attempt, verified candidate, fixture resource comparison and replay denial. It also checks tampering, expiry, changed head/base/repository facts, policy restrictions and concurrent attempts. First compilation may take a few minutes.

No Touch ID, Keychain or GitHub credentials are used. No GitHub action is sent. The demo uses temporary test storage and software keys; it is a reviewable walkthrough, not the live MVP or a production fallback. Final reservation, real approval and deployment qualification remain unfinished.

The walkthrough displays the actual synthetic proposal, including the full approved head SHA, base, method, public identity references, simulated expiry and mandate fingerprint. This is a recorded proposal shown after successful checks, not an interactive approval prompt.

## Project documents

- [Execution plan](docs/implementation-plan.md)
- [First-release goals and acceptance gates](docs/release-v0.1.md)
- [Build and development checks](docs/development.md)
- [Architecture decisions and unresolved gates](docs/design-baseline.md)
- [Standards and interoperability](docs/standards.md)
- [Contribution and adversarial review process](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)
- [Logo assets and usage](assets/brand/README.md)

The planned implementation uses Rust for the CLI, verifier, policy evaluator, storage, and GitHub adapter; a small browser UI provides WebAuthn. A Swift key-storage helper is conditional on a macOS feasibility test. GitHub Pages documentation will follow once the demo works.

Licensed under [Apache License 2.0](LICENSE).
