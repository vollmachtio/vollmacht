# Vollmacht

Verifiable human authority for AI agents.

Vollmacht is German for authority granted to act on someone else's behalf. The project aims to let an agent perform an explicitly bounded operation after a person approves it using an existing passkey.

Status: design and feasibility work, with a development CLI shell. Authorization is not implemented and no release exists yet. Experimental v0 must not be the sole control for production-critical operations.

The first target is macOS: an agent proposes a GitHub pull request merge, a local approval page displays the exact operation, and a local enforcement service verifies and consumes a single-use Human Mandate before calling GitHub. Read-only operations can proceed under local policy without a prompt.

WebAuthn user verification may use Touch ID where available. Vollmacht receives no biometric data. A verified credential does not establish universal proof of humanity or prove that a person understood an operation.

## Project documents

- [Execution plan](docs/implementation-plan.md)
- [Build and development checks](docs/development.md)
- [Architecture decisions and unresolved gates](docs/design-baseline.md)
- [Standards and interoperability](docs/standards.md)
- [Contribution and adversarial review process](CONTRIBUTING.md)
- [Security boundaries](SECURITY.md)
- [Logo assets and usage](assets/brand/README.md)

The planned implementation uses Rust for the CLI, verifier, policy evaluator, storage, and GitHub adapter; a small browser UI provides WebAuthn. A Swift key-storage helper is conditional on a macOS feasibility test. GitHub Pages documentation will follow once the demo works.

Licensed under [Apache License 2.0](LICENSE).
