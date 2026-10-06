# Client-data gate cross-runtime assessment

This test harness composes the candidate Rust syntax gate with the real Node verification function. It changes no browser, enrollment, helper transport or production verification path. Software-generated signatures and UP/UV flags are test evidence only, not human or hardware evidence.

The Rust `client-data-gate` example reads at most 12,289 bytes, validates against the 12,288-byte candidate limit, and echoes accepted bytes unchanged. Rejection exits with status one and fixed diagnostics. Callers must close stdin, bound output, enforce a process deadline, and discard output unless exit status is zero. It is a test driver, not a supported security service or general command-line interface. No parsed or reserialized client data is forwarded.

The Node harness checks the 24 shared unsigned vectors against the Rust executable, then exercises signed assertions. Valid whitespace, Unicode and unknown JSON values must retain signature validity. Replacing signed bytes with an equivalent reserialization must fail. Correctly signed ambiguous inputs accepted by the unchanged helper must be rejected by the candidate gate. This does not imply that invoking the helper directly has become safe against those inputs.

Build the example from repository root with `cargo build -p vollmacht-helper-probe --example client-data-gate`. In this directory, set `VOLLMACHT_CLIENT_DATA_GATE` to the absolute `target/debug/examples/client-data-gate` path and run `npm run test:client-data-gate` using the pinned Node runtime. CI builds the release example and runs the suite on macOS and Linux. No new dependencies are introduced.

The gate checks syntax, not authority. Required WebAuthn fields, trusted expectations, raw-byte signature verification, current registry state and replay protection remain separate responsibilities. This harness calls the verification function directly; it does not establish private-pipe transport, registration coverage, runtime installation integrity, or controller-level enforcement. Production integration and compatibility decisions remain P06 gates.
