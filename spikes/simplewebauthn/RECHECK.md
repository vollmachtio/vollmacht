# Retained assertion recheck assessment

Experimental evidence, not an execution verifier. Three tests exercise the actual SimpleWebAuthn helper with software-generated assertions and its strict request decoder. No browser, passkey or hardware action occurs.

An assertion with counter five verifies repeatedly against its immutable original counter-zero context. The helper reports five but does not mutate the request or persist any counter. The same assertion rejects if verification instead supplies the already-advanced counter five. Changing the expected challenge also rejects. When both counters are zero, repeated verification succeeds: signature counters are not replay-consumption state.

This supports the candidate distinction between first issuance and retained-evidence rechecking. It does not implement a protected approval record or make an agent-supplied historical counter trustworthy. Only the issuer may store the original verified context; execution must independently check the current credential/key status, registry revision, policy and durable reservation. Rechecking must never write an old counter back over newer registry state or issue another mandate.

The helper's API has no current enabled/disabled registry field. A supplied extra field is rejected, not interpreted as authorization. Consequently these tests do not prove revocation or concurrent state enforcement. Those remain Rust-controller integration gates; helper success alone must never dispatch an operation.

Run `node helper-recheck-test.mjs` from this directory with the pinned Node runtime. The normal `npm test` command includes these checks. Raw signed client data is preserved, including a pretty-printed fixture; no signed bytes are reconstructed to perform rechecks.
