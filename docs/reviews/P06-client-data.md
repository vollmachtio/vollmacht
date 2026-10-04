# P06 signed client-data characterization review

Independent reviewer: `durable_key_contract`, separate from author `mandate_design`. No blocking findings in the reviewed characterization tests, fixture extension or documentation.

Independently ran all five new tests with pinned Node 24.21.0; all passed. Inspected the test fixture, unchanged helper, strict outer request decoder, and installed SimpleWebAuthn 14.0.2 client-data decoder and authentication verifier. The library hashes original decoded bytes for signature verification, while its field interpretation uses JSON.parse. Tests validly sign each malformed or ambiguous fixture rather than tampering after signing and falsely claiming bypass.

The raw test override accepts only bounded Buffers and copies them before hashing. Default fixture behavior is preserved. Its software key and synthetic UP/UV flags establish no browser or human evidence. Valid representation variations are rejected when replaced without resigning. Duplicate, invalid UTF-8, surrogate and BOM outcomes are documented as limited characterization, not production permission, conformance proof or a credential-forgery exploit.

The proposed validation policy is clearly unimplemented, preserves original bytes, distinguishes unknown-field compatibility, and identifies registration as a separate gate. No helper runtime changes, dependencies, native operations or production parser are included. Review did not establish behavior for all malformed inputs or independently rerun the entire npm suite.

Reviewed SHA-256 values:

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/client-data-test.mjs` | `df8ea57de485de0b2261c6109b615390a23249758d36363d86a70438b4799a0c` |
| `spikes/simplewebauthn/CLIENT-DATA.md` | `e7495a1713ac1acf2453a4054857efa0c19c1d967db9a0366a316d90d6297ec2` |
| `spikes/simplewebauthn/fixture.mjs` | `fc8148fd6329bc78f80b09c7b78eea7bac53d3cff100ea796b0e2b6accaae1c5` |
| `spikes/simplewebauthn/package.json` | `ded202c197e0e3f60d7c84c6602505d6e2323a26d77590e88280c0916d1db784` |

Final combined package test-script integration is reviewed: all prior checks remain, followed by the retained-evidence recheck and client-data tests, with failure propagation preserved. Dependencies and other scripts are unchanged. The three previously reviewed content hashes still match.
