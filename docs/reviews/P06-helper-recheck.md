# P06 retained assertion recheck review

Independent reviewer: `durable_key_contract`, separate from root author. No blocking findings for this assessment-only change.

Reviewed `helper-recheck-test.mjs`, `RECHECK.md` and the package test-script addition, with the helper, strict decoder and software fixture implementation as context. Independently ran all three new tests using the pinned Node 24.21.0 runtime; all passed. Expected existing Web Crypto experimental warnings were emitted. No browser, hardware, real credential or execution path was exercised.

The tests distinguish stateless signature/evidence verification from mutable counter tracking: original counter context permits repeated checks without request mutation; equal advanced nonzero context rejects; changed expected challenge rejects; all-zero counters permit repeated checks. An unsupported enabled field is rejected by the envelope decoder, not interpreted as revocation enforcement. The test-script change appends these checks to the existing suite without changing dependencies or helper runtime behavior.

Documentation accurately limits the result. The tests do not implement protected historical context, current credential-status checks, durable reservation, concurrency enforcement or issuance. They do not justify accepting agent-supplied historical counters. End-to-end controller checks and preservation of newer registry state remain integration gates. This reviewer ran the three new tests, not the full existing npm suite or dependency audit.

Reviewed SHA-256 values:

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/helper-recheck-test.mjs` | `5e91bdf93bf6ad672a4f0205083020d7f3435c0ebfcd8a071db0955b7f8985c2` |
| `spikes/simplewebauthn/RECHECK.md` | `69fd90431f470a667004ef011b334d5cc3aac86b7aae48c70dfbf81cd2abb3cb` |
| `spikes/simplewebauthn/package.json` | `ce2d5d3f92b3d21a8c99f46244456aeda8e5992a34cb1b8e8e18a3052f86bbb9` |
