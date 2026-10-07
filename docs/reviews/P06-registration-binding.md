# Registration identity-binding assessment review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in this test-only characterization.

The positive registration control verifies the fixture's extracted credential ID and public key, and explicitly confirms empty none attestation. The outer-ID mismatch test accurately records rejection when browser id/rawId differ. The separate matched-outer-ID case preserves attestation bytes and accurately records library acceptance despite disagreement with the extracted authenticator credential ID. Its explicit inequality assertions expose the proposed-policy gap rather than pretending to enforce it.

Activation uses a different challenge and the credential returned by registration. The wrong-key control retains a genuinely valid signature under the other key while claiming the candidate ID, verifies that signature independently with Node crypto, and then observes failure under the registered candidate key. This distinguishes private-key possession from successful none-attestation parsing. Synthetic UP/UV flags do not establish a human ceremony.

The existing Session was inspected: it stores the credential returned by registration verification. The documentation accurately describes that behavior while retaining the future three-ID equality requirement and activation/commit gates. No runtime Session, verifier, registration transport or dependency is changed. Package integration retains earlier tests and appends this file; inventory adds one unmeasured test source. The architecture crosslink explicitly remains an assessment, not acceptance of production enrollment.

## Independent validation

- Ran the new file using pinned Node 24.21.0: all five tests passed.
- Inspected the existing Session credential assignment and the fixture/verification boundaries.
- Reviewed all five scoped files. Did not run the network-dependent full package suite, modify reviewed sources, invoke hardware or mutate Git.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/simplewebauthn/registration-binding.test.mjs` | `843cb176e5c2f03251b9724c6b2d627e66eaee46baaf1e5dc441bcc3c7867e97` |
| `spikes/simplewebauthn/REGISTRATION-BINDING.md` | `30b6497c2c54f1136ca7eff5e2fde594e60efe508e55ac80b5e103f303aaef64` |
| `spikes/simplewebauthn/package.json` | `460527acc67e1d57799e4ef696d8ce5920568adb75198f0b03595a94e0daa287` |
| `coverage/sources.json` | `56a4375af66faac0cee91e1d00636be544bdc92b40160751cbd908932f269a92` |
| `docs/architecture/enrollment.md` | `0731ecb0b345898030971123105bca47bc5e7166e59bce300e19f2b30f5e44d8` |
