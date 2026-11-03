# Registration transport model review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no unresolved blocking findings in this test-only proposal assessment. This is not approval of a registration helper or a frozen protocol.

## Review findings

Review requested explicit valid-string mutations for RP ID, origin, registration type and rejection code, plus a genuine version 1 assertion shape to exercise separation in both directions. The final tests include these controls, verify the version 1 positive parse first, reject its original and relabeled shapes in the proposed decoder, and reject both version 2 response alternatives through the existing version 1 decoder. This closes the identified test-completeness gap.

The model matches the proposed structural field sets, literals, correlation, unsigned counters and backup combinations. It reuses the unchanged private outer parser before values can discard duplicate names or normalize integer syntax. Base64url bounds apply before decoding and canonical re-encoding is checked afterward. Boundary tests exercise each binary field, maximum aggregate body size including whitespace, fragmented framing and poisoned decoder state after trailing frames.

Client-data syntax and browser-ID equality are separate semantic preconditions. Response ID comparisons cover both browser fields, but do not extract an authenticator credential ID. Original opaque evidence bytes survive model processing unchanged. The fixed success result is explicitly simulated: invalid attestation and key placeholders are deliberately accepted structurally, not cryptographically. The documentation accurately excludes maintained-library verification, COSE validation, cross-runtime agreement, activation, process lifecycle and protected-state enforcement.

The inventory delta adds only the new test file as unmeasured. No runtime codec, parser visibility, dependencies or native operations change. The reviewed fixtures and model share authorship and therefore are not independent conformance oracles; that limitation is explicit.

## Independent validation

- Ran the full helper package: all 53 tests passed, including eight in the new integration binary, of which two are reused parser tests.
- Workspace formatting and helper-package strict all-target Clippy passed.
- Inventory validation passed with 110 sources.
- Reviewed the proposed registration contract and all four scoped files. No Git mutations, reviewed-source edits or hardware operations performed.

## Reviewed source SHA-256

| File | SHA-256 |
| :--- | :--- |
| `spikes/helper-protocol/tests/registration_vectors.rs` | `2fd10f92716a20d6345e0dd7d695e19c9a6ad698d437468abf11bc6fdcadb442` |
| `spikes/helper-protocol/registration-vectors.json` | `036cd70624573010ab652cb0520a0a6aa58afad0d9e90f5ef9ac8131aae07278` |
| `spikes/helper-protocol/REGISTRATION-VECTORS.md` | `4ad1ebdeafbc3b589b24a5c3aebf8874fbecf5a850d3c862d5664385e66bf0af` |
| `coverage/sources.json` | `361d6e65a94cf8c9785d35f6a6cfb8c5348ef0fedb53ee232cfe3dd2e25652a5` |
