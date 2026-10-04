# P06 JOSE edge-vector review

Reviewed 2026-10-03 by independent reviewer `adversarial_p02`, separate from author `durable_key_contract`.

## Scope and disposition

No blockers found in the changes to `spikes/jose/tests/compatibility.rs` and `spikes/jose/README.md`. Other concurrent working-tree changes are outside this review. No production parser, signer, replay state, native key integration or library selection is introduced.

Literal DER expectations cover both small scalar padding and the extra positive-sign octet. Expected raw64 bytes are constructed independently of the conversion under test. The malformed DER checks allow decoder rejection or explicit detection of negative/noncanonical output; they do not falsely claim that the decoder rejects every malformed input. A separate assertion demonstrates trailing-data acceptance and the need for exact encoding checks.

Scalar rejection tests first verify a valid public-key/signature control, then substitute zero, order, order plus one and maximal 256-bit values independently into r and s. The malleability test verifies both original and order-minus-s signatures, checks that their bytes differ, and rejects a changed message. Direct OpenSSL verification is independent of josekit's conversion code, not an independent cryptographic provider. The README states that distinction and correctly ties replay identity to trusted mandate state rather than signature bytes.

## Independent validation

Ran `python3 scripts/check-jose.py`: formatting, strict Clippy and all 11 tests passed. No hardware operations, dependency changes, advisory refresh or full-workspace rerun was performed by this reviewer. Hosted exact-head CI remains a merge requirement.

These are selected compatibility vectors, not exhaustive DER/scalar conformance or proof of a production adapter's validation. The raw ES256 examples do not exercise compact JWS framing. Strict production parsing, exact canonicality, replay transactions and native signing remain separate gates.

## Reviewed source identity

SHA-256 of the reviewed working-tree files:

```text
2bebaf00315d4d7f01b107c1397593556e2f2fcd3665bff2445bc67ea4dba4cf  spikes/jose/README.md
b3ff276915fd3a90473bb31c3d70ef5f64a6a436f74cb5d3e440d6e0857d833e  spikes/jose/tests/compatibility.rs
```
