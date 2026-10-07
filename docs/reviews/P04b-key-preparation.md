# Existing-key preparation review

Independent reviewer: `mandate_design`. Author: `durable_key_contract`. Reviewed 2026-10-06.

Disposition: no blocking findings in the final `Runtime.swift`, `RuntimeTests.swift` and README delta. This is a preparatory software refactor, not a native lock-state test or P04b completion.

## Source and test findings

`preparePersistent` preserves the original open path's validation order: validate the retained P-256 point, read and validate the exact ready record, require its pin match, require exactly one key, and compare that handle's public bytes with the pin. No creation, reservation, commit, signing, pin adoption or fallback is added to preparation. Its result retains the exact returned handle with immutable request/pin fields. The initializer is file-private; the result is expressly not authority or a durable registry. A reference-type handle's underlying object remains mutable, as documented.

`openPersistent` immediately uses the prepared handle and same pin in the unchanged fixed-message evidence verifier. It still signs once, enforces signature encoding bounds/canonicality and verifies the signature against the pinned public key and fixed message. Creation and native backend methods are unchanged. No new UI, timer, native call site or signing configuration is introduced.

All existing tests are retained. Added fakes check exact call sequences, handle identity, no storage mutation, invalid retained points before backend access, malformed/mismatched records, absent/duplicate/ambiguous lookups, substituted public keys and stage failures. Open-path controls reject malformed signatures and signatures over another message. The final lookup-cardinality matrix includes its unique-key success case through the same closure as its negative cases; this both detects an always-reject implementation and exercises the previously unexecuted normal-return path. No assertion, exclusion or coverage baseline was weakened.

The reviewer independently ran `python3 spikes/macos-key/swift/run.py`: both fake-only binaries passed and the UI typecheck completed successfully. Tests instantiate `FakeRuntime`, not `NativeKeyBackend`. No Keychain item operation, signed app, user project or hardware action was performed by this review. Fake results do not establish native immutability, concurrency, access denial or persistence.

## Coverage scope and evidence

No collector, normalizer, compiler configuration, runner or source-inventory entry changed. Existing `Runtime.swift` and `RuntimeTests.swift` remain in the same raw Swift fake-suite scope; no new path needs classification. `ProbeView.swift` remains explicitly unmeasured, and native methods remain represented without execution.

The coordinator collected base `857c6fe` and final-head reports and reported a zero-regression normalized comparison. The reviewer independently inspected those supplied raw reports and metadata, rather than rerunning collection. Compiler/LLVM versions and collector configuration matched; both used macOS SDK 26.5, build 25F70. Both reports contained 12 `NativeKeyBackend` function records, all with zero executions.

| Source | Base lines / functions | Final lines / functions |
| :--- | :--- | :--- |
| `Runtime.swift` | 42/137; 4/15 | 53/148; 6/17 |
| `RuntimeTests.swift` | 149/150; 44/44 | 290/291; 80/80 |
| `Profile.swift` | 77/79; 12/12 | Unchanged |
| `Tests.swift` | 163/168; 58/58 | Unchanged |

These are matched line/function measurements for the declared four-file scope, not branch coverage, complete repository coverage, an independently authenticated report chain or proof of security. No new infrastructure requirement is needed for this refactor.

## Final reviewed SHA-256

```text
54fad2dc23333a8365b0c0f99bcb17a512c8b4ca0ae225604747a24acd7f5c0b  spikes/macos-key/swift/Runtime.swift
cc48aaac8fd08c1014fc4c4d9127a86c47a73067814f80dddeb86ebe18d01a5e  spikes/macos-key/swift/RuntimeTests.swift
d16daa99aaf42aa53224eb15c44a8c6f5fdc19c61a553965a64e7170ca169eae  spikes/macos-key/swift/README.md
```
