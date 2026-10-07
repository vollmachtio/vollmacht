# Native restart evidence review

Independent adversarial reviewer: `adversarial_p02`.

Disposition: no blocking findings in `spikes/macos-key/swift/RESULTS.md`.

Compared the record with the user-report context supplied for this review: reopened PASS, `existingKey` following another Create attempt, and no prompts; no supplied initial creation PASS or creation-time public key; earlier environment versions not reconfirmed. The document preserves those distinctions and does not invent an independently observed native run or a retained create/reopen key comparison.

The reopen result is correctly limited to the reviewed application's internal pin/record/signature checks. Duplicate Create stopping does not establish native concurrency exclusion or enumerate matching keys. Absence of prompts does not establish WebAuthn verification or biometric identity. The prior source-copy comparison and fake-suite run are attributed to the coordinating agent, not independently repeated in this evidence review or treated as running-binary attestation.

P04b remains open. Version/signing metadata, continuity, locked-device behavior, another-identity denial, native fault cases and protected enrollment remain separate gates. Future permission-sensitive tests require scoped authorization; the record neither authorizes them nor permits repinning, deletion, replacement identities or software fallback to bypass a stop.

Validation: read the complete result record and checked its two local documentation targets. No source changes, runtime tests, native calls, signing changes, app launch or Git mutations were performed. This is a review of evidence wording, not independent verification of hardware outcomes.

Reviewed source SHA-256:

```text
a072dc98f0a09fc4bc43e04854a80a915f56eb02d4d0b80e49c0bf262d5be755  spikes/macos-key/swift/RESULTS.md
```
