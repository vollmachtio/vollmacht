# Native restart experiment: reported results

Recorded 2026-10-05. These are maintainer-reported results from the [manual signed restart experiment](RESTART.md), not an independently observed hardware run. They do not complete P04b or establish production enrollment.

## Evidence received

| Action | User-reported result | Supported interpretation |
| :--- | :--- | :--- |
| Open and verify following the restart experiment | `PASS: reopened and verified a fixed-message signature.` | The reviewed open path reported success, including its internal public-key comparisons and fixed-message signature verification. |
| Create experimental key again | `STOP: existingKey` | The duplicate-create guard reported the expected stop. The user explicitly confirmed this was **Create experimental key**, not **Open and verify**. |
| Creation and reopening | No prompts reported | Consistent with this experiment's key profile, which does not require biometric verification. This does not test WebAuthn or prove biometric identity. |

The initial creation PASS message and public-key bytes were not supplied in the recorded evidence. There is therefore no independently retained create/reopen public-key pair to compare. The reopen PASS supports the experiment's internal comparison against its local preference pin and ready record; those stores are not a protected production registry. The duplicate-create result alone does not prove exclusive creation under concurrency or absence of additional matching native items.

Before this run, the coordinating agent reported comparing all three Xcode source copies (`Profile.swift`, `Runtime.swift`, `ProbeView.swift`) with the reviewed repository sources and successfully running the fake-only `run.py` checks. That preflight is software evidence, not independent observation of native key access or proof of the running binary's signing identity.

Previously user-reported context was macOS 26.6 and Xcode 27.0 (27A266a). These versions were **not reconfirmed for this run**. No signing identifiers, machine identifiers, binary digest, entitlement dump or numeric OS result was captured here.

## Remaining gates, in order

1. Complete the evidence record: reconfirm OS/Xcode versions and record narrowly scoped binary/signing/profile metadata for the tested app. Retain the public key from a subsequent successful **Open and verify** if provided; do not describe it as a recovered creation-time capture. Do not create another identity to fill this evidence gap.
2. Assess same-identity rebuild/update continuity with the retained pin and public key. Record any failure without changing identifiers, repinning or falling back to software storage.
3. Under a separately reviewed procedure, record locked/unlocked lookup and signing behavior independently. The current combined PASS does not separate those operations. Do not assume a prompt or automatic retry is appropriate.
4. Obtain separately authorized signing/entitlement test setups for another identity and missing/invalid authorization. Record denial or invisibility without assuming it from this successful run.
5. Review and assess native concurrency, ambiguous matches, changed pins, missing items and crash/orphan recovery. Existing fake tests are not native evidence. State-altering fault injection or cleanup requires explicit scoped approval; never reset the current pin or delete items to bypass a stop.
6. Resolve release identity, packaging, protected enrollment persistence and recovery, then review the full [P04b matrix](../DURABLE.md#signed-identity-and-manual-test-matrix). Record gate completion explicitly rather than inferring it from these two messages.

No other-identity denial, locked-device result, crash test, production enrollment or complete durable-key guarantee is claimed. No source, signing configuration, native item or cleanup action is changed by this record.
