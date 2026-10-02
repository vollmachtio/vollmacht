# P06 enrollment and remote-precondition review

Scope: proposed enrollment/recovery lifecycle and GitHub merge-precondition assessment, linked from the architecture index. Neither document freezes a wire format or enables live execution.

Independent reviewer: `adversarial_p02`. Enrollment author: `mandate_design`; GitHub assessment author: root, using a separate primary-source investigation by the reviewer. Static review found one P2 ambiguity: a single-use capability and phase machine did not clearly span registration, activation and replacement authorization.

Resolved before commit: operation-level and stage-level state are separate; each stage gets a fresh ID/challenge; all stages share the original 120-second deadline. Cancellation, expiry or verification failure terminally consumes the operation and clears its pending candidate, while the old credential stays enabled until successful atomic replacement. Reviewer confirmed no remaining blockers.

The GitHub assessment distinguishes head protection from missing atomic base protection, labels the race analysis as inference, and retains a user-decision gate before a weaker live guarantee or different action. No GitHub test writes or native storage actions were performed.

Local validation: relative links and whitespace checked. There is no new executable schema or admin API to test. Hosted CI remains required. Extra enrollment confirmation, protected first-admin access, installation anchor, registry integrity, native evidence and exact administrative vectors remain acceptance gates.
