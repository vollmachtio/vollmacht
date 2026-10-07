# Candidate deployment and bootstrap boundary

Status: **PROPOSED**, 2026-10-07. This records the unresolved deployment contract needed by [P06](README.md#evidence-and-acceptance-gates) and [trusted enrollment](enrollment.md). It selects no account, sandbox, container, VM, signing identity, entitlement or paid service. It implements nothing, freezes no protocol and does not waive P04b. Existing developer experiments are not this deployment.

## Authority and ownership

The initial MVP must distinguish the trusted administrator/executor from the demonstrated agent environment. The following are logical ownership requirements, not claims about a selected macOS mechanism. The operator is trusted; protection against a compromised administrator, malicious trusted helper/UI or same-user malware is not claimed by the [release scope](../release-v0.1.md). That exclusion does not permit the configured agent to bypass the demonstrated enforcement path.

| Asset | Required owner and permitted use | Required agent denial |
| :--- | :--- | :--- |
| Issuer private key and retained public-key binding | Trusted signing component; exact approved envelope only | No extraction, replacement, repinning or alternate signing invocation |
| Installation anchor | Protected bootstrap authority, independently retained from the ordinary database | No creation, replacement, removal or reset that makes an initialized installation appear fresh |
| Registry, policy, credential evidence and approved records | Executor-owned storage; administrative changes only through scoped trusted ceremonies | No read of sensitive evidence, writes, path redirection or substitution of key/status/revision records |
| Reservations, revocations and recovery state | Executor-only durable state, retained across restart | No deletion, rewind, import or overwrite that restores consumed authority |
| GitHub write credential | Executor credential store and fixed merge adapter | No reading, exporting, inherited access or direct use through another tool/session |
| Node/helper, issuer adapter, executable, UI and trusted configuration | Reviewed installation/update path | No replacement, dependency or loader injection, writable ancestor/path substitution or agent-selected launch configuration |
| Administrative capability and active browser/terminal session | Deliberate operator session; bounded, operation-scoped in-memory use | No token capture, administration invocation, terminal/process inspection or browser-session control that impersonates the operator |
| Agent key and submitted proposals | Agent may hold its own private key and submit bounded inputs | Possession or submitted public keys never grant registry membership or administrator authority |

Public IDs, public keys and explicitly redacted diagnostics can cross the boundary through reviewed interfaces. Raw evidence and storage files do not become public merely because verification uses public-key cryptography. The [helper assessment](../helper-assessment.md) remains authoritative about private pipes, constrained environment and trusted runtime dependencies; absolute paths alone are not installation integrity.

Ordinary file permission bits do not distinguish two processes with equivalent effective access. A TTY, matching Unix user, localhost origin or pasted capability is not proof that the agent is excluded from the administrator's environment. The selected deployment must account for shared mounts, credentials, inherited descriptors/environment, host integration and process/browser access. Naming an account, container or VM is not evidence that these properties hold.

## Bootstrap and startup reconciliation

The installation anchor's exact representation, owner and protection mechanism remain unresolved. It must distinguish fresh setup from loss of previously initialized state and bind the installation to its retained issuer identity. The database cannot be its own independent anchor. A key pin in editable local preferences does not satisfy this requirement. These are design requirements, not new guarantees of the native experiment.

Bootstrap must have explicit persisted phases and a reviewed reconciliation procedure for its independently stored pieces. No cross-store atomic transaction is presumed. Before production implementation, specify the write order, durable acknowledgements and allowed read-only reconciliation for each interrupted phase. Test at least:

| Observed state or interruption | Required outcome |
| :--- | :--- |
| No prior anchor, database or dedicated key | Only explicitly authorized initialization may proceed; an empty directory alone is insufficient proof of freshness |
| Anchor exists but database or issuer key is absent | Block new authority; do not silently initialize, generate a key or repin |
| Database/key exists but anchor is absent, unreadable or mismatched | Block setup and authorization; preserve artifacts for scoped investigation |
| Key or anchor creation acknowledged, next bootstrap write fails | Remain incomplete; restart cannot report enrolled authority or auto-create another identity |
| Candidate registered/activated but registry commit fails or is uncertain | No reported enrollment success; read-only reconciliation, not repeated insertion from the response |
| Installation/key/revision bindings disagree, paths redirect, storage is unavailable or access is denied | Fail closed without fallback storage or inferred trust |
| Restart after approval or reservation | Invalidate unreserved approvals and pending challenges; retain consumed reservations and classify incomplete results under the existing recovery policy |
| Stale backup or backward clock state is presented | Reject detected inconsistency; never restore consumed authority through an automatic recovery path |

An anchor is not a universal anti-rollback device. If an attacker can restore the anchor, database and relevant machine state together, internal consistency can survive a rollback. Similarly, an unchanged identity anchor cannot detect every older but internally consistent database. The selected threat boundary must prevent the demonstrated agent from performing those restores. Detection claims must state what independent state supports them; neither a hash chain nor an anchor alone proves arbitrary rollback resistance. Existing [reservation and restart rules](README.md#adr-candidate-3-reservation-not-exactly-once-execution) remain required.

## Acceptance work and user choice

Before accepting P06, document the actual proposed agent location, administrator/executor location, allowed shared resources, bootstrap-anchor mechanism and runtime/storage ownership. Obtain independent review of the resulting boundary and startup contract. Obtain the required usable protected issuer-key evidence from P04b; software tests do not establish signed-identity denial or locked-device behavior. Keep these unresolved items visible rather than selecting a weaker fallback.

The user must choose an acceptable deployment arrangement before changes to accounts, machine/container setup, signing configuration or paid distribution. The concrete question is: **where will the agent execute, and which separation from the operator's terminal, browser, process state, registry and GitHub credential is acceptable?** No arrangement is chosen or authorized here. If the desired agent retains equivalent administrator access, report that enforcement blocker rather than asserting token-based isolation.

After that contract is accepted, implement and test the boundary as part of the existing plan. MVP acceptance must demonstrate agent-denied storage/key/token access, denied administrative invocation and runtime replacement, the startup fault cases above, and no direct GitHub write bypass. Use synthetic credentials and disposable test storage for automated negative tests; destructive fault injection against the user's retained key/database requires separate scoped authorization. Physical browser and issuer-key checks remain manual. Successful signatures, a fake state model or a normal startup alone cannot satisfy these tests.

Later implementation/release work includes packaged installation integrity, clean-machine onboarding, update ownership, explicit recovery/retention procedures and complete coverage enforcement under [R1 through R9](../release-v0.1.md#release-gates). Their detailed packaging implementation need not precede core development once P06 is accepted, but an unresolved usable protection boundary cannot be deferred as cosmetic hardening. Production GA, additional platforms and protection against a compromised administrator remain outside v0.1. This proposal adds no production code, recovery command or hardware action.
