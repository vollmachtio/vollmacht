CREATE TABLE binding (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 installation_id TEXT NOT NULL, bootstrap_commit_id TEXT NOT NULL,
 session_id TEXT NOT NULL, issuer_id TEXT NOT NULL, executor_id TEXT NOT NULL,
 principal_id TEXT NOT NULL, issuer_kid TEXT NOT NULL,
 provider_reference TEXT NOT NULL, issuer_public_key BLOB NOT NULL,
 wall_high_water INTEGER NOT NULL CHECK(wall_high_water>=0)
) STRICT;
CREATE TABLE registry (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 issuer_revision INTEGER NOT NULL CHECK(issuer_revision>0),
 principal_revision INTEGER NOT NULL CHECK(principal_revision>0),
 credential_revision INTEGER NOT NULL CHECK(credential_revision>0),
 agent_revision INTEGER NOT NULL CHECK(agent_revision>0),
 issuer_enabled INTEGER NOT NULL CHECK(issuer_enabled IN (0,1)),
 principal_enabled INTEGER NOT NULL CHECK(principal_enabled IN (0,1)),
 credential_enabled INTEGER NOT NULL CHECK(credential_enabled IN (0,1)),
 agent_enabled INTEGER NOT NULL CHECK(agent_enabled IN (0,1))
) STRICT;
CREATE TABLE mandates (
 mandate_id TEXT PRIMARY KEY, issuer_id TEXT NOT NULL, session_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('approved','reserved','invalidated')),
 issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 mandate_digest BLOB NOT NULL CHECK(length(mandate_digest)=32),
 operation_digest BLOB NOT NULL CHECK(length(operation_digest)=32),
 envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
 agent_jkt BLOB NOT NULL CHECK(length(agent_jkt)=32), audience TEXT NOT NULL,
 policy_revision INTEGER NOT NULL, issuer_revision INTEGER NOT NULL,
 principal_revision INTEGER NOT NULL, credential_revision INTEGER NOT NULL,
 agent_revision INTEGER NOT NULL
) STRICT;
CREATE TABLE challenges (
 challenge TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES mandates(mandate_id),
 session_id TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','claimed','rejected')),
 claim_operation_id TEXT UNIQUE
) STRICT;
CREATE UNIQUE INDEX active_challenge_per_mandate ON challenges(mandate_id) WHERE state IN ('pending','claimed');
CREATE TABLE operations (
 operation_id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES mandates(mandate_id),
 challenge TEXT NOT NULL REFERENCES challenges(challenge),
 outcome TEXT NOT NULL CHECK(outcome IN ('claimed','rejected'))
) STRICT;
CREATE TABLE audit (
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 transition TEXT NOT NULL CHECK(transition IN ('claimed','rejected')),
 wall_seconds INTEGER NOT NULL CHECK(wall_seconds>=0)
) STRICT;
PRAGMA user_version=1;
