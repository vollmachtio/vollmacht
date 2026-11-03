//! Enrollment proposal A structure and binding, not administrator authority.

use crate::public_key::{binary, exact, require, sha256, string};
use crate::{AgentPublicKey, ApplicationObject, EnrollmentError, InputLimit, parse_object};
use serde_json::{Map, Value};

const FIELDS: &[&str] = &[
    "version",
    "crypto_profile",
    "operation",
    "operation_id",
    "installation_id",
    "audience",
    "principal_id",
    "credential_id",
    "registry_revision",
    "credential_revision",
    "policy_revision",
    "agent_key",
    "agent_jkt",
    "ceremony_id",
    "nonce",
    "issued_at",
    "expires_at",
];

/// Immutable canonical proposal with a valid public point and matching thumbprint.
/// This does not check pending context, signatures, current time, registry state,
/// administrator approval or whether an installation's agent slot is available.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrollmentProposal {
    object: ApplicationObject,
    agent_key: AgentPublicKey,
    canonical: Vec<u8>,
}

impl EnrollmentProposal {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let limit = InputLimit::new(4_096).ok_or(EnrollmentError::InvalidInput)?;
        let object = parse_object(bytes, limit).map_err(|_| EnrollmentError::InvalidInput)?;
        let fields = object.fields();
        let canonical = serde_jcs::to_vec(fields).map_err(|_| EnrollmentError::Serialization)?;
        // Prove the whole original is canonical before reserializing nested
        // key data, so original nested spelling and byte limits cannot vanish.
        if canonical != bytes {
            return Err(EnrollmentError::NonCanonical);
        }
        exact(fields, FIELDS)?;
        require(integer(fields, "version")? == 1)?;
        require(string(fields, "crypto_profile")? == "vollmacht-local-es256-v1")?;
        require(string(fields, "operation")? == "enroll_agent")?;
        for name in [
            "operation_id",
            "installation_id",
            "audience",
            "principal_id",
            "ceremony_id",
        ] {
            let value = string(fields, name)?;
            require(
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            )?;
        }
        binary(string(fields, "credential_id")?, 1, 1_024)?;
        binary(string(fields, "nonce")?, 32, 32)?;
        let thumbprint = binary(string(fields, "agent_jkt")?, 32, 32)?;
        for name in [
            "registry_revision",
            "credential_revision",
            "policy_revision",
        ] {
            require(integer(fields, name)? > 0)?;
        }
        let lifetime = integer(fields, "expires_at")?
            .checked_sub(integer(fields, "issued_at")?)
            .ok_or(EnrollmentError::InvalidInput)?;
        require((1..=120).contains(&lifetime))?;
        let key_fields = fields
            .get("agent_key")
            .and_then(Value::as_object)
            .ok_or(EnrollmentError::InvalidInput)?;
        let key_bytes =
            serde_jcs::to_vec(key_fields).map_err(|_| EnrollmentError::Serialization)?;
        let agent_key = AgentPublicKey::parse_canonical(&key_bytes)?;
        require(agent_key.thumbprint()?.as_slice() == thumbprint)?;
        // All fields except the depth-one key are explicitly scalar, enforcing
        // proposal depth two without accepting arbitrary nested values.
        Ok(Self {
            object,
            agent_key,
            canonical,
        })
    }

    pub fn fields(&self) -> &Map<String, Value> {
        self.object.fields()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn agent_key(&self) -> &AgentPublicKey {
        &self.agent_key
    }

    /// Domain-separated challenge digest; not evidence of an approval ceremony.
    pub fn authorization_digest(&self) -> Result<[u8; 32], EnrollmentError> {
        sha256(b"vollmacht:admin:enroll-agent:v1\0", self.canonical_bytes())
    }
}

fn integer(fields: &Map<String, Value>, name: &str) -> Result<u64, EnrollmentError> {
    fields
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(EnrollmentError::InvalidInput)
}
