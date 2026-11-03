//! Canonical proof payload schemas, not signatures or trusted pending context.

use crate::{ApplicationObject, InputLimit, parse_object};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use std::fmt;

const PROFILE: &str = "vollmacht-local-es256-v1";
const EXECUTION_FIELDS: &[&str] = &[
    "version",
    "crypto_profile",
    "mandate_digest",
    "operation_digest",
    "envelope_digest",
    "audience",
    "challenge",
    "issued_at",
    "expires_at",
];
const POSSESSION_FIELDS: &[&str] = &[
    "version",
    "crypto_profile",
    "operation",
    "operation_id",
    "installation_id",
    "audience",
    "principal_id",
    "agent_jkt",
    "authorization_digest",
    "ceremony_id",
    "challenge",
    "issued_at",
    "expires_at",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofPayloadError {
    InvalidPayload,
    NonCanonical,
    Serialization,
}

impl fmt::Display for ProofPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPayload => "proof payload rejected",
            Self::NonCanonical => "proof payload is not canonical",
            Self::Serialization => "proof payload serialization failed",
        })
    }
}

impl std::error::Error for ProofPayloadError {}

#[derive(Debug, PartialEq, Eq)]
struct ParsedPayload {
    object: ApplicationObject,
    canonical: Vec<u8>,
}

/// Immutable execution proof structure, not a verified proof or permission.
///
/// Digests, audience and times are only schema-checked. They still require
/// trusted pending-state matching, signature verification and freshness checks.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionProofPayload(ParsedPayload);

impl ExecutionProofPayload {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ProofPayloadError> {
        parse(bytes, 8_192, EXECUTION_FIELDS, validate_execution).map(Self)
    }

    pub fn fields(&self) -> &Map<String, Value> {
        self.0.object.fields()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0.canonical
    }
}

/// Immutable enrollment possession payload B, not enrollment or key possession.
///
/// No comparison with proposal A, administrator approval, registry, current
/// time, original deadline or candidate signature occurs at this layer.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrollmentPossessionPayload(ParsedPayload);

impl EnrollmentPossessionPayload {
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ProofPayloadError> {
        parse(bytes, 2_048, POSSESSION_FIELDS, validate_possession).map(Self)
    }

    pub fn fields(&self) -> &Map<String, Value> {
        self.0.object.fields()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0.canonical
    }
}

fn require(condition: bool) -> Result<(), ProofPayloadError> {
    if condition {
        Ok(())
    } else {
        Err(ProofPayloadError::InvalidPayload)
    }
}

fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProofPayloadError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ProofPayloadError::InvalidPayload)
}

fn integer(object: &Map<String, Value>, name: &str) -> Result<u64, ProofPayloadError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(ProofPayloadError::InvalidPayload)
}

fn identity(value: &str) -> Result<(), ProofPayloadError> {
    require(
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    )
}

fn binary32(value: &str) -> Result<(), ProofPayloadError> {
    // Exactly 32 bytes require 43 unpadded encoded characters. Bound before
    // allocation, then check decoded length and spelling, including pad bits.
    require(value.len() == 43)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProofPayloadError::InvalidPayload)?;
    require(decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == value)
}

fn parse(
    bytes: &[u8],
    cap: usize,
    names: &[&str],
    validate_role: fn(&Map<String, Value>) -> Result<(), ProofPayloadError>,
) -> Result<ParsedPayload, ProofPayloadError> {
    // Limits and field lists are private constants selected by the public type,
    // never supplied by the parsed payload or a caller configuration.
    let limit = InputLimit::new(cap).ok_or(ProofPayloadError::InvalidPayload)?;
    let object = parse_object(bytes, limit).map_err(|_| ProofPayloadError::InvalidPayload)?;
    let fields = object.fields();
    require(fields.len() == names.len() && names.iter().all(|name| fields.contains_key(*name)))?;
    require(integer(fields, "version")? == 1)?;
    require(string(fields, "crypto_profile")? == PROFILE)?;
    identity(string(fields, "audience")?)?;
    binary32(string(fields, "challenge")?)?;
    let lifetime = integer(fields, "expires_at")?
        .checked_sub(integer(fields, "issued_at")?)
        .ok_or(ProofPayloadError::InvalidPayload)?;
    require((1..=30).contains(&lifetime))?;
    // Every accepted field is explicitly a string or unsigned integer. This
    // also enforces the possession profile's depth-one restriction.
    validate_role(fields)?;
    let canonical = serde_jcs::to_vec(fields).map_err(|_| ProofPayloadError::Serialization)?;
    require(canonical.len() <= cap)?;
    if canonical != bytes {
        return Err(ProofPayloadError::NonCanonical);
    }
    Ok(ParsedPayload { object, canonical })
}

fn validate_execution(fields: &Map<String, Value>) -> Result<(), ProofPayloadError> {
    for name in ["mandate_digest", "operation_digest", "envelope_digest"] {
        binary32(string(fields, name)?)?;
    }
    Ok(())
}

fn validate_possession(fields: &Map<String, Value>) -> Result<(), ProofPayloadError> {
    require(string(fields, "operation")? == "enroll_agent")?;
    for name in [
        "operation_id",
        "installation_id",
        "principal_id",
        "ceremony_id",
    ] {
        identity(string(fields, name)?)?;
    }
    for name in ["agent_jkt", "authorization_digest"] {
        binary32(string(fields, name)?)?;
    }
    Ok(())
}
