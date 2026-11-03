//! Exact approval payload structure. No key trust, freshness or authorization.

use crate::{ApplicationObject, InputLimit, parse_object};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use std::fmt;

const MAX_PAYLOAD_BYTES: usize = 8_192;
const PROFILE: &str = "vollmacht-local-es256-v1";
const FIELDS: &[&str] = &[
    "version",
    "crypto_profile",
    "mandate_id",
    "nonce",
    "issuer_id",
    "audience",
    "principal_id",
    "credential_id",
    "agent_jkt",
    "policy_revision",
    "issued_at",
    "expires_at",
    "operation",
    "display",
];

/// Immutable schema-valid approval data, not an approved or trusted mandate.
///
/// This type does not check enrollment, nonce randomness, current time, trusted
/// display/resource resolution or cryptographic evidence. It grants no action.
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovalPayload {
    object: ApplicationObject,
    canonical: Vec<u8>,
}

/// Redacted errors contain neither submitted values nor upstream diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidPayload,
    NonCanonical,
    Serialization,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPayload => "approval payload rejected",
            Self::NonCanonical => "approval payload is not canonical",
            Self::Serialization => "approval serialization failed",
        })
    }
}

impl std::error::Error for ApprovalError {}

impl ApprovalPayload {
    /// Validate original bounded bytes, then serialize with maintained JCS.
    ///
    /// Valid input whitespace, member ordering and equivalent ASCII escapes may
    /// differ from the returned canonical bytes. No input normalization makes
    /// an otherwise invalid field valid.
    pub fn parse(bytes: &[u8]) -> Result<Self, ApprovalError> {
        let limit = InputLimit::new(MAX_PAYLOAD_BYTES).ok_or(ApprovalError::InvalidPayload)?;
        let object = parse_object(bytes, limit).map_err(|_| ApprovalError::InvalidPayload)?;
        validate(object.fields())?;
        let canonical =
            serde_jcs::to_vec(object.fields()).map_err(|_| ApprovalError::Serialization)?;
        require(canonical.len() <= MAX_PAYLOAD_BYTES)?;
        Ok(Self { object, canonical })
    }

    /// Additionally require original bytes to equal the exact canonical output.
    /// Never verify a rewritten signature input using this method's output.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, ApprovalError> {
        let parsed = Self::parse(bytes)?;
        if parsed.canonical != bytes {
            return Err(ApprovalError::NonCanonical);
        }
        Ok(parsed)
    }

    pub fn fields(&self) -> &Map<String, Value> {
        self.object.fields()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

fn require(condition: bool) -> Result<(), ApprovalError> {
    if condition {
        Ok(())
    } else {
        Err(ApprovalError::InvalidPayload)
    }
}

fn exact(object: &Map<String, Value>, names: &[&str]) -> Result<(), ApprovalError> {
    require(object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)))
}

fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, ApprovalError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ApprovalError::InvalidPayload)
}

fn integer(object: &Map<String, Value>, name: &str) -> Result<u64, ApprovalError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(ApprovalError::InvalidPayload)
}

fn child<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    names: &[&str],
) -> Result<&'a Map<String, Value>, ApprovalError> {
    let nested = object
        .get(name)
        .and_then(Value::as_object)
        .ok_or(ApprovalError::InvalidPayload)?;
    exact(nested, names)?;
    Ok(nested)
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn binary(value: &str, min: usize, max: usize) -> Result<(), ApprovalError> {
    // Bounds are internal constants, never submitted values. Reject encoded
    // overflow before allocating the decoded buffer, then require exact spelling.
    require(value.len() <= (max * 4).div_ceil(3))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApprovalError::InvalidPayload)?;
    require((min..=max).contains(&decoded.len()) && URL_SAFE_NO_PAD.encode(&decoded) == value)
}

fn branch(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value != "@"
        && value != "HEAD"
        && !value.starts_with('-')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && value.bytes().all(|byte| {
            (0x21..=0x7e).contains(&byte)
                && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        && value
            .split('/')
            .all(|part| !part.starts_with('.') && !part.ends_with(".lock"))
}

fn repository_label(value: &str) -> bool {
    if !(1..=201).contains(&value.len()) {
        return false;
    }
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    [owner, name].iter().all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    })
}

fn validate(object: &Map<String, Value>) -> Result<(), ApprovalError> {
    exact(object, FIELDS)?;
    require(integer(object, "version")? == 1)?;
    require(string(object, "crypto_profile")? == PROFILE)?;
    for name in ["mandate_id", "issuer_id", "audience", "principal_id"] {
        require(lower_hex(string(object, name)?, 32))?;
    }
    binary(string(object, "nonce")?, 32, 32)?;
    binary(string(object, "agent_jkt")?, 32, 32)?;
    binary(string(object, "credential_id")?, 1, 1024)?;
    require(integer(object, "policy_revision")? > 0)?;
    let issued = integer(object, "issued_at")?;
    let expires = integer(object, "expires_at")?;
    let lifetime = expires
        .checked_sub(issued)
        .ok_or(ApprovalError::InvalidPayload)?;
    require((1..=300).contains(&lifetime))?;

    let operation = child(object, "operation", &["action", "resource", "constraints"])?;
    require(string(operation, "action")? == "github.pull_request.merge")?;
    let resource = child(
        operation,
        "resource",
        &["host", "repository_id", "pull_request_number"],
    )?;
    require(string(resource, "host")? == "github.com")?;
    let repository_id = string(resource, "repository_id")?;
    require(
        (1..=20).contains(&repository_id.len())
            && !repository_id.starts_with('0')
            && repository_id.bytes().all(|byte| byte.is_ascii_digit()),
    )?;
    require((1..=2_147_483_647).contains(&integer(resource, "pull_request_number")?))?;
    let constraints = child(
        operation,
        "constraints",
        &["expected_head_sha", "base_ref", "merge_method"],
    )?;
    require(lower_hex(string(constraints, "expected_head_sha")?, 40))?;
    require(branch(string(constraints, "base_ref")?))?;
    require(matches!(
        string(constraints, "merge_method")?,
        "merge" | "squash" | "rebase"
    ))?;
    let display = child(object, "display", &["version", "repository"])?;
    require(integer(display, "version")? == 1)?;
    require(repository_label(string(display, "repository")?))
}
