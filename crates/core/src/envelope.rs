//! Canonical envelope structure, not WebAuthn or issuer verification.

use crate::{ApprovalPayload, InputLimit, parse_object};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use std::fmt;

/// Immutable canonical envelope whose evidence is still unverified.
///
/// Signed evidence remains opaque bytes represented by canonical base64url.
/// This type does not parse client data, verify signatures, establish credential
/// enrollment or validate the returned user handle against trusted state.
#[derive(Debug, PartialEq, Eq)]
pub struct MandateEnvelope {
    approval: ApprovalPayload,
    evidence: Map<String, Value>,
    canonical: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidEnvelope,
    NonCanonical,
    Serialization,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEnvelope => "mandate envelope rejected",
            Self::NonCanonical => "mandate envelope is not canonical",
            Self::Serialization => "mandate envelope serialization failed",
        })
    }
}

impl std::error::Error for EnvelopeError {}

impl MandateEnvelope {
    /// Require canonical original bytes before extracting the nested approval.
    ///
    /// Normalizing the outer input first would erase spelling/size evidence for
    /// nested payload checks. No constructor accepts an arbitrary parsed Value.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let object =
            parse_object(bytes, InputLimit::MAX).map_err(|_| EnvelopeError::InvalidEnvelope)?;
        let canonical =
            serde_jcs::to_vec(object.fields()).map_err(|_| EnvelopeError::Serialization)?;
        if canonical != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        let fields = object.fields();
        exact(fields, &["version", "payload", "evidence"])?;
        require(fields.get("version").and_then(Value::as_u64) == Some(1))?;
        let payload = fields
            .get("payload")
            .and_then(Value::as_object)
            .ok_or(EnvelopeError::InvalidEnvelope)?;
        let payload_bytes = serde_jcs::to_vec(payload).map_err(|_| EnvelopeError::Serialization)?;
        // Outer canonical equality proves these are the original nested bytes.
        // ApprovalPayload separately enforces its 8,192-byte raw/output limit.
        let approval = ApprovalPayload::parse_canonical(&payload_bytes)
            .map_err(|_| EnvelopeError::InvalidEnvelope)?;
        let evidence = fields
            .get("evidence")
            .and_then(Value::as_object)
            .ok_or(EnvelopeError::InvalidEnvelope)?;
        exact(
            evidence,
            &[
                "kind",
                "credential_id",
                "client_data_json",
                "authenticator_data",
                "signature",
                "user_handle",
            ],
        )?;
        require(string(evidence, "kind")? == "webauthn.get")?;
        let credential = string(evidence, "credential_id")?;
        binary(credential, 1, 1_024)?;
        require(
            Some(credential)
                == approval
                    .fields()
                    .get("credential_id")
                    .and_then(Value::as_str),
        )?;
        for (name, min, max) in [
            ("client_data_json", 1, 12_288),
            ("authenticator_data", 37, 8_192),
            ("signature", 1, 1_024),
            ("user_handle", 0, 64),
        ] {
            binary(string(evidence, name)?, min, max)?;
        }
        Ok(Self {
            approval,
            evidence: evidence.clone(),
            canonical,
        })
    }

    pub fn approval(&self) -> &ApprovalPayload {
        &self.approval
    }

    pub fn evidence(&self) -> &Map<String, Value> {
        &self.evidence
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

fn require(condition: bool) -> Result<(), EnvelopeError> {
    if condition {
        Ok(())
    } else {
        Err(EnvelopeError::InvalidEnvelope)
    }
}

fn exact(object: &Map<String, Value>, names: &[&str]) -> Result<(), EnvelopeError> {
    require(object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)))
}

fn string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, EnvelopeError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(EnvelopeError::InvalidEnvelope)
}

fn binary(value: &str, min: usize, max: usize) -> Result<(), EnvelopeError> {
    require(value.len() <= (max * 4).div_ceil(3))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EnvelopeError::InvalidEnvelope)?;
    require((min..=max).contains(&decoded.len()) && URL_SAFE_NO_PAD.encode(&decoded) == value)
}
