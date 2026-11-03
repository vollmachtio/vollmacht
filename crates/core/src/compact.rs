//! Strict compact-JWS preflight. No signature or authority verification.

use crate::{
    EnrollmentPossessionPayload, ExecutionProofPayload, InputLimit, MandateEnvelope, parse_object,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::fmt;

/// Select from the trusted calling operation, not from the submitted header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactRole {
    Issuer,
    Execution,
    EnrollmentPossession,
}

impl CompactRole {
    fn limits(self) -> (usize, usize) {
        match self {
            Self::Issuer => (100_000, 65_536),
            Self::Execution => (8_192, 8_192),
            Self::EnrollmentPossession => (8_192, 2_048),
        }
    }

    fn type_label(self) -> &'static str {
        match self {
            Self::Issuer => "vollmacht-mandate+jws",
            Self::Execution => "vollmacht-execution+jws",
            Self::EnrollmentPossession => "vollmacht-agent-enrollment+jws",
        }
    }
}

/// Schema-checked content that is still unsigned in the trust sense.
#[derive(Debug, PartialEq, Eq)]
pub enum UnverifiedPayload {
    Issuer(MandateEnvelope),
    Execution(ExecutionProofPayload),
    EnrollmentPossession(EnrollmentPossessionPayload),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactError;

impl fmt::Display for CompactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("compact artifact rejected")
    }
}

impl std::error::Error for CompactError {}

/// Immutable original bytes and bounded schema, never a verified artifact.
///
/// Matching a caller-supplied key ID is not proof that the caller used trusted
/// registry state. Signature verification, actual key resolution, current time,
/// pending state, retained WebAuthn verification and replay policy remain absent.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedCompact {
    role: CompactRole,
    original: Vec<u8>,
    signing_input_len: usize,
    signature: [u8; 64],
    payload: UnverifiedPayload,
}

impl UnverifiedCompact {
    /// Preflight using the role and key ID expected by the trusted caller.
    /// No alternate role, algorithm, decoder or key is tried on failure.
    pub fn parse(
        bytes: &[u8],
        role: CompactRole,
        expected_kid: &str,
    ) -> Result<Self, CompactError> {
        let (compact_cap, payload_cap) = role.limits();
        if bytes.is_empty() || bytes.len() > compact_cap || !bytes.is_ascii() {
            return Err(CompactError);
        }
        validate_key_id(role, expected_kid)?;
        let mut parts = bytes.split(|byte| *byte == b'.');
        let encoded_header = parts.next().ok_or(CompactError)?;
        let encoded_payload = parts.next().ok_or(CompactError)?;
        let encoded_signature = parts.next().ok_or(CompactError)?;
        if parts.next().is_some() {
            return Err(CompactError);
        }
        // Bound each encoded segment before its decoding allocation. Empty
        // segments are rejected, so detached and unsigned forms cannot pass.
        let header = decode(encoded_header, 512)?;
        validate_header(&header, role, expected_kid)?;
        let payload_bytes = decode(encoded_payload, payload_cap)?;
        let signature: [u8; 64] = decode(encoded_signature, 64)?
            .try_into()
            .map_err(|_| CompactError)?;
        let payload = match role {
            CompactRole::Issuer => UnverifiedPayload::Issuer(
                MandateEnvelope::parse_canonical(&payload_bytes).map_err(|_| CompactError)?,
            ),
            CompactRole::Execution => UnverifiedPayload::Execution(
                ExecutionProofPayload::parse_canonical(&payload_bytes).map_err(|_| CompactError)?,
            ),
            CompactRole::EnrollmentPossession => {
                let proof = EnrollmentPossessionPayload::parse_canonical(&payload_bytes)
                    .map_err(|_| CompactError)?;
                if proof.fields().get("agent_jkt").and_then(Value::as_str) != Some(expected_kid) {
                    return Err(CompactError);
                }
                UnverifiedPayload::EnrollmentPossession(proof)
            }
        };
        // Preserve the original encoded header.payload, never reconstruct it
        // from decoded objects for a later cryptographic verifier.
        let signing_input_len = encoded_header.len() + 1 + encoded_payload.len();
        Ok(Self {
            role,
            original: bytes.to_vec(),
            signing_input_len,
            signature,
            payload,
        })
    }

    pub fn role(&self) -> CompactRole {
        self.role
    }

    pub fn payload(&self) -> &UnverifiedPayload {
        &self.payload
    }

    pub fn compact_bytes(&self) -> &[u8] {
        &self.original
    }

    pub fn signing_input(&self) -> &[u8] {
        &self.original[..self.signing_input_len]
    }

    /// The length is validated, not the scalar values or signature itself.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

fn decode(encoded: &[u8], max: usize) -> Result<Vec<u8>, CompactError> {
    if encoded.is_empty() || encoded.len() > (max * 4).div_ceil(3) {
        return Err(CompactError);
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| CompactError)?;
    if bytes.is_empty() || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes).as_bytes() != encoded
    {
        return Err(CompactError);
    }
    Ok(bytes)
}

fn validate_key_id(role: CompactRole, key_id: &str) -> Result<(), CompactError> {
    match role {
        CompactRole::Issuer => {
            if key_id.len() != 32
                || !key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CompactError);
            }
        }
        CompactRole::Execution | CompactRole::EnrollmentPossession => {
            if decode(key_id.as_bytes(), 32)?.len() != 32 {
                return Err(CompactError);
            }
        }
    }
    Ok(())
}

fn validate_header(bytes: &[u8], role: CompactRole, key_id: &str) -> Result<(), CompactError> {
    let limit = InputLimit::new(512).ok_or(CompactError)?;
    let parsed = parse_object(bytes, limit).map_err(|_| CompactError)?;
    let fields = parsed.fields();
    if fields.len() != 3
        || fields.get("typ").and_then(Value::as_str) != Some(role.type_label())
        || fields.get("alg").and_then(Value::as_str) != Some("ES256")
        || fields.get("kid").and_then(Value::as_str) != Some(key_id)
    {
        return Err(CompactError);
    }
    // Fixed literals and the validated key alphabet need no JSON escaping.
    // This is the accepted preflight byte predicate, not a JOSE encoder/signer.
    let expected = format!(
        "{{\"typ\":\"{}\",\"alg\":\"ES256\",\"kid\":\"{}\"}}",
        role.type_label(),
        key_id
    );
    if expected.as_bytes() != bytes {
        return Err(CompactError);
    }
    Ok(())
}
