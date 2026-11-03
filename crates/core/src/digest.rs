//! Typed, domain-separated digests. Matching digests confer no authority.

use crate::{ApprovalPayload, MandateEnvelope};
use openssl::hash::{Hasher, MessageDigest};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestError;

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mandate digest computation failed")
    }
}

impl std::error::Error for DigestError {}

/// Hash the validated canonical approval with the mandate domain and one NUL.
pub fn mandate_digest(approval: &ApprovalPayload) -> Result<[u8; 32], DigestError> {
    hash(b"vollmacht:mandate:v1\0", approval.canonical_bytes())
}

/// Hash only the exact canonical operation, not the display or evidence.
pub fn operation_digest(approval: &ApprovalPayload) -> Result<[u8; 32], DigestError> {
    let operation = approval.fields().get("operation").ok_or(DigestError)?;
    let bytes = serde_jcs::to_vec(operation).map_err(|_| DigestError)?;
    hash(b"vollmacht:operation:v1\0", &bytes)
}

/// Hash the validated canonical envelope, not any issuer signature encoding.
pub fn envelope_digest(envelope: &MandateEnvelope) -> Result<[u8; 32], DigestError> {
    hash(b"vollmacht:envelope:v1\0", envelope.canonical_bytes())
}

fn hash(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], DigestError> {
    let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|_| DigestError)?;
    hasher.update(domain).map_err(|_| DigestError)?;
    hasher.update(bytes).map_err(|_| DigestError)?;
    let digest = hasher.finish().map_err(|_| DigestError)?;
    digest.as_ref().try_into().map_err(|_| DigestError)
}
