//! Prepared bytes and compatibility guards, not a signing service or permission.
use crate::{
    AgentPublicKey, CompactRole, EnrollmentPossessionPayload, ExecutionProofPayload,
    MandateEnvelope, SignatureCheckedCompact, UnverifiedCompact, VerificationBinding,
    VerificationRuntime,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningInputError;
impl fmt::Display for SigningInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("prepared signing input rejected")
    }
}
impl std::error::Error for SigningInputError {}

/// Immutable exact bytes bound to a caller-supplied trusted key and role.
///
/// Construction proves schema/byte compatibility, not trusted lookup, approval,
/// current state, WebAuthn validity or permission to use a private key. No signer,
/// provider handle, clock, retry or software fallback is exposed here.
pub struct PreparedSigningInput {
    input: Vec<u8>,
    role: CompactRole,
    kid: String,
    binding: VerificationBinding,
}
impl fmt::Debug for PreparedSigningInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedSigningInput { .. }")
    }
}
impl PreparedSigningInput {
    /// Supply the registered issuer key label and public key from trusted state.
    pub fn issuer(
        payload: &MandateEnvelope,
        expected_kid: &str,
        key: &AgentPublicKey,
    ) -> Result<Self, SigningInputError> {
        Self::prepare(
            payload.canonical_bytes(),
            CompactRole::Issuer,
            expected_kid,
            key,
        )
    }

    /// Supply the permitted agent thumbprint and public key from trusted state.
    pub fn execution(
        payload: &ExecutionProofPayload,
        expected_kid: &str,
        key: &AgentPublicKey,
    ) -> Result<Self, SigningInputError> {
        Self::prepare(
            payload.canonical_bytes(),
            CompactRole::Execution,
            expected_kid,
            key,
        )
    }

    /// Supply the pending agent key binding. Matching B is not enrollment approval.
    pub fn enrollment_possession(
        payload: &EnrollmentPossessionPayload,
        expected_kid: &str,
        key: &AgentPublicKey,
    ) -> Result<Self, SigningInputError> {
        if payload
            .fields()
            .get("agent_jkt")
            .and_then(serde_json::Value::as_str)
            != Some(expected_kid)
        {
            return Err(SigningInputError);
        }
        Self::prepare(
            payload.canonical_bytes(),
            CompactRole::EnrollmentPossession,
            expected_kid,
            key,
        )
    }

    fn prepare(
        payload: &[u8],
        role: CompactRole,
        kid: &str,
        key: &AgentPublicKey,
    ) -> Result<Self, SigningInputError> {
        // Validate before interpolating the key label. The accepted alphabets
        // contain no JSON escapes; no arbitrary header fields are accepted.
        let binding = VerificationBinding::new(role, kid, key).map_err(|_| SigningInputError)?;
        let (typ, compact_cap) = match role {
            CompactRole::Issuer => ("vollmacht-mandate+jws", 100_000),
            CompactRole::Execution => ("vollmacht-execution+jws", 8_192),
            CompactRole::EnrollmentPossession => ("vollmacht-agent-enrollment+jws", 8_192),
        };
        let header = format!("{{\"typ\":\"{typ}\",\"alg\":\"ES256\",\"kid\":\"{kid}\"}}");
        let input = format!("{}.{}", B64.encode(header), B64.encode(payload)).into_bytes();
        // A raw ES256 signature encodes to 86 bytes, plus its separator. Reject
        // an oversized future artifact before any eventual signer can be called.
        if input
            .len()
            .checked_add(87)
            .is_none_or(|len| len > compact_cap)
        {
            return Err(SigningInputError);
        }
        Ok(Self {
            input,
            role,
            kid: kid.to_owned(),
            binding,
        })
    }

    pub fn signing_input(&self) -> &[u8] {
        &self.input
    }

    /// The eventual encoder callback must call this BEFORE using a key.
    /// Passing this guard does not authorize signing or reserve/consume a handle.
    /// A mismatch is terminal for that operation, never a request to re-sign.
    pub fn check_callback_input(&self, input: &[u8]) -> Result<(), SigningInputError> {
        if input == self.input {
            Ok(())
        } else {
            Err(SigningInputError)
        }
    }

    /// Check an encoder's final artifact against these exact prepared bytes and
    /// the same bound public key. Never repairs output or invokes a signer.
    /// Success checks only the outer signature, not authority or WebAuthn.
    pub fn validate_output(
        &self,
        runtime: &VerificationRuntime,
        bytes: &[u8],
    ) -> Result<SignatureCheckedCompact, SigningInputError> {
        let artifact =
            UnverifiedCompact::parse(bytes, self.role, &self.kid).map_err(|_| SigningInputError)?;
        self.check_callback_input(artifact.signing_input())?;
        runtime
            .verify(bytes, &self.binding)
            .map_err(|_| SigningInputError)
    }
}
