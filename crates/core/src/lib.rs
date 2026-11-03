//! Restricted application JSON and approval schema/canonical bytes.
//!
//! Successful parsing does not establish a Human Mandate or authorization. In
//! particular, this profile must never validate signed WebAuthn client data,
//! which has different Unicode, number and extension compatibility rules.

mod approval;
mod compact;
mod digest;
mod enrollment;
mod envelope;
mod json;
mod proof_payload;
mod public_key;
mod verification;

pub use approval::{ApprovalError, ApprovalPayload};
pub use compact::{CompactError, CompactRole, UnverifiedCompact, UnverifiedPayload};
pub use digest::{DigestError, envelope_digest, mandate_digest, operation_digest};
pub use enrollment::EnrollmentProposal;
pub use envelope::{EnvelopeError, MandateEnvelope};
pub use json::{ApplicationObject, InputLimit, MAX_INPUT_BYTES, ParseError, parse_object};
pub use proof_payload::{EnrollmentPossessionPayload, ExecutionProofPayload, ProofPayloadError};
pub use public_key::{AgentPublicKey, EnrollmentError};
pub use verification::{
    SignatureCheckedCompact, VerificationBinding, VerificationError, VerificationRuntime,
};
