//! Restricted application JSON and approval schema/canonical bytes.
//!
//! Successful parsing does not establish a Human Mandate or authorization. In
//! particular, this profile must never validate signed WebAuthn client data,
//! which has different Unicode, number and extension compatibility rules.

mod approval;
mod client_data;
mod compact;
mod digest;
mod enrollment;
mod envelope;
mod execution;
mod json;
mod preflight;
mod proof_payload;
mod public_key;
mod signing_input;
mod verification;

pub use approval::{ApprovalError, ApprovalPayload};
pub use client_data::{ClientDataError, SyntaxCheckedClientData};
pub use compact::{CompactError, CompactRole, UnverifiedCompact, UnverifiedPayload};
pub use digest::{DigestError, envelope_digest, mandate_digest, operation_digest};
pub use enrollment::EnrollmentProposal;
pub use envelope::{EnvelopeError, MandateEnvelope};
pub use execution::{
    AssertionRecheckResult, EvidenceRecheckError, EvidenceRecheckRequest, EvidenceRechecker,
    ExecutionContext, ExecutionError, ExecutionTime, ExecutionTrust, OriginalCredential,
    PendingExecution, VerifiedExecutionCandidate, verify_claimed_attempt,
};
pub use json::{ApplicationObject, InputLimit, MAX_INPUT_BYTES, ParseError, parse_object};
pub use preflight::{
    CurrentMergePolicy, MergeMetadataProvider, MergeMethod, MergeObservation, MergeResourceRequest,
    MetadataError, ResourceComparedCandidate, ResourceComparisonError, compare_merge_resource,
};
pub use proof_payload::{EnrollmentPossessionPayload, ExecutionProofPayload, ProofPayloadError};
pub use public_key::{AgentPublicKey, EnrollmentError};
pub use signing_input::{PreparedSigningInput, SigningInputError};
pub use verification::{
    SignatureCheckedCompact, VerificationBinding, VerificationError, VerificationRuntime,
};
