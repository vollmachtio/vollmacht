//! Restricted application JSON and approval schema/canonical bytes.
//!
//! Successful parsing does not establish a Human Mandate or authorization. In
//! particular, this profile must never validate signed WebAuthn client data,
//! which has different Unicode, number and extension compatibility rules.

mod approval;
mod digest;
mod envelope;
mod json;

pub use approval::{ApprovalError, ApprovalPayload};
pub use digest::{DigestError, envelope_digest, mandate_digest, operation_digest};
pub use envelope::{EnvelopeError, MandateEnvelope};
pub use json::{ApplicationObject, InputLimit, MAX_INPUT_BYTES, ParseError, parse_object};
