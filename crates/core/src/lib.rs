//! Restricted application JSON and approval schema/canonical bytes.
//!
//! Successful parsing does not establish a Human Mandate or authorization. In
//! particular, this profile must never validate signed WebAuthn client data,
//! which has different Unicode, number and extension compatibility rules.

mod approval;
mod json;

pub use approval::{ApprovalError, ApprovalPayload};
pub use json::{ApplicationObject, InputLimit, MAX_INPUT_BYTES, ParseError, parse_object};
