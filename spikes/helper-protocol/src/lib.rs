//! Experimental codec only. A decoded helper success is not authority or proof.
//! No process, deadline, registry, cryptographic or durable-state checks live here.

mod frame;
mod json;
mod message;

pub use frame::{FrameDecoder, MAX_BODY, frame};
pub use message::{HelperResult, Request, decode_response, rejection_frame};

/// Fixed errors deliberately carry no input, credential or library diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Protocol,
    VerificationRejected,
}
