//! Experimental codec and single-ceremony lifecycle harness. No authority or proof.
//! Registry state is simulated in memory; no cryptographic or durable-state checks.

mod frame;
mod json;
mod lifecycle;
mod message;
mod process;

pub use frame::{FrameDecoder, MAX_BODY, frame};
pub use lifecycle::{Coordinator, Failure, Launch};
pub use message::{HelperResult, Request, decode_response, rejection_frame};

/// Fixed errors deliberately carry no input, credential or library diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Protocol,
    VerificationRejected,
}
