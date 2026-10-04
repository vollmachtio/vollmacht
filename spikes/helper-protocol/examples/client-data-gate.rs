//! Test driver only, not a production helper or WebAuthn verification endpoint.
//! Caller must close stdin and enforce process/output deadlines. Success echoes
//! original bytes; output must be discarded unless the process exits successfully.

#[path = "../tests/support/client_data.rs"]
mod validation;

use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

fn run() -> Result<(), ()> {
    if std::env::args_os().nth(1).is_some() {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(validation::MAX_BYTES + 1);
    io::stdin()
        .lock()
        .take((validation::MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    validation::validate(&bytes).map_err(|_| ())?;
    let mut output = io::stdout().lock();
    output.write_all(&bytes).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            // Diagnostics are deliberately fixed; never print parser or IO details.
            let _ = io::stderr().lock().write_all(b"client_data_rejected\n");
            ExitCode::from(1)
        }
    }
}
