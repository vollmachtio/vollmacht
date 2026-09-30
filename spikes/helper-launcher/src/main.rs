//! Single-threaded exec boundary. No Tokio, threads, protocol or credential data.
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path, process::ExitCode};

#[allow(unsafe_code)]
mod native;

fn main() -> ExitCode {
    // Exactly one absolute executable path and at most one absolute helper path.
    // Bounded iteration avoids retaining arbitrary untrusted argument lists.
    let raw: Vec<_> = std::env::args_os().skip(1).take(3).collect();
    if !(1..=2).contains(&raw.len()) || raw.iter().any(|v| !Path::new(v).is_absolute()) {
        return ExitCode::from(125);
    }
    let Ok(args) = raw
        .iter()
        .map(|v| CString::new(v.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return ExitCode::from(125);
    };
    // Success replaces this image and cannot return. All failure paths are silent.
    native::replace(&args);
    ExitCode::from(126)
}
