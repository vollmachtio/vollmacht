use std::env;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Vollmacht: verifiable human authority for AI agents\n\
Experimental development shell. Authorization is not implemented.\n\n\
Usage: vollmacht [help | version]\n\
  help, -h     Show this message\n\
  version, -V  Show the development version\n";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let first = args.next();

    // Reject the whole invocation before handling even informational commands.
    // Never echo untrusted arguments, which could contain secrets or terminal escapes.
    let response = if args.next().is_some() {
        None
    } else {
        match first.as_deref() {
            None => Some(HELP.to_owned()),
            Some(arg) if arg == OsStr::new("help") || arg == OsStr::new("-h") => {
                Some(HELP.to_owned())
            }
            Some(arg) if arg == OsStr::new("version") || arg == OsStr::new("-V") => Some(format!(
                "vollmacht {} (experimental)\n",
                env!("CARGO_PKG_VERSION")
            )),
            _ => None,
        }
    };

    match response {
        Some(text) => match io::stdout().lock().write_all(text.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        None => {
            let _ = io::stderr()
                .lock()
                .write_all(b"Unsupported arguments. Run 'vollmacht help'.\n");
            ExitCode::from(2)
        }
    }
}
