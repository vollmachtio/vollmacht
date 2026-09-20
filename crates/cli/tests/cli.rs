use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vollmacht"))
        .args(args)
        .output()
        .expect("CLI should start")
}

#[test]
fn help_is_explicit_about_implementation_status() {
    for args in [&[][..], &["help"][..], &["-h"][..]] {
        let result = run(args);
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let text = String::from_utf8(result.stdout).expect("help is UTF-8");
        assert!(text.contains("Authorization is not implemented."));
        assert!(text.contains("Usage: vollmacht"));
    }
}

#[test]
fn version_matches_package_metadata() {
    for arg in ["version", "-V"] {
        let result = run(&[arg]);
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        assert_eq!(
            result.stdout,
            format!("vollmacht {} (experimental)\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
    }
}

#[test]
fn unsupported_invocations_fail_without_echoing_input() {
    for args in [
        vec!["merge"],
        vec!["approve"],
        vec![""],
        vec!["help", "secret-token"],
        vec!["version", "merge"],
        vec!["\u{1b}[2Jsecret-token"],
    ] {
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert_eq!(
            result.stderr,
            b"Unsupported arguments. Run 'vollmacht help'.\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_are_rejected_without_panicking() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let result = Command::new(env!("CARGO_BIN_EXE_vollmacht"))
        .arg(OsString::from_vec(vec![0xff]))
        .output()
        .expect("CLI should start");
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(
        result.stderr,
        b"Unsupported arguments. Run 'vollmacht help'.\n"
    );
}
