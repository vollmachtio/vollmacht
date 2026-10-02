use std::{
    fs::File,
    io::Write,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Command, Stdio},
};

#[allow(unsafe_code)]
fn inheritable_copy(fd: &impl AsRawFd, minimum: i32) -> OwnedFd {
    use std::os::fd::FromRawFd;
    // SAFETY: F_DUPFD creates a new owned descriptor, never aliases an occupied
    // number; ownership is transferred exactly once into OwnedFd for cleanup.
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, minimum) };
    assert!(
        copy >= minimum,
        "failed to construct inheritable test descriptor"
    );
    let copy = unsafe { OwnedFd::from_raw_fd(copy) };
    assert_eq!(
        unsafe { libc::fcntl(copy.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    copy
}

#[test]
fn file_and_socket_leaks_are_closed_without_changing_pid_or_standard_pipes() {
    let file = File::open(std::env::current_exe().unwrap()).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    // High descriptor numbers avoid incidental reuse by the Rust runtime.
    let file_copy = inheritable_copy(&file, 128);
    let socket_copy = inheritable_copy(&socket, 192);
    for protected in [false, true] {
        let probe = env!("CARGO_BIN_EXE_descriptor-probe");
        let mut command = if protected {
            let mut c = Command::new(env!("CARGO_BIN_EXE_vollmacht-helper-launcher"));
            c.arg(probe);
            c
        } else {
            Command::new(probe)
        };
        // Deliberately supplied here to prove the launcher clears its target's
        // environment too. The coordinator normally clears it before first exec.
        command
            .env_clear()
            .env("VOLLMACHT_TEST_SENTINEL", "not-a-secret")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let original_pid = child.id();
        writeln!(
            child.stdin.take().unwrap(),
            "{} {}",
            file_copy.as_raw_fd(),
            socket_copy.as_raw_fd()
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["pid"], original_pid);
        assert_eq!(result["open"], serde_json::json!([!protected, !protected]));
        assert_eq!(result["environment_empty"], protected);
        assert_eq!(output.stderr, b"stderr preserved");
    }
    // The launcher must not mutate or close the parent's copies.
    let _still_open = inheritable_copy(&file_copy, 200);
    let _socket_still_open = inheritable_copy(&socket_copy, 210);
}

#[test]
fn invalid_arguments_and_missing_target_fail_silently() {
    let launcher = env!("CARGO_BIN_EXE_vollmacht-helper-launcher");
    let absolute = env!("CARGO_BIN_EXE_descriptor-probe");
    for args in [
        vec![],
        vec!["relative"],
        vec![absolute, "relative"],
        vec![absolute, absolute, absolute],
        vec!["/vollmacht/definitely/not/present"],
    ] {
        let output = Command::new(launcher)
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
    // Launch failure never interprets an unrecognized executable as a shell script.
    let path: PathBuf =
        std::env::temp_dir().join(format!("vollmacht-nonbinary-{}", std::process::id()));
    use std::os::unix::fs::PermissionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(b"printf must-not-run").unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .unwrap();
    drop(file);
    let output = Command::new(launcher)
        .arg(&path)
        .env_clear()
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
