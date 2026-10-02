use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use vollmacht_helper_probe::{Coordinator, Failure, Launch, Request};

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vollmacht-helper-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn launch(&self, mode: &str) -> Launch {
        Launch {
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_vollmacht-helper-launcher")),
            executable: PathBuf::from(env!("CARGO_BIN_EXE_fake-helper")),
            helper: Some(self.0.join(mode)),
            directory: self.0.clone(),
        }
    }
    fn ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.0.join("ready").exists() {
            assert!(Instant::now() < deadline, "fake helper never became ready");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn reaped(&self) {
        if let Ok(pid) = std::fs::read_to_string(self.0.join("pid")) {
            let status = std::process::Command::new("/bin/kill")
                .args(["-0", &pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(
                !status.success(),
                "child still exists after verification returned"
            );
        }
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(counter: u32) -> Request {
    request_sized(counter, false)
}

fn request_sized(counter: u32, largest: bool) -> Request {
    let mut value = json!({"version":1,"kind":"verify_assertion",
        "request_id":"000102030405060708090a0b0c0d0e0f", "challenge":URL_SAFE_NO_PAD.encode([0;32]),
        "rp_id":"localhost", "origin":"http://localhost:8374",
        "credential":{"id":"AA","public_key":"AA","counter":counter,"user_handle":"AA","backup_eligible":false},
        "assertion":{"id":"AA","raw_id":"AA","type":"public-key","client_data_json":"AA",
            "authenticator_data":URL_SAFE_NO_PAD.encode([0;37]),"signature":"AA","user_handle":""}});
    if largest {
        for (path, size) in [
            ("/credential/id", 1024),
            ("/credential/public_key", 4096),
            ("/credential/user_handle", 64),
            ("/assertion/id", 1024),
            ("/assertion/raw_id", 1024),
            ("/assertion/client_data_json", 12288),
            ("/assertion/authenticator_data", 8192),
            ("/assertion/signature", 1024),
            ("/assertion/user_handle", 64),
        ] {
            *value.pointer_mut(path).unwrap() = json!(URL_SAFE_NO_PAD.encode(vec![0; size]));
        }
    }
    Request::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn coordinator(ttl: Duration) -> Arc<Coordinator> {
    Arc::new(Coordinator::new(request(0), Instant::now() + ttl))
}

#[test]
fn complete_success_requires_eof_exit_and_is_single_use() {
    for mode in ["success", "fragmented", "stderr-limit", "environment"] {
        let temp = Sandbox::new();
        let c = coordinator(Duration::from_secs(5));
        assert_eq!(c.verify(temp.launch(mode)).unwrap().new_counter, 1);
        assert_eq!(c.counter(), 1);
        c.cancel(); // cancellation after committed acceptance cannot undo it
        assert_eq!(c.counter(), 1);
        assert_eq!(
            c.verify(temp.launch(mode)),
            Err(Failure::CeremonyUnavailable)
        );
        temp.reaped();
    }
}

#[test]
fn malformed_outputs_and_helper_failures_are_consumed_and_reaped() {
    for (mode, expected) in [
        ("wrong-id", Failure::HelperProtocolError),
        ("wrong-challenge", Failure::HelperProtocolError),
        ("truncated", Failure::HelperProtocolError),
        ("trailing", Failure::HelperProtocolError),
        ("second-frame", Failure::HelperProtocolError),
        ("oversized", Failure::HelperProtocolError),
        ("stdout-flood", Failure::HelperProtocolError),
        ("stderr-flood", Failure::HelperProtocolError),
        ("no-output", Failure::HelperProtocolError),
        ("success-crash", Failure::HelperExitFailed),
        ("reject", Failure::VerificationRejected),
        ("backup", Failure::VerificationRejected),
    ] {
        let temp = Sandbox::new();
        let c = coordinator(Duration::from_secs(5));
        assert_eq!(c.verify(temp.launch(mode)), Err(expected), "{mode}");
        assert_eq!(c.counter(), 0);
        assert_eq!(
            c.verify(temp.launch(mode)),
            Err(Failure::CeremonyUnavailable)
        );
        temp.reaped();
    }
}

#[test]
fn hangs_during_read_or_after_success_are_killed_and_reaped() {
    for mode in ["no-read", "wait", "success-hang"] {
        let temp = Sandbox::new();
        let c = coordinator(Duration::from_millis(250));
        let start = Instant::now();
        assert_eq!(
            c.verify(temp.launch(mode)),
            Err(Failure::DeadlineExceeded),
            "{mode}"
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(c.counter(), 0);
        temp.reaped();
    }
}

#[test]
fn expired_or_cancelled_pending_never_launches() {
    let temp = Sandbox::new();
    let c = coordinator(Duration::ZERO);
    assert_eq!(
        c.verify(temp.launch("success")),
        Err(Failure::CeremonyUnavailable)
    );
    let c = coordinator(Duration::from_secs(5));
    c.cancel();
    assert_eq!(c.verify(temp.launch("success")), Err(Failure::Cancelled));
    assert!(!temp.0.join("pid").exists());
}

#[test]
fn concurrent_attempt_does_not_disturb_owner_and_cancellation_wins() {
    let temp = Sandbox::new();
    let c = coordinator(Duration::from_secs(5));
    let worker = {
        let c = c.clone();
        let launch = temp.launch("gate");
        std::thread::spawn(move || c.verify(launch))
    };
    temp.ready();
    assert_eq!(
        c.verify(temp.launch("success")),
        Err(Failure::CeremonyUnavailable)
    );
    c.cancel();
    std::fs::write(temp.0.join("go"), b"go").unwrap();
    assert_eq!(worker.join().unwrap(), Err(Failure::Cancelled));
    assert_eq!(c.counter(), 0);
    temp.reaped();
}

#[test]
fn registry_change_during_verification_rejects_stale_result() {
    for enabled in [true, false] {
        let temp = Sandbox::new();
        let c = coordinator(Duration::from_secs(5));
        let worker = {
            let c = c.clone();
            let launch = temp.launch("gate");
            std::thread::spawn(move || c.verify(launch))
        };
        temp.ready();
        c.change_registry(enabled);
        std::fs::write(temp.0.join("go"), b"go").unwrap();
        assert_eq!(worker.join().unwrap(), Err(Failure::VerificationRejected));
        assert_eq!(c.counter(), 0);
        temp.reaped();
    }
}

#[test]
fn disabled_registry_and_bad_launcher_do_not_execute() {
    let temp = Sandbox::new();
    let c = coordinator(Duration::from_secs(5));
    c.change_registry(false);
    assert_eq!(
        c.verify(temp.launch("success")),
        Err(Failure::VerificationRejected)
    );
    for path in [PathBuf::from("relative"), temp.0.join("absent")] {
        let c = coordinator(Duration::from_secs(5));
        let mut launch = temp.launch("success");
        launch.launcher = path;
        assert_eq!(c.verify(launch), Err(Failure::HelperLaunchFailed));
    }
    assert!(!temp.0.join("pid").exists());
    let c = coordinator(Duration::from_secs(5));
    c.change_registry(true);
    assert_eq!(
        c.verify(temp.launch("success")),
        Err(Failure::VerificationRejected)
    );
    assert!(!temp.0.join("pid").exists());
}

#[test]
fn maximum_request_to_nonreading_child_is_bounded_and_can_also_roundtrip() {
    for mode in ["no-read", "success"] {
        let temp = Sandbox::new();
        let c = Coordinator::new(
            request_sized(0, true),
            Instant::now() + Duration::from_millis(400),
        );
        let result = c.verify(temp.launch(mode));
        if mode == "no-read" {
            assert_eq!(result, Err(Failure::DeadlineExceeded));
        } else {
            assert!(result.is_ok());
        }
        temp.reaped();
    }
}

#[test]
fn counter_regression_cannot_commit() {
    let temp = Sandbox::new();
    let c = Coordinator::new(request(1), Instant::now() + Duration::from_secs(5));
    assert_eq!(
        c.verify(temp.launch("counter-regress")),
        Err(Failure::VerificationRejected)
    );
    assert_eq!(c.counter(), 1);
    temp.reaped();
}
