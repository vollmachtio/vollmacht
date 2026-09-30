use crate::{HelperResult, Request};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    CeremonyUnavailable,
    Cancelled,
    DeadlineExceeded,
    HelperLaunchFailed,
    HelperProtocolError,
    HelperExitFailed,
    HelperCleanupFailed,
    VerificationRejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn fixture() -> Request {
        let value = serde_json::json!({"version":1,"kind":"verify_assertion",
            "request_id":"000102030405060708090a0b0c0d0e0f","challenge":URL_SAFE_NO_PAD.encode([0;32]),
            "rp_id":"localhost","origin":"http://localhost:8374",
            "credential":{"id":"AA","public_key":"AA","counter":0,"user_handle":"AA","backup_eligible":false},
            "assertion":{"id":"AA","raw_id":"AA","type":"public-key","client_data_json":"AA",
                "authenticator_data":URL_SAFE_NO_PAD.encode([0;37]),"signature":"AA","user_handle":""}});
        Request::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn delayed_launch_and_cleanup_disable_coordinator_but_retain_reaper() {
        for delayed_launch in [true, false] {
            let c = Coordinator::new(fixture(), Instant::now() + Duration::from_secs(10));
            let reaped = Arc::new(AtomicBool::new(false));
            let delay = Duration::from_millis(1600);
            let faults = crate::process::Faults {
                launch_delay: if delayed_launch {
                    delay
                } else {
                    Duration::ZERO
                },
                reap_delay: if delayed_launch {
                    Duration::ZERO
                } else {
                    delay
                },
                reaped: Some(reaped.clone()),
            };
            let launch = Launch {
                // This unit test exercises ownership faults only; integration
                // tests in helper-launcher exercise the actual exec boundary.
                launcher: PathBuf::from("/usr/bin/env"),
                executable: PathBuf::from("/bin/cat"),
                helper: None,
                directory: std::env::temp_dir(),
            };
            assert_eq!(
                c.verify_inner(launch.clone(), Duration::from_millis(100), faults),
                Err(Failure::HelperCleanupFailed)
            );
            assert!(c.disabled());
            assert_eq!(c.verify(launch), Err(Failure::CeremonyUnavailable));
            let deadline = Instant::now() + Duration::from_secs(4);
            while !reaped.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "late child not reaped");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(c.counter(), 0);
        }
    }
}

/// Trusted launcher configuration. Arguments must never contain evidence/secrets.
/// This experiment does not establish ownership, signing or file integrity.
#[derive(Clone)]
pub struct Launch {
    pub launcher: PathBuf,
    pub executable: PathBuf,
    pub helper: Option<PathBuf>,
    pub directory: PathBuf,
}

impl Launch {
    pub(crate) fn valid(&self) -> bool {
        self.launcher.is_absolute()
            && self.executable.is_absolute()
            && self.directory.is_absolute()
            && self.helper.as_ref().is_none_or(|path| path.is_absolute())
    }
}

pub(crate) struct State {
    claimed: bool,
    finished: bool,
    pub(crate) failure: Option<Failure>,
    revision: u64,
    enabled: bool,
    counter: u32,
    disabled: bool,
}

/// Single pending ceremony, constructed only from a trusted synthetic fixture.
/// No enrollment API, challenge generation, persistent registry or execution.
/// Dropping the calling thread cannot discard the worker's child ownership.
pub struct Coordinator {
    request: Arc<Request>,
    state: Arc<Mutex<State>>,
    expires: Instant,
}

impl Coordinator {
    pub fn new(request: Request, expires: Instant) -> Self {
        let counter = request.counter();
        Self {
            request: Arc::new(request),
            expires,
            state: Arc::new(Mutex::new(State {
                claimed: false,
                finished: false,
                failure: None,
                revision: 0,
                enabled: true,
                counter,
                disabled: false,
            })),
        }
    }

    /// Terminal until a completed acceptance; a later cancel cannot undo success.
    pub fn cancel(&self) {
        let mut state = self.state.lock().unwrap();
        if !state.finished {
            state.failure.get_or_insert(Failure::Cancelled);
        }
    }

    /// Simulates a serialized registry mutation, without accepting new evidence.
    pub fn change_registry(&self, enabled: bool) {
        let mut state = self.state.lock().unwrap();
        state.enabled = enabled;
        // Saturation must never allow an unchanged revision to look fresh.
        match state.revision.checked_add(1) {
            Some(revision) => state.revision = revision,
            None => state.disabled = true,
        }
    }

    pub fn counter(&self) -> u32 {
        self.state.lock().unwrap().counter
    }

    pub fn disabled(&self) -> bool {
        self.state.lock().unwrap().disabled
    }

    pub fn verify(&self, launch: Launch) -> Result<HelperResult, Failure> {
        self.verify_with_budget(launch, Duration::from_secs(5))
    }

    fn verify_with_budget(
        &self,
        launch: Launch,
        budget: Duration,
    ) -> Result<HelperResult, Failure> {
        self.verify_inner(launch, budget, crate::process::Faults::default())
    }

    fn verify_inner(
        &self,
        launch: Launch,
        budget: Duration,
        faults: crate::process::Faults,
    ) -> Result<HelperResult, Failure> {
        let deadline = self.expires.min(Instant::now() + budget);
        let revision;
        {
            let mut state = self.state.lock().unwrap();
            if state.disabled || state.claimed || state.finished {
                return Err(Failure::CeremonyUnavailable);
            }
            if let Some(error) = state.failure {
                state.finished = true;
                return Err(error);
            }
            if Instant::now() >= deadline {
                state.finished = true;
                state.failure = Some(Failure::CeremonyUnavailable);
                return Err(Failure::CeremonyUnavailable);
            }
            state.claimed = true;
            // This single fixture was captured when the registry revision was 0.
            // A mutation before claim is stale too, not just one during I/O.
            revision = 0;
            if !state.enabled || state.revision != revision {
                state.finished = true;
                state.failure = Some(Failure::VerificationRejected);
                return Err(Failure::VerificationRejected);
            }
        }
        let result = crate::process::run(
            launch,
            self.request.clone(),
            self.state.clone(),
            deadline,
            faults,
        );
        let mut state = self.state.lock().unwrap();
        state.finished = true;
        if result == Err(Failure::HelperCleanupFailed) {
            state.disabled = true;
            state.failure = Some(Failure::HelperCleanupFailed);
        }
        if let Some(error) = state.failure {
            return Err(error);
        }
        if Instant::now() >= deadline {
            state.failure = Some(Failure::DeadlineExceeded);
            return Err(Failure::DeadlineExceeded);
        }
        match result {
            Ok(claim) if state.enabled && state.revision == revision && !state.disabled => {
                state.counter = claim.new_counter;
                Ok(claim)
            }
            Ok(_) => {
                state.failure = Some(Failure::VerificationRejected);
                Err(Failure::VerificationRejected)
            }
            Err(error) => {
                state.failure = Some(error);
                Err(error)
            }
        }
    }
}
