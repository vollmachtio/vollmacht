//! A dedicated owner thread retains responsibility even if launch blocks.
use crate::lifecycle::State;
use crate::{Error, Failure, FrameDecoder, HelperResult, Launch, Request, decode_response};
use std::{
    process::Stdio,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
};

const CLEANUP: Duration = Duration::from_secs(1);

/// Faults exist only in unit-test builds, never in the launcher API.
#[derive(Default)]
pub(crate) struct Faults {
    #[cfg(test)]
    pub launch_delay: Duration,
    #[cfg(test)]
    pub reap_delay: Duration,
    #[cfg(test)]
    pub reaped: Option<Arc<std::sync::atomic::AtomicBool>>,
}

fn cleanup_failed(state: &Mutex<State>) -> Failure {
    let mut state = state.lock().unwrap();
    state.failure = Some(Failure::HelperCleanupFailed);
    Failure::HelperCleanupFailed
}

fn stop(state: &Mutex<State>, deadline: Instant) -> Option<Failure> {
    let mut state = state.lock().unwrap();
    if Instant::now() >= deadline {
        state.failure.get_or_insert(Failure::DeadlineExceeded);
    }
    state.failure
}

fn record(state: &Mutex<State>, error: Failure) -> Failure {
    let mut state = state.lock().unwrap();
    *state.failure.get_or_insert(error)
}

pub(crate) fn run(
    launch: Launch,
    request: Arc<Request>,
    state: Arc<Mutex<State>>,
    deadline: Instant,
    faults: Faults,
) -> Result<HelperResult, Failure> {
    if !launch.valid() {
        return Err(record(&state, Failure::HelperLaunchFailed));
    }
    let (tx, rx) = mpsc::sync_channel(1);
    let worker_state = state.clone();
    // Dedicated owner survives caller timeout; blocking OS spawn cannot strand a
    // late child. No Tokio task cancellation can silently discard this owner.
    let worker = thread::Builder::new()
        .name("vollmacht-helper-owner".into())
        .spawn(move || {
            let result = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(execute(
                    launch,
                    request,
                    worker_state.clone(),
                    deadline,
                    faults,
                )),
                Err(_) => Err(record(&worker_state, Failure::HelperLaunchFailed)),
            };
            let _ = tx.send(result);
        });
    if worker.is_err() {
        return Err(record(&state, Failure::HelperLaunchFailed));
    }
    // First await normal completion. Then allow bounded cancellation cleanup.
    // Short polling observes cancel without waiting out the full ceremony TTL.
    loop {
        match rx.recv_timeout(Duration::from_millis(5)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(cleanup_failed(&state));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
        if stop(&state, deadline).is_some() {
            return match rx.recv_timeout(CLEANUP) {
                Ok(result) => result,
                Err(_) => Err(cleanup_failed(&state)),
            };
        }
    }
}

async fn stdout(mut stream: impl AsyncRead + Unpin) -> Result<Vec<u8>, Failure> {
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| Failure::HelperProtocolError)?;
        if count == 0 {
            return decoder.finish().map_err(|_| Failure::HelperProtocolError);
        }
        decoder
            .feed(&buffer[..count])
            .map_err(|_| Failure::HelperProtocolError)?;
    }
}

async fn stderr(mut stream: impl AsyncRead + Unpin) -> Result<(), Failure> {
    let mut total = 0;
    let mut buffer = [0; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| Failure::HelperProtocolError)?;
        if count == 0 {
            return Ok(());
        }
        total += count;
        if total > 8192 {
            return Err(Failure::HelperProtocolError);
        }
    }
}

async fn send(mut input: impl AsyncWrite + Unpin, bytes: &[u8]) -> Result<(), Failure> {
    input
        .write_all(bytes)
        .await
        .map_err(|_| Failure::HelperProtocolError)?;
    input
        .shutdown()
        .await
        .map_err(|_| Failure::HelperProtocolError)?;
    Ok(())
}

async fn execute(
    launch: Launch,
    request: Arc<Request>,
    state: Arc<Mutex<State>>,
    deadline: Instant,
    _faults: Faults,
) -> Result<HelperResult, Failure> {
    if let Some(error) = stop(&state, deadline) {
        return Err(error);
    }
    let bytes = request
        .to_frame()
        .map_err(|_| record(&state, Failure::HelperProtocolError))?;
    let mut command = Command::new(launch.launcher);
    command.arg(launch.executable);
    if let Some(helper) = launch.helper {
        command.arg(helper);
    }
    command
        .current_dir(launch.directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(test)]
    std::thread::sleep(_faults.launch_delay);
    let mut child = command
        .spawn()
        .map_err(|_| record(&state, Failure::HelperLaunchFailed))?;
    // A successful spawn with Stdio::piped creates these owned handles.
    let input = child.stdin.take().expect("piped stdin");
    let output = child.stdout.take().expect("piped stdout");
    let diagnostic = child.stderr.take().expect("piped stderr");
    let result = {
        let transfer = async {
            let write = send(input, &bytes);
            let wait = async {
                let status = child.wait().await.map_err(|_| Failure::HelperExitFailed)?;
                if status.success() {
                    Ok(())
                } else {
                    Err(Failure::HelperExitFailed)
                }
            };
            let (_, body, _, _) =
                tokio::try_join!(write, stdout(output), stderr(diagnostic), wait)?;
            decode_response(&body, &request).map_err(|error| match error {
                Error::Protocol => Failure::HelperProtocolError,
                Error::VerificationRejected => Failure::VerificationRejected,
            })
        };
        tokio::pin!(transfer);
        loop {
            if let Some(error) = stop(&state, deadline) {
                break Err(error);
            }
            tokio::select! {
                result = &mut transfer => break result,
                _ = tokio::time::sleep(Duration::from_millis(5)) => (),
            }
        }
    }; // All pipe futures dropped before cleanup.
    if let Err(error) = result {
        let error = record(&state, error);
        let _ = child.start_kill();
        #[cfg(test)]
        tokio::time::sleep(_faults.reap_delay).await;
        match tokio::time::timeout(CLEANUP, child.wait()).await {
            Ok(Ok(_)) => {
                #[cfg(test)]
                if let Some(reaped) = _faults.reaped {
                    reaped.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                return Err(error);
            }
            _ => {
                {
                    cleanup_failed(&state);
                }
                // Remain responsible for eventual reaping after the caller returns.
                let _ = child.wait().await;
                return Err(Failure::HelperCleanupFailed);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_stdin_future_is_cancellable_and_closes_its_writer() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (writer, mut reader) = tokio::io::duplex(1);
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), send(writer, &[0; 1024]))
                        .await
                        .is_err()
                );
                let mut retained = Vec::new();
                // A reader-held buffer of one byte proves the write was actually blocked.
                reader.read_to_end(&mut retained).await.unwrap();
                assert_eq!(retained, vec![0]);
            });
    }
}
