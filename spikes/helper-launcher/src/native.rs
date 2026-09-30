//! The runtime unsafe exception, confined to a fresh single-threaded
//! executable. All arguments own NUL-terminated strings for the entire syscall.
use std::ffi::CString;

#[cfg(target_os = "linux")]
pub(super) fn replace(args: &[CString]) {
    // SAFETY: scalar syscall arguments; no pointers or Rust-owned handles are
    // closed now. CLOEXEC acts at exec, and this process never starts threads.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result != 0 {
        return;
    } // No enumeration/RLIMIT fallback on older kernels.
    let mut argv: Vec<_> = args.iter().map(|v| v.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env = [std::ptr::null()];
    // SAFETY: valid NUL-terminated pointer arrays backed by live CStrings.
    // execve has no shell fallback and preserves the PID on success.
    unsafe {
        libc::execve(args[0].as_ptr(), argv.as_ptr(), env.as_ptr());
    }
}

#[cfg(target_os = "macos")]
pub(super) fn replace(args: &[CString]) {
    let mut attr = std::ptr::null_mut();
    let mut actions = std::ptr::null_mut();
    // SAFETY: init receives valid writable pointers to native opaque handles.
    if unsafe { libc::posix_spawnattr_init(&mut attr) } != 0 {
        return;
    }
    if unsafe { libc::posix_spawn_file_actions_init(&mut actions) } != 0 {
        // SAFETY: attr was successfully initialized and is destroyed once.
        unsafe {
            libc::posix_spawnattr_destroy(&mut attr);
        }
        return;
    }
    // SAFETY: all calls use initialized live handles. SETEXEC replaces this
    // process instead of forking a grandchild; CLOEXEC_DEFAULT denies every FD
    // except the explicitly preserved stdin/stdout/stderr file actions.
    let mut ok = unsafe {
        libc::posix_spawnattr_setflags(
            &mut attr,
            (libc::POSIX_SPAWN_SETEXEC | libc::POSIX_SPAWN_CLOEXEC_DEFAULT) as libc::c_short,
        )
    } == 0;
    for fd in 0..=2 {
        ok &= unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions, fd, fd) } == 0;
    }
    if ok {
        let mut argv: Vec<_> = args.iter().map(|v| v.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        let env = [std::ptr::null_mut()];
        // SAFETY: arrays are NUL-terminated and CStrings remain live. pid is
        // intentionally NULL: SETEXEC cannot create an independently owned child.
        unsafe {
            libc::posix_spawn(
                std::ptr::null_mut(),
                args[0].as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                env.as_ptr(),
            );
        }
    }
    // Only an error can return with SETEXEC. Destroy both initialized handles.
    unsafe {
        libc::posix_spawn_file_actions_destroy(&mut actions);
        libc::posix_spawnattr_destroy(&mut attr);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn replace(_args: &[CString]) { /* Unsupported target: fail closed. */
}
