//! Test-only inspection fixture: reads descriptor numbers, never file contents.
use std::io::{Read, Write};

#[allow(unsafe_code)]
fn is_open(fd: i32) -> bool {
    // SAFETY: F_GETFD takes only a scalar FD; it does not dereference memory.
    let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if result < 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }
    result >= 0
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .take(4096)
        .read_to_string(&mut input)
        .unwrap();
    let fds: Vec<i32> = input
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect();
    let open: Vec<bool> = fds.iter().map(|fd| is_open(*fd)).collect();
    let result = serde_json::json!({"pid":std::process::id(), "open":open,
        "environment_empty":std::env::vars_os().next().is_none()});
    std::io::stderr().write_all(b"stderr preserved").unwrap();
    println!("{result}");
}
