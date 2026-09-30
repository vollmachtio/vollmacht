//! Test fixture only. Produces fabricated claims; never use for real verification.
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    time::Duration,
};
use vollmacht_helper_probe::{FrameDecoder, Request, frame, rejection_frame};

fn sleep() {
    std::thread::sleep(Duration::from_secs(30));
}

fn main() {
    let path = std::env::args().nth(1).expect("fixture scenario");
    let mode = std::path::Path::new(&path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    std::fs::write("pid", std::process::id().to_string()).unwrap();
    if mode == "no-read" {
        sleep();
        return;
    }
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0; 103];
    loop {
        let n = std::io::stdin().read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        decoder.feed(&buffer[..n]).unwrap();
    }
    let body = decoder.finish().unwrap();
    let request = Request::parse(&body).unwrap();
    std::fs::write("ready", b"ready").unwrap();
    if mode == "wait" || mode == "gate" {
        while !std::path::Path::new("go").exists() {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    if mode == "no-output" {
        return;
    }
    if mode == "stdout-flood" {
        let _ = std::io::stdout().write_all(&[b'x'; 70_000]);
        sleep();
        return;
    }
    if mode == "stderr-flood" {
        let _ = std::io::stderr().write_all(&[b'x'; 8193]);
        sleep();
        return;
    }
    if mode == "stderr-limit" {
        std::io::stderr().write_all(&[b'x'; 8192]).unwrap();
    }
    if mode == "environment" {
        assert!(
            std::env::vars_os().next().is_none(),
            "environment must be empty"
        );
    }
    let input: Value = serde_json::from_slice(&body).unwrap();
    let mut reply = json!({"version":1, "kind":"verification_result", "request_id":input["request_id"],
        "challenge":input["challenge"], "outcome":"verified", "new_counter":1,
        "backup_eligible":false,"backed_up":false});
    match mode {
        "wrong-id" => reply["request_id"] = json!("ffffffffffffffffffffffffffffffff"),
        "wrong-challenge" => {
            reply["challenge"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")
        }
        "counter-regress" => reply["new_counter"] = json!(0),
        "backup" => reply["backed_up"] = json!(true),
        _ => (),
    }
    let mut bytes = if mode == "reject" {
        rejection_frame(&request).unwrap()
    } else {
        frame(&serde_json::to_vec(&reply).unwrap()).unwrap()
    };
    match mode {
        "truncated" => {
            bytes.pop();
        }
        "trailing" => bytes.push(0),
        "second-frame" => bytes.extend_from_within(..),
        "oversized" => bytes = 65_537_u32.to_be_bytes().to_vec(),
        _ => (),
    }
    if mode == "fragmented" {
        for byte in bytes {
            std::io::stdout().write_all(&[byte]).unwrap();
        }
    } else {
        std::io::stdout().write_all(&bytes).unwrap();
    }
    std::io::stdout().flush().unwrap();
    if mode == "success-crash" {
        std::process::exit(23);
    }
    if mode == "success-hang" {
        sleep();
    }
}
