use std::process::ExitCode;

const HELP: &str = "Experimental Apple key probe. No mandates or persistent keys.\nUsage: vollmacht-macos-key-probe [help | secure-enclave]\nsecure-enclave creates a temporary hardware key and signs only a fixed test message.\nNo software fallback. This is not human authorization or an attestation service.";

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        [arg] if arg == "help" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        [arg] if arg == "secure-enclave" => run(),
        _ => {
            eprintln!("Unsupported arguments. Run help.");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run() -> ExitCode {
    eprintln!("unsupported_platform: this experiment requires macOS; no software fallback.");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
fn run() -> ExitCode {
    match apple::probe() {
        Ok(()) => {
            println!(
                "PASS: temporary Secure Enclave key requested; private export unavailable; fixed-message signature verified independently; DER/P1363 round-trip verified.\nNo persistent key was requested. This is local API evidence, not remote hardware attestation or human approval."
            );
            ExitCode::SUCCESS
        }
        Err(stage) => {
            eprintln!(
                "{stage}: experiment failed; no software fallback. See the spike README for platform and signing limits."
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "macos")]
mod apple {
    use security_framework::{
        access_control::{ProtectionMode, SecAccessControl},
        key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    };
    use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
    use vollmacht_macos_key_probe::{MESSAGE, der_to_p1363, p1363_to_der, verify};

    pub fn probe() -> Result<(), String> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|_| "access_control")?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        // Deliberately omit location: the wrapper sets isPermanent=false for both keys.
        // No lookup, label, migration, Keychain deletion, or fallback path is provided.
        let key = SecKey::new(&options)
            .map_err(|error| format!("key_creation (OS code {})", error.code()))?;
        if key.external_representation().is_some() {
            return Err("unexpected_private_export".into());
        }
        let public = key
            .public_key()
            .and_then(|key| key.external_representation())
            .ok_or("public_key_export")?;
        let signature = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, MESSAGE)
            .map_err(|error| format!("signing (OS code {})", error.code()))?;
        verify(public.bytes(), MESSAGE, &signature).map_err(|_| "independent_verification")?;
        let raw = der_to_p1363(&signature).map_err(|_| "der_conversion")?;
        let der = p1363_to_der(&raw).map_err(|_| "raw_conversion")?;
        verify(public.bytes(), MESSAGE, &der).map_err(|_| "round_trip_verification")?;
        if verify(public.bytes(), b"changed message", &signature).is_ok() {
            return Err("mutation_accepted".into());
        }
        Ok(())
    }
}
