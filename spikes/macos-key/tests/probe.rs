//! Software-generated test keys validate encoding/verification, never Secure Enclave behavior.
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use vollmacht_macos_key_probe::{MESSAGE, der_to_p1363, p1363_to_der, verify};

fn fixture() -> (PKey<Private>, Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let public = key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
        .unwrap();
    let key = PKey::from_ec_key(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(MESSAGE).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    (key, public, signature)
}

#[test]
fn independent_verification_and_encoding_round_trip() {
    let (_, public, signature) = fixture();
    verify(&public, MESSAGE, &signature).unwrap();
    let raw = der_to_p1363(&signature).unwrap();
    assert_eq!(raw.len(), 64);
    let der = p1363_to_der(&raw).unwrap();
    assert_eq!(der, signature);
    verify(&public, MESSAGE, &der).unwrap();
}

#[test]
fn altered_message_and_wrong_key_are_rejected() {
    let (_, public, signature) = fixture();
    let (_, other, _) = fixture();
    assert!(verify(&public, b"different", &signature).is_err());
    assert!(verify(&other, MESSAGE, &signature).is_err());
}

#[test]
fn signature_bit_mutations_are_rejected() {
    let (_, public, signature) = fixture();
    for index in 0..signature.len() {
        let mut changed = signature.clone();
        changed[index] ^= 1;
        assert!(verify(&public, MESSAGE, &changed).is_err());
    }
}

#[test]
fn malformed_public_points_and_lengths_are_rejected() {
    let (_, public, signature) = fixture();
    for key in [vec![], vec![4; 65], public[..64].to_vec(), vec![0; 66]] {
        assert!(verify(&key, MESSAGE, &signature).is_err());
    }
    let mut changed = public;
    changed[0] = 2;
    assert!(verify(&changed, MESSAGE, &signature).is_err());
}

#[test]
fn malformed_noncanonical_and_zero_signatures_are_rejected() {
    let (_, _, mut signature) = fixture();
    signature.push(0);
    for der in [
        vec![],
        vec![0; 73],
        signature,
        vec![0x30, 6, 2, 1, 0, 2, 1, 1],    // zero r
        vec![0x30, 6, 2, 1, 0xff, 2, 1, 1], // negative r
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1], // redundant padding
    ] {
        assert!(der_to_p1363(&der).is_err());
    }
    for raw in [vec![], vec![1; 63], vec![1; 65], vec![0; 64]] {
        assert!(p1363_to_der(&raw).is_err());
    }
}

#[test]
fn fixed_width_padding_and_high_bit_der_padding_round_trip() {
    for first in [1_u8, 0x7f, 0x80, 0xff] {
        let mut raw = [0_u8; 64];
        raw[31] = 1; // small r requires left padding in P1363
        raw[32] = first;
        let der = p1363_to_der(&raw).unwrap();
        assert_eq!(der_to_p1363(&der).unwrap(), raw);
    }
}

#[test]
fn encodable_out_of_range_scalars_are_not_valid_signatures() {
    let (_, public, _) = fixture();
    let raw = [0xff_u8; 64];
    let der = p1363_to_der(&raw).unwrap();
    assert_eq!(der_to_p1363(&der).unwrap(), raw);
    assert!(verify(&public, MESSAGE, &der).is_err());
}

#[test]
fn default_help_and_invalid_arguments_never_invoke_hardware() {
    for args in [vec![], vec!["help"]] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_vollmacht-macos-key-probe"))
            .args(args)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(String::from_utf8_lossy(&result.stdout).contains("No software fallback"));
    }
    for args in [vec!["SECRET"], vec!["secure-enclave", "SECRET"]] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_vollmacht-macos-key-probe"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("SECRET"));
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_platform_has_no_fallback() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_vollmacht-macos-key-probe"))
        .arg("secure-enclave")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported_platform"));
}
