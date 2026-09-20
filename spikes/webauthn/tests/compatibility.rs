//! Synthetic authenticator tests only. UV is deliberately simulated by the
//! upstream SoftPasskey; these tests do not demonstrate Touch ID or human consent.

use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

const ORIGIN: &str = "http://localhost:8374";

struct Fixture {
    server: Webauthn,
    authenticator: WebauthnAuthenticator<SoftPasskey>,
    credential: Passkey,
}

fn origin() -> Url {
    Url::parse(ORIGIN).expect("fixed test URL")
}

fn fixture() -> Fixture {
    let server = WebauthnBuilder::new("localhost", &origin())
        .expect("localhost RP configuration")
        .allow_any_port(false)
        .allow_subdomains(false)
        .build()
        .expect("WebAuthn configuration");
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, state) = server
        .start_passkey_registration(
            Uuid::from_u128(1),
            "vollmacht-probe",
            "Vollmacht synthetic probe",
            None,
        )
        .expect("registration options");
    let response = authenticator
        .do_registration(origin(), options)
        .expect("synthetic registration");
    let credential = server
        .finish_passkey_registration(&response, &state)
        .expect("verified registration");
    Fixture {
        server,
        authenticator,
        credential,
    }
}

#[test]
fn library_verifies_a_normal_random_challenge_ceremony() {
    let mut f = fixture();
    let (options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .expect("authentication options");
    let response = f
        .authenticator
        .do_authentication(origin(), options)
        .expect("synthetic assertion");
    let result = f
        .server
        .finish_passkey_authentication(&response, &state)
        .expect("verified assertion");
    assert!(result.user_verified());
}

#[test]
fn changing_only_the_browser_challenge_does_not_support_payload_binding() {
    let mut f = fixture();
    let (mut options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .expect("authentication options");
    // Use a guaranteed-different 32-byte challenge. The authenticator signs it
    // correctly; rejection must come from challenge validation, not a bad signature.
    let mut replacement = options.public_key.challenge.as_ref().to_vec();
    replacement[0] ^= 1;
    options.public_key.challenge = replacement.into();
    let response = f
        .authenticator
        .do_authentication(origin(), options)
        .expect("validly signed alternate challenge");
    assert!(matches!(
        f.server.finish_passkey_authentication(&response, &state),
        Err(WebauthnError::MismatchedChallenge)
    ));
}

#[test]
fn a_valid_assertion_cannot_be_swapped_into_another_ceremony() {
    let mut f = fixture();
    let credentials = [f.credential];
    let (options, first) = f.server.start_passkey_authentication(&credentials).unwrap();
    let (_, second) = f.server.start_passkey_authentication(&credentials).unwrap();
    let response = f
        .authenticator
        .do_authentication(origin(), options)
        .unwrap();
    assert!(
        f.server
            .finish_passkey_authentication(&response, &first)
            .is_ok()
    );
    assert!(matches!(
        f.server.finish_passkey_authentication(&response, &second),
        Err(WebauthnError::MismatchedChallenge)
    ));
}

#[test]
fn library_state_is_not_itself_a_single_use_replay_store() {
    let mut f = fixture();
    let (options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .unwrap();
    let response = f
        .authenticator
        .do_authentication(origin(), options)
        .unwrap();
    // This documents the caller's obligation: finish takes borrowed state and
    // does not consume it. The browser spike must own and atomically take state.
    assert!(
        f.server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
    assert!(
        f.server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
}

#[test]
fn validly_signed_wrong_port_origin_is_rejected() {
    let mut f = fixture();
    let (options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .unwrap();
    let other_origin = Url::parse("http://localhost:8375").unwrap();
    let response = f
        .authenticator
        .do_authentication(other_origin, options)
        .unwrap();
    assert!(matches!(
        f.server.finish_passkey_authentication(&response, &state),
        Err(WebauthnError::InvalidRPOrigin)
    ));
}

#[test]
fn client_cannot_downgrade_required_user_verification() {
    let mut f = fixture();
    let (mut options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .unwrap();
    // The synthetic backend sets UV only when the client options require it.
    options.public_key.user_verification = UserVerificationPolicy::Preferred;
    let response = f
        .authenticator
        .do_authentication(origin(), options)
        .unwrap();
    assert!(matches!(
        f.server.finish_passkey_authentication(&response, &state),
        Err(WebauthnError::UserNotVerified)
    ));
}

#[test]
fn an_unknown_credential_is_rejected() {
    let mut f = fixture();
    let (options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .unwrap();
    let mut response = f
        .authenticator
        .do_authentication(origin(), options)
        .unwrap();
    response.raw_id = vec![0; 32].into();
    assert!(matches!(
        f.server.finish_passkey_authentication(&response, &state),
        Err(WebauthnError::CredentialNotFound)
    ));
}

#[test]
fn a_corrupted_signature_is_rejected() {
    let mut f = fixture();
    let (options, state) = f
        .server
        .start_passkey_authentication(&[f.credential])
        .unwrap();
    let mut response = f
        .authenticator
        .do_authentication(origin(), options)
        .unwrap();
    response.response.signature = vec![0; 64].into();
    assert!(
        f.server
            .finish_passkey_authentication(&response, &state)
            .is_err()
    );
}
