//! Synthetic UV only. These tests do not establish physical Touch ID behavior.
use std::time::Instant;
use vollmacht_webauthn_probe::{
    ORIGIN,
    ceremony::{Ceremonies, Error, TTL},
};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;

fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}
fn origin() -> Url {
    Url::parse(ORIGIN).unwrap()
}
fn synthetic(mut options: CreationChallengeResponse) -> CreationChallengeResponse {
    // SoftPasskey rejects platform hints; removing this client hint does not change server UV policy.
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .authenticator_attachment = None;
    options
}
fn enroll(state: &mut Ceremonies, auth: &mut WebauthnAuthenticator<SoftPasskey>, now: Instant) {
    let (id, options) = state.start_registration(now).unwrap();
    let response = auth.do_registration(origin(), synthetic(options)).unwrap();
    state.finish_registration(&id, &response, now).unwrap();
}

#[test]
fn enrollment_is_required_and_cannot_be_replaced() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    assert!(matches!(
        state.start_authentication(now),
        Err(Error::NotRegistered)
    ));
    enroll(&mut state, &mut authenticator(), now);
    assert!(matches!(
        state.start_registration(now),
        Err(Error::AlreadyRegistered)
    ));
}

#[test]
fn registration_response_is_single_use() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let (id, options) = state.start_registration(now).unwrap();
    let response = authenticator()
        .do_registration(origin(), synthetic(options))
        .unwrap();
    assert_eq!(state.finish_registration(&id, &response, now), Ok(()));
    assert_eq!(
        state.finish_registration(&id, &response, now),
        Err(Error::NoMatchingCeremony)
    );
}

#[test]
fn failed_registration_is_consumed_and_does_not_enroll() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let (id, mut options) = state.start_registration(now).unwrap();
    options.public_key.challenge = vec![0_u8; 32].into();
    let response = authenticator()
        .do_registration(origin(), synthetic(options))
        .unwrap();
    assert_eq!(
        state.finish_registration(&id, &response, now),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        state.finish_registration(&id, &response, now),
        Err(Error::NoMatchingCeremony)
    );
    assert!(matches!(
        state.start_authentication(now),
        Err(Error::NotRegistered)
    ));
    assert!(state.start_registration(now).is_ok());
}

#[test]
fn authentication_success_and_failure_both_consume_state() {
    for corrupt in [false, true] {
        let now = Instant::now();
        let mut state = Ceremonies::new().unwrap();
        let mut auth = authenticator();
        enroll(&mut state, &mut auth, now);
        let (id, options) = state.start_authentication(now).unwrap();
        let mut response = auth.do_authentication(origin(), options).unwrap();
        if corrupt {
            response.response.signature = vec![0_u8; 64].into();
        }
        assert_eq!(
            state.finish_authentication(&id, &response, now),
            if corrupt {
                Err(Error::VerificationFailed)
            } else {
                Ok(())
            }
        );
        assert_eq!(
            state.finish_authentication(&id, &response, now),
            Err(Error::NoMatchingCeremony)
        );
        assert!(state.start_authentication(now).is_ok());
    }
}

#[test]
fn expiration_at_exact_deadline_rejects_both_ceremonies() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let mut auth = authenticator();
    let (id, options) = state.start_registration(now).unwrap();
    let response = auth.do_registration(origin(), synthetic(options)).unwrap();
    assert_eq!(
        state.finish_registration(&id, &response, now + TTL),
        Err(Error::NoMatchingCeremony)
    );
    enroll(&mut state, &mut auth, now + TTL);
    let (id, options) = state.start_authentication(now + TTL).unwrap();
    let response = auth.do_authentication(origin(), options).unwrap();
    assert_eq!(
        state.finish_authentication(&id, &response, now + TTL * 2),
        Err(Error::NoMatchingCeremony)
    );
}

#[test]
fn just_before_expiry_succeeds() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let (id, options) = state.start_registration(now).unwrap();
    let response = authenticator()
        .do_registration(origin(), synthetic(options))
        .unwrap();
    assert_eq!(
        state.finish_registration(
            &id,
            &response,
            now + TTL - std::time::Duration::from_nanos(1)
        ),
        Ok(())
    );
}

#[test]
fn pending_cancellation_and_stale_ids_cannot_replace_current_state() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let (old_id, _) = state.start_registration(now).unwrap();
    assert!(matches!(state.start_registration(now), Err(Error::Busy)));
    state.cancel(&old_id, now).unwrap();
    let (id, options) = state.start_registration(now).unwrap();
    assert_ne!(old_id, id);
    assert_eq!(state.cancel(&old_id, now), Err(Error::NoMatchingCeremony));
    let response = authenticator()
        .do_registration(origin(), synthetic(options))
        .unwrap();
    assert_eq!(
        state.finish_registration(&old_id, &response, now),
        Err(Error::NoMatchingCeremony)
    );
    assert_eq!(state.finish_registration(&id, &response, now), Ok(()));
}

#[test]
fn wrong_kind_submission_consumes_matching_state() {
    let now = Instant::now();
    let mut state = Ceremonies::new().unwrap();
    let mut auth = authenticator();
    let (id, options) = state.start_registration(now).unwrap();
    let registration = auth.do_registration(origin(), synthetic(options)).unwrap();
    state.finish_registration(&id, &registration, now).unwrap();
    let (id, options) = state.start_authentication(now).unwrap();
    let authentication = auth.do_authentication(origin(), options).unwrap();
    assert_eq!(
        state.finish_registration(&id, &registration, now),
        Err(Error::NoMatchingCeremony)
    );
    assert_eq!(
        state.finish_authentication(&id, &authentication, now),
        Err(Error::NoMatchingCeremony)
    );
}
