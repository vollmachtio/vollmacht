//! One ephemeral enrollment and at most one pending ceremony per process.
//! The HTTP boundary serializes all operations using a single mutex.

use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

pub const TTL: Duration = Duration::from_secs(120);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    AlreadyRegistered,
    NotRegistered,
    NoMatchingCeremony,
    VerificationFailed,
    Internal,
}

enum PendingKind {
    Register(PasskeyRegistration),
    Authenticate(PasskeyAuthentication),
}

struct Pending {
    id: String,
    deadline: Instant,
    kind: PendingKind,
}

pub struct Ceremonies {
    verifier: Webauthn,
    credential: Option<Passkey>,
    pending: Option<Pending>,
}

/// OS randomness, encoded for transport only. No cryptographic primitive is implemented here.
pub fn random_token() -> Result<String, Error> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Internal)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl Ceremonies {
    pub fn new() -> Result<Self, WebauthnError> {
        let origin = Url::parse(crate::ORIGIN).expect("constant origin");
        let verifier = WebauthnBuilder::new("localhost", &origin)?
            .allow_any_port(false)
            .allow_subdomains(false)
            .build()?;
        Ok(Self {
            verifier,
            credential: None,
            pending: None,
        })
    }

    fn expire(&mut self, now: Instant) {
        if self.pending.as_ref().is_some_and(|p| now >= p.deadline) {
            self.pending = None;
        }
    }

    fn ready(&mut self, now: Instant) -> Result<(), Error> {
        self.expire(now);
        if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }

    pub fn start_registration(
        &mut self,
        now: Instant,
    ) -> Result<(String, CreationChallengeResponse), Error> {
        self.ready(now)?;
        if self.credential.is_some() {
            return Err(Error::AlreadyRegistered);
        }
        let mut user_id = [0_u8; 16];
        getrandom::fill(&mut user_id).map_err(|_| Error::Internal)?;
        let (mut options, state) = self
            .verifier
            .start_passkey_registration(
                Uuid::from_bytes(user_id),
                "vollmacht-local-spike",
                "Vollmacht local spike (remove after testing)",
                None,
            )
            .map_err(|_| Error::Internal)?;
        // This requests a platform authenticator. It does not prove hardware provenance.
        if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
            selection.authenticator_attachment =
                Some(webauthn_rs_proto::AuthenticatorAttachment::Platform);
        }
        let id = random_token()?;
        self.pending = Some(Pending {
            id: id.clone(),
            deadline: now + TTL,
            kind: PendingKind::Register(state),
        });
        Ok((id, options))
    }

    pub fn start_authentication(
        &mut self,
        now: Instant,
    ) -> Result<(String, RequestChallengeResponse), Error> {
        self.ready(now)?;
        let credential = self.credential.as_ref().ok_or(Error::NotRegistered)?;
        let (options, state) = self
            .verifier
            .start_passkey_authentication(std::slice::from_ref(credential))
            .map_err(|_| Error::Internal)?;
        let id = random_token()?;
        self.pending = Some(Pending {
            id: id.clone(),
            deadline: now + TTL,
            kind: PendingKind::Authenticate(state),
        });
        Ok((id, options))
    }

    /// Matching submissions are consumed BEFORE verification, including wrong-kind submissions.
    /// Unknown/stale IDs cannot cancel a different pending ceremony.
    fn take(&mut self, id: &str, now: Instant) -> Result<PendingKind, Error> {
        self.expire(now);
        if !self.pending.as_ref().is_some_and(|p| p.id == id) {
            return Err(Error::NoMatchingCeremony);
        }
        Ok(self.pending.take().expect("matching pending ceremony").kind)
    }

    pub fn cancel(&mut self, id: &str, now: Instant) -> Result<(), Error> {
        self.take(id, now).map(|_| ())
    }

    pub fn finish_registration(
        &mut self,
        id: &str,
        response: &RegisterPublicKeyCredential,
        now: Instant,
    ) -> Result<(), Error> {
        let PendingKind::Register(state) = self.take(id, now)? else {
            return Err(Error::NoMatchingCeremony);
        };
        let credential = self
            .verifier
            .finish_passkey_registration(response, &state)
            .map_err(|_| Error::VerificationFailed)?;
        self.credential = Some(credential);
        Ok(())
    }

    pub fn finish_authentication(
        &mut self,
        id: &str,
        response: &PublicKeyCredential,
        now: Instant,
    ) -> Result<(), Error> {
        let PendingKind::Authenticate(state) = self.take(id, now)? else {
            return Err(Error::NoMatchingCeremony);
        };
        let result = self
            .verifier
            .finish_passkey_authentication(response, &state)
            .map_err(|_| Error::VerificationFailed)?;
        if !result.user_verified() {
            return Err(Error::VerificationFailed);
        }
        self.credential
            .as_mut()
            .ok_or(Error::Internal)?
            .update_credential(&result)
            .ok_or(Error::Internal)?;
        Ok(())
    }
}
