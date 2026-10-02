//! Portable lifecycle contract only. There is deliberately no Apple backend or signer.
//! A backend is trusted code, not evidence of Secure Enclave or entitlement enforcement.

use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
};

const PREFIX: &str = "io.vollmacht.experimental.issuer.v1.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(String);

impl KeyId {
    /// Trusted configuration supplies 128 bits encoded as 32 lowercase hex digits.
    /// This validates syntax, not randomness, ownership, or authority.
    pub fn new(suffix: &str) -> Result<Self, Error> {
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidId);
        }
        Ok(Self(format!("{PREFIX}{suffix}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact SEC1 uncompressed P-256 public key, not an Apple application-label hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 65]);

impl PublicKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 65] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        if bytes[0] != 4 {
            return Err(Error::InvalidPublicKey);
        }
        let group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| Error::InvalidPublicKey)?;
        let mut context = BigNumContext::new().map_err(|_| Error::InvalidPublicKey)?;
        let point = EcPoint::from_bytes(&group, &bytes, &mut context)
            .map_err(|_| Error::InvalidPublicKey)?;
        let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::InvalidPublicKey)?;
        key.check_key().map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    Denied,
    Locked,
    Cancelled,
    Unsupported,
    Unavailable,
    Duplicate,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidId,
    InvalidPublicKey,
    Missing,
    Ambiguous,
    PublicKeyMismatch,
    Backend(BackendError),
}

/// Explicit cardinality prevents accidentally accepting the first search result.
pub enum Lookup<H> {
    Missing,
    One(H),
    Ambiguous,
}

/// Native implementations must use an exact private-key identifier within a trusted
/// access group, Data Protection Keychain, and the fixed hardware/protection profile.
/// Search must distinguish zero, one, and multiple matches, never a default limit of one.
/// No broad label lookup, software fallback, implicit replacement, or deletion is allowed.
pub trait Backend {
    type Handle;

    /// Atomically create a new identity or report Duplicate. A prior lookup is not
    /// sufficient to prevent concurrent creation. Failures may leave an orphan;
    /// callers must never silently retry creation or delete anything on failure.
    fn create_new(&mut self, id: &KeyId) -> Result<Self::Handle, BackendError>;
    fn lookup(&mut self, id: &KeyId) -> Result<Lookup<Self::Handle>, BackendError>;
    /// Export the public key of this exact handle, not a fresh identifier lookup.
    fn public_key(&mut self, handle: &Self::Handle) -> Result<Vec<u8>, BackendError>;
}

/// Trusted enrollment metadata must be stored with integrity outside agent control.
/// This in-memory value is not a durable registry or a signed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    id: KeyId,
    public_key: PublicKey,
}

impl Enrollment {
    /// Restore metadata from a trusted registry, never from a request to authorize.
    pub fn restore(id: KeyId, public_key: PublicKey) -> Self {
        Self { id, public_key }
    }
    pub fn id(&self) -> &KeyId {
        &self.id
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Validated handle and metadata travel together; no signing API exists in this slice.
pub struct Opened<H> {
    handle: H,
    enrollment: Enrollment,
}

impl<H> Opened<H> {
    pub fn enrollment(&self) -> &Enrollment {
        &self.enrollment
    }
    pub fn handle(&self) -> &H {
        &self.handle
    }
}

pub fn create<B: Backend>(backend: &mut B, id: KeyId) -> Result<Opened<B::Handle>, Error> {
    let handle = backend.create_new(&id).map_err(Error::Backend)?;
    let bytes = backend.public_key(&handle).map_err(Error::Backend)?;
    let public_key = PublicKey::parse(&bytes)?;
    Ok(Opened {
        handle,
        enrollment: Enrollment { id, public_key },
    })
}

/// Opening never creates. Missing, inaccessible, or changed identities stay failures.
pub fn open<B: Backend>(
    backend: &mut B,
    expected: &Enrollment,
) -> Result<Opened<B::Handle>, Error> {
    let handle = match backend.lookup(&expected.id).map_err(Error::Backend)? {
        Lookup::Missing => return Err(Error::Missing),
        Lookup::Ambiguous => return Err(Error::Ambiguous),
        Lookup::One(handle) => handle,
    };
    let bytes = backend.public_key(&handle).map_err(Error::Backend)?;
    let public_key = PublicKey::parse(&bytes)?;
    if public_key != expected.public_key {
        return Err(Error::PublicKeyMismatch);
    }
    Ok(Opened {
        handle,
        enrollment: expected.clone(),
    })
}
