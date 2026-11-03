//! Validated public key material, not enrollment or private-key possession.

use crate::{ApplicationObject, InputLimit, parse_object};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::{Hasher, MessageDigest},
    nid::Nid,
};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    InvalidInput,
    NonCanonical,
    Serialization,
    Crypto,
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "enrollment input rejected",
            Self::NonCanonical => "enrollment input is not canonical",
            Self::Serialization => "enrollment serialization failed",
            Self::Crypto => "enrollment cryptographic operation failed",
        })
    }
}

impl std::error::Error for EnrollmentError {}

/// Immutable P-256 public JWK with exactly the four RFC 7638 public members.
/// A valid point and thumbprint do not establish trust or private-key possession.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentPublicKey {
    object: ApplicationObject,
    canonical: Vec<u8>,
}

impl AgentPublicKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let limit = InputLimit::new(512).ok_or(EnrollmentError::InvalidInput)?;
        let object = parse_object(bytes, limit).map_err(|_| EnrollmentError::InvalidInput)?;
        let fields = object.fields();
        exact(fields, &["kty", "crv", "x", "y"])?;
        require(string(fields, "kty")? == "EC" && string(fields, "crv")? == "P-256")?;
        let x = binary(string(fields, "x")?, 32, 32)?;
        let y = binary(string(fields, "y")?, 32, 32)?;
        validate_point(&x, &y)?;
        let canonical = serde_jcs::to_vec(fields).map_err(|_| EnrollmentError::Serialization)?;
        require(canonical.len() <= 512)?;
        Ok(Self { object, canonical })
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let parsed = Self::parse(bytes)?;
        if parsed.canonical != bytes {
            return Err(EnrollmentError::NonCanonical);
        }
        Ok(parsed)
    }

    pub fn fields(&self) -> &Map<String, Value> {
        self.object.fields()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// RFC 7638 SHA-256 over exactly crv/kty/x/y canonical public members.
    /// This has no Vollmacht domain prefix and is not an enrollment credential.
    pub fn thumbprint(&self) -> Result<[u8; 32], EnrollmentError> {
        sha256(&[], self.canonical_bytes())
    }
}

fn validate_point(x_bytes: &[u8], y_bytes: &[u8]) -> Result<(), EnrollmentError> {
    let group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| EnrollmentError::Crypto)?;
    let x = BigNum::from_slice(x_bytes).map_err(|_| EnrollmentError::Crypto)?;
    let y = BigNum::from_slice(y_bytes).map_err(|_| EnrollmentError::Crypto)?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|_| EnrollmentError::InvalidInput)?;
    key.check_key().map_err(|_| EnrollmentError::InvalidInput)?;
    // Reject any coordinate normalization by the backend. Use maintained
    // extraction/padding APIs, not handwritten field arithmetic.
    let mut actual_x = BigNum::new().map_err(|_| EnrollmentError::Crypto)?;
    let mut actual_y = BigNum::new().map_err(|_| EnrollmentError::Crypto)?;
    let mut context = BigNumContext::new().map_err(|_| EnrollmentError::Crypto)?;
    key.public_key()
        .affine_coordinates_gfp(&group, &mut actual_x, &mut actual_y, &mut context)
        .map_err(|_| EnrollmentError::Crypto)?;
    let actual_x = actual_x
        .to_vec_padded(32)
        .map_err(|_| EnrollmentError::Crypto)?;
    let actual_y = actual_y
        .to_vec_padded(32)
        .map_err(|_| EnrollmentError::Crypto)?;
    require(actual_x == x_bytes && actual_y == y_bytes)
}

pub(crate) fn require(condition: bool) -> Result<(), EnrollmentError> {
    if condition {
        Ok(())
    } else {
        Err(EnrollmentError::InvalidInput)
    }
}

pub(crate) fn exact(fields: &Map<String, Value>, names: &[&str]) -> Result<(), EnrollmentError> {
    require(fields.len() == names.len() && names.iter().all(|name| fields.contains_key(*name)))
}

pub(crate) fn string<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, EnrollmentError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or(EnrollmentError::InvalidInput)
}

pub(crate) fn binary(value: &str, min: usize, max: usize) -> Result<Vec<u8>, EnrollmentError> {
    require(value.len() <= (max * 4).div_ceil(3))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EnrollmentError::InvalidInput)?;
    require((min..=max).contains(&decoded.len()) && URL_SAFE_NO_PAD.encode(&decoded) == value)?;
    Ok(decoded)
}

pub(crate) fn sha256(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], EnrollmentError> {
    let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|_| EnrollmentError::Crypto)?;
    hasher.update(domain).map_err(|_| EnrollmentError::Crypto)?;
    hasher.update(bytes).map_err(|_| EnrollmentError::Crypto)?;
    let digest = hasher.finish().map_err(|_| EnrollmentError::Crypto)?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| EnrollmentError::Crypto)
}
