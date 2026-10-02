//! Experimental public-key/signature checks, independent of Apple signing APIs.
//! No mandate parsing, arbitrary-message signing, key persistence, or trust registry.

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Verifier,
};

pub mod durable;

pub const MESSAGE: &[u8] = b"vollmacht:macos-key-probe:v1\0fixed-test-message-not-a-mandate";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    PublicKey,
    SignatureEncoding,
    Verification,
}

/// SEC1 uncompressed P-256 public key and strict DER ECDSA signature.
pub fn verify(public: &[u8], message: &[u8], der: &[u8]) -> Result<(), Error> {
    if public.len() != 65 || public.first() != Some(&4) {
        return Err(Error::PublicKey);
    }
    // Bound parsing and disallow trailing bytes/noncanonical DER by round-tripping.
    let _ = der_to_p1363(der)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| Error::PublicKey)?;
    let mut context = BigNumContext::new().map_err(|_| Error::PublicKey)?;
    let point = EcPoint::from_bytes(&group, public, &mut context).map_err(|_| Error::PublicKey)?;
    let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::PublicKey)?;
    key.check_key().map_err(|_| Error::PublicKey)?;
    let key = PKey::from_ec_key(key).map_err(|_| Error::PublicKey)?;
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), &key).map_err(|_| Error::Verification)?;
    verifier.update(message).map_err(|_| Error::Verification)?;
    match verifier.verify(der) {
        Ok(true) => Ok(()),
        _ => Err(Error::Verification),
    }
}

/// Encoding experiment only: ES256 uses fixed-width r || s, unlike Apple's DER output.
pub fn der_to_p1363(der: &[u8]) -> Result<[u8; 64], Error> {
    if der.len() > 72 {
        return Err(Error::SignatureEncoding);
    }
    let signature = EcdsaSig::from_der(der).map_err(|_| Error::SignatureEncoding)?;
    if signature.to_der().map_err(|_| Error::SignatureEncoding)? != der {
        return Err(Error::SignatureEncoding);
    }
    let mut raw = [0_u8; 64];
    let r = signature.r();
    if r.is_negative() || r.num_bits() == 0 {
        return Err(Error::SignatureEncoding);
    }
    raw[..32].copy_from_slice(&r.to_vec_padded(32).map_err(|_| Error::SignatureEncoding)?);
    let s = signature.s();
    if s.is_negative() || s.num_bits() == 0 {
        return Err(Error::SignatureEncoding);
    }
    raw[32..].copy_from_slice(&s.to_vec_padded(32).map_err(|_| Error::SignatureEncoding)?);
    Ok(raw)
}

pub fn p1363_to_der(raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() != 64 {
        return Err(Error::SignatureEncoding);
    }
    let r = BigNum::from_slice(&raw[..32]).map_err(|_| Error::SignatureEncoding)?;
    let s = BigNum::from_slice(&raw[32..]).map_err(|_| Error::SignatureEncoding)?;
    if r.num_bits() == 0 || s.num_bits() == 0 {
        return Err(Error::SignatureEncoding);
    }
    EcdsaSig::from_private_components(r, s)
        .and_then(|signature| signature.to_der())
        .map_err(|_| Error::SignatureEncoding)
}
