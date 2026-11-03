//! Signature checking only. Trusted registry lookup and authorization remain caller duties.
use crate::{AgentPublicKey, CompactRole, UnverifiedCompact};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    crypto::{CryptoProvider, JwtVerifier, KeyUtils},
    errors::ErrorKind,
    signature,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    sign::Verifier,
};
use std::{cmp::Ordering, fmt};

/// Redacted failures; no input, keys, or backend diagnostics are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    Initialization,
    InvalidBinding,
    InvalidArtifact,
    Signature,
}
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}
impl std::error::Error for VerificationError {}

/// Explicit caller-supplied binding, not evidence of a trusted registry lookup.
/// The caller must obtain the role, key label and key from trusted state, never
/// from the artifact. Issuer labels are independent of issuer IDs/thumbprints.
pub struct VerificationBinding {
    role: CompactRole,
    kid: String,
    der: Vec<u8>,
}
impl VerificationBinding {
    pub fn new(
        role: CompactRole,
        expected_kid: &str,
        key: &AgentPublicKey,
    ) -> Result<Self, VerificationError> {
        let fail = || VerificationError::InvalidBinding;
        match role {
            CompactRole::Issuer => {
                if expected_kid.len() != 32
                    || !expected_kid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(fail());
                }
            }
            CompactRole::Execution | CompactRole::EnrollmentPossession => {
                if expected_kid.len() != 43
                    || B64.encode(key.thumbprint().map_err(|_| fail())?) != expected_kid
                {
                    return Err(fail());
                }
            }
        }
        let coordinate = |name| -> Result<BigNum, VerificationError> {
            let s = key
                .fields()
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(fail)?;
            BigNum::from_slice(&B64.decode(s).map_err(|_| fail())?).map_err(|_| fail())
        };
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| fail())?;
        let x = coordinate("x")?;
        let y = coordinate("y")?;
        let public =
            EcKey::from_public_key_affine_coordinates(&group, &x, &y).map_err(|_| fail())?;
        public.check_key().map_err(|_| fail())?;
        let der = PKey::from_ec_key(public)
            .and_then(|k| k.public_key_to_der())
            .map_err(|_| fail())?;
        Ok(Self {
            role,
            kid: expected_kid.to_owned(),
            der,
        })
    }
}

/// Capability obtained only after explicit process-global startup succeeds.
/// Initialize before starting listeners/workers. This API cannot inspect or
/// enforce OS thread ordering. Share this handle; do not initialize per request.
pub struct VerificationRuntime {
    _private: (),
}
impl VerificationRuntime {
    /// Rejects any preinstalled provider, including a previous successful call.
    /// Failure after installation is permanent: stop startup, never retry/fallback.
    pub fn initialize() -> Result<Self, VerificationError> {
        Self::initialize_checked(|| self_check().map_err(|_| VerificationError::Initialization))
    }

    // Kept private so callers cannot substitute a startup check. The unit test
    // injects a backend-check failure to exercise permanent initialization loss.
    fn initialize_checked(
        check: fn() -> Result<(), VerificationError>,
    ) -> Result<Self, VerificationError> {
        PROVIDER
            .install_default()
            .map_err(|_| VerificationError::Initialization)?;
        check()?;
        Ok(Self { _private: () })
    }
    pub fn verify(
        &self,
        bytes: &[u8],
        binding: &VerificationBinding,
    ) -> Result<SignatureCheckedCompact, VerificationError> {
        let artifact = UnverifiedCompact::parse(bytes, binding.role, &binding.kid)
            .map_err(|_| VerificationError::InvalidArtifact)?;
        let token = std::str::from_utf8(artifact.compact_bytes())
            .map_err(|_| VerificationError::InvalidArtifact)?;
        let mut validation = Validation::new(Algorithm::ES256);
        // These are not JWT claims. Profile-specific time/state checks belong to
        // later authorization stages; signature validation remains enabled.
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        jsonwebtoken::decode::<serde_json::Value>(
            token,
            &DecodingKey::from_ec_der(&binding.der),
            &validation,
        )
        .map_err(|_| VerificationError::Signature)?;
        Ok(SignatureCheckedCompact { artifact })
    }
}

/// The outer signature passed. This is NOT authorization, freshness, revocation,
/// replay protection, WebAuthn validation, or enrollment/dispatch permission.
pub struct SignatureCheckedCompact {
    artifact: UnverifiedCompact,
}
impl fmt::Debug for SignatureCheckedCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignatureCheckedCompact { .. }")
    }
}
impl SignatureCheckedCompact {
    pub fn artifact(&self) -> &UnverifiedCompact {
        &self.artifact
    }
}

struct PublicVerifier(PKey<Public>);
impl signature::Verifier<Vec<u8>> for PublicVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        if signature.len() != 64 {
            return Err(signature::Error::new());
        }
        let check = || -> Result<bool, openssl::error::ErrorStack> {
            let r = BigNum::from_slice(&signature[..32])?;
            let s = BigNum::from_slice(&signature[32..])?;
            let mut order = BigNum::new()?;
            let mut context = BigNumContext::new()?;
            self.0.ec_key()?.group().order(&mut order, &mut context)?;
            if r.num_bits() == 0
                || s.num_bits() == 0
                || r.ucmp(&order) != Ordering::Less
                || s.ucmp(&order) != Ordering::Less
            {
                return Ok(false);
            }
            let der = EcdsaSig::from_private_components(r, s)?.to_der()?;
            let mut verifier = Verifier::new(MessageDigest::sha256(), &self.0)?;
            verifier.update(message)?;
            verifier.verify(&der)
        };
        match check() {
            Ok(true) => Ok(()),
            _ => Err(signature::Error::new()),
        }
    }
}
impl JwtVerifier for PublicVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}
fn select(
    algorithm: &Algorithm,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Box<dyn JwtVerifier>> {
    if *algorithm != Algorithm::ES256 {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    let public = PKey::public_key_from_der(key.try_get_as_bytes()?)
        .map_err(|_| ErrorKind::InvalidKeyFormat)?;
    let ec = public.ec_key().map_err(|_| ErrorKind::InvalidKeyFormat)?;
    if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    ec.check_key().map_err(|_| ErrorKind::InvalidKeyFormat)?;
    Ok(Box::new(PublicVerifier(public)))
}
static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    verifier_factory: select,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        rsa_pub_components_from_public_key: |_| Err(ErrorKind::InvalidAlgorithm.into()),
        ec_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        ed_pub_components_from_private_key: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
        compute_digest: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    },
};

fn self_check() -> Result<(), Box<dyn std::error::Error>> {
    // Public known-answer vector: RFC 6979 Appendix A.2.5, P-256/SHA-256,
    // message "sample". No private key or runtime fixture access.
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let x =
        BigNum::from_hex_str("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")?;
    let y =
        BigNum::from_hex_str("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")?;
    let key = PKey::from_ec_key(EcKey::from_public_key_affine_coordinates(&group, &x, &y)?)?;
    let r =
        BigNum::from_hex_str("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")?;
    let s =
        BigNum::from_hex_str("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")?;
    let raw = [r.to_vec_padded(32)?, s.to_vec_padded(32)?].concat();
    let verifier = (PROVIDER.verifier_factory)(
        &Algorithm::ES256,
        &DecodingKey::from_ec_der(&key.public_key_to_der()?),
    )?;
    verifier.verify(b"sample", &raw)?;
    if verifier.verify(b"sample!", &raw).is_ok() {
        return Err("negative self-check failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_startup_check_cannot_be_retried_or_return_a_capability() {
        assert!(matches!(
            VerificationRuntime::initialize_checked(|| Err(VerificationError::Initialization)),
            Err(VerificationError::Initialization)
        ));
        assert!(matches!(
            VerificationRuntime::initialize(),
            Err(VerificationError::Initialization)
        ));
    }

    #[test]
    fn unsupported_callbacks_fail_without_panicking() {
        use jsonwebtoken::{
            EncodingKey,
            jwk::{EllipticCurve, ThumbprintHash},
        };
        assert!(
            (PROVIDER.signer_factory)(&Algorithm::ES256, &EncodingKey::from_secret(b"unused"))
                .is_err()
        );
        assert!(
            (PROVIDER.verifier_factory)(&Algorithm::HS256, &DecodingKey::from_secret(b"unused"))
                .is_err()
        );
        assert!(
            (PROVIDER.verifier_factory)(&Algorithm::ES256, &DecodingKey::from_ec_der(b"invalid"))
                .is_err()
        );
        let k = &PROVIDER.key_utils;
        assert!((k.rsa_pub_components_from_private_key)(b"").is_err());
        assert!((k.rsa_pub_components_from_public_key)(b"").is_err());
        assert!((k.ec_pub_components_from_private_key)(b"", Algorithm::ES256).is_err());
        assert!((k.ed_pub_components_from_private_key)(b"", &EllipticCurve::Ed25519).is_err());
        assert!((k.compute_digest)(b"", ThumbprintHash::SHA256).is_err());
    }
}
