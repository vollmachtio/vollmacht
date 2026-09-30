use crate::{Error, frame, json};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

// No Debug implementations: accidental logs must not dump credential/evidence data.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestData {
    version: u8,
    kind: String,
    request_id: String,
    challenge: String,
    rp_id: String,
    origin: String,
    credential: Credential,
    assertion: Assertion,
}

/// Validated transport request. Construction is possible only through `parse`.
pub struct Request(RequestData);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    id: String,
    public_key: String,
    counter: u32,
    user_handle: String,
    backup_eligible: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    kind: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: String,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", deny_unknown_fields)]
enum Response {
    #[serde(rename = "verified")]
    Verified {
        version: u8,
        kind: String,
        request_id: String,
        challenge: String,
        new_counter: u32,
        backup_eligible: bool,
        backed_up: bool,
    },
    #[serde(rename = "rejected")]
    Rejected {
        version: u8,
        kind: String,
        request_id: String,
        challenge: String,
        code: String,
    },
}

/// Untrusted helper claim, not final acceptance. Process and registry checks follow.
#[derive(Debug, Eq, PartialEq)]
pub struct HelperResult {
    pub new_counter: u32,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

fn require(condition: bool) -> Result<(), Error> {
    condition.then_some(()).ok_or(Error::Protocol)
}

fn binary(value: &str, min: usize, max: usize) -> Result<(), Error> {
    require(value.len() <= (max * 4).div_ceil(3))?;
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Protocol)?;
    require((min..=max).contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(bytes) == value)
}

impl Request {
    /// Validates transport syntax only, not key trust, freshness or signatures.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let request: RequestData =
            serde_json::from_value(json::parse(bytes)?).map_err(|_| Error::Protocol)?;
        require(request.version == 1 && request.kind == "verify_assertion")?;
        require(
            request.request_id.len() == 32
                && request
                    .request_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        require(request.rp_id == "localhost" && request.origin == "http://localhost:8374")?;
        binary(&request.challenge, 32, 32)?;
        let c = &request.credential;
        binary(&c.id, 1, 1024)?;
        binary(&c.public_key, 1, 4096)?;
        binary(&c.user_handle, 1, 64)?;
        let a = &request.assertion;
        require(a.kind == "public-key")?;
        binary(&a.id, 1, 1024)?;
        binary(&a.raw_id, 1, 1024)?;
        binary(&a.client_data_json, 1, 12288)?;
        binary(&a.authenticator_data, 37, 8192)?;
        binary(&a.signature, 1, 1024)?;
        if !a.user_handle.is_empty() {
            binary(&a.user_handle, 1, 64)?;
        }
        // ID/key matching and actual WebAuthn verification belong to the helper.
        Ok(Self(request))
    }

    pub fn to_frame(&self) -> Result<Vec<u8>, Error> {
        frame(&serde_json::to_vec(&self.0).map_err(|_| Error::Protocol)?)
    }
}

pub fn decode_response(bytes: &[u8], request: &Request) -> Result<HelperResult, Error> {
    let request = &request.0;
    let response: Response =
        serde_json::from_value(json::parse(bytes)?).map_err(|_| Error::Protocol)?;
    let (version, kind, id, challenge) = match &response {
        Response::Verified {
            version,
            kind,
            request_id,
            challenge,
            ..
        }
        | Response::Rejected {
            version,
            kind,
            request_id,
            challenge,
            ..
        } => (*version, kind, request_id, challenge),
    };
    require(
        version == 1
            && kind == "verification_result"
            && id == &request.request_id
            && challenge == &request.challenge,
    )?;
    match response {
        Response::Rejected { code, .. } => {
            require(code == "verification_rejected")?;
            Err(Error::VerificationRejected)
        }
        Response::Verified {
            new_counter,
            backup_eligible,
            backed_up,
            ..
        } => {
            let old = request.credential.counter;
            if backup_eligible != request.credential.backup_eligible
                || (backed_up && !backup_eligible)
                || ((old != 0 || new_counter != 0) && new_counter <= old)
            {
                return Err(Error::VerificationRejected);
            }
            Ok(HelperResult {
                new_counter,
                backup_eligible,
                backed_up,
            })
        }
    }
}

/// Fake helper output. A rejection never represents cryptographic verification.
pub fn rejection_frame(request: &Request) -> Result<Vec<u8>, Error> {
    let request = &request.0;
    let response = serde_json::json!({
        "version": 1, "kind": "verification_result", "request_id": request.request_id,
        "challenge": request.challenge, "outcome": "rejected", "code": "verification_rejected",
    });
    frame(&serde_json::to_vec(&response).map_err(|_| Error::Protocol)?)
}
