//! Original signed client-data syntax only, not WebAuthn verification.
//! Unlike application JSON, Unicode, extensions and arbitrary JSON value types
//! are allowed. No normalized representation is returned or substituted.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

const MAX_BYTES: usize = 12_288;
const MAX_DEPTH: usize = 16;

/// Bounded error that never includes signed input or parser diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientDataError;

impl fmt::Display for ClientDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("client-data syntax rejected")
    }
}
impl std::error::Error for ClientDataError {}

/// Immutable original bytes that passed this syntax policy, not a schema,
/// challenge/origin check, credential binding, signature or authorization check.
pub struct SyntaxCheckedClientData<'a> {
    original: &'a [u8],
}

impl fmt::Debug for SyntaxCheckedClientData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyntaxCheckedClientData { .. }")
    }
}

impl<'a> SyntaxCheckedClientData<'a> {
    /// Accept one UTF-8 object without BOM, duplicate decoded names, invalid
    /// surrogates, nonfinite numbers or excessive container nesting. Whitespace
    /// and spelling remain unchanged, including numbers and Unicode escapes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ClientDataError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(ClientDataError);
        }
        let input = std::str::from_utf8(bytes).map_err(|_| ClientDataError)?;
        if input.starts_with('\u{feff}') {
            return Err(ClientDataError);
        }
        let mut parser = serde_json::Deserializer::from_str(input);
        parser
            .deserialize_map(Seed(1))
            .map_err(|_| ClientDataError)?;
        parser.end().map_err(|_| ClientDataError)?;
        Ok(Self { original: bytes })
    }

    pub fn original_bytes(&self) -> &'a [u8] {
        self.original
    }
}

// The depth is the next container's depth, with the required root object at 1.
// Scalars do not consume a container level. No parsed value is retained.
struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, parser: D) -> Result<(), D::Error> {
        parser.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded unambiguous JSON")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<(), E> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("nonfinite number"))
        }
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        if self.0 > MAX_DEPTH {
            return Err(de::Error::custom("container depth exceeded"));
        }
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate member"));
            }
            map.next_value_seed(Seed(self.0 + 1))?;
        }
        Ok(())
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<(), S::Error> {
        if self.0 > MAX_DEPTH {
            return Err(de::Error::custom("container depth exceeded"));
        }
        while sequence.next_element_seed(Seed(self.0 + 1))?.is_some() {}
        Ok(())
    }
}
