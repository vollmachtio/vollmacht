//! Test-only structural assessment, not a WebAuthn validator or runtime API.
//! Bounds are 12,288 bytes and 16 containers, counting the root object as one.
//! Unknown JSON values are allowed, but serde_json's finite-number range applies.
//! Validation returns no normalized representation; callers retain original bytes.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

pub const MAX_BYTES: usize = 12_288;
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct Rejected;

struct Seed(usize);

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded unambiguous JSON")
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

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<(), E> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("nonfinite number"))
        }
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        if self.0 >= MAX_DEPTH {
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
        if self.0 >= MAX_DEPTH {
            return Err(de::Error::custom("container depth exceeded"));
        }
        while sequence.next_element_seed(Seed(self.0 + 1))?.is_some() {}
        Ok(())
    }
}

pub fn validate(bytes: &[u8]) -> Result<(), Rejected> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES || bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Rejected);
    }
    // serde_json string decoding alone must not be assumed to validate all input.
    std::str::from_utf8(bytes).map_err(|_| Rejected)?;
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    parser.deserialize_map(Seed(0)).map_err(|_| Rejected)?;
    parser.end().map_err(|_| Rejected)
}
