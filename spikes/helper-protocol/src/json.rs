//! Validate before serde's Value can discard duplicates or normalize numbers.
use crate::{Error, MAX_BODY};
use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Seed(usize);

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded protocol JSON")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if !value.is_ascii() {
            return Err(E::custom("non-ASCII string"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        if self.0 >= 8 {
            return Err(de::Error::custom("depth exceeded"));
        }
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !key.is_ascii() || object.contains_key(&key) {
                return Err(de::Error::custom("invalid or duplicate key"));
            }
            object.insert(key, map.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(object))
    }
    // Deliberately no signed integers, floats, nulls or arrays in this profile.
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    if !(1..=MAX_BODY).contains(&bytes.len()) {
        return Err(Error::Protocol);
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(0).deserialize(&mut de).map_err(|_| Error::Protocol)?;
    de.end().map_err(|_| Error::Protocol)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_before_normalization() {
        for input in [
            "{\"x\":1,\"x\":2}",
            "{\"x\":1,\"\\u0078\":2}",
            "{\"a\":{\"x\":1,\"x\":2}}",
            "-0",
            "-1",
            "1.0",
            "1e0",
            "01",
            "null",
            "[]",
            "\"é\"",
            "\"\\ud800\"",
            "{}{}",
            "\u{feff}{}",
        ] {
            assert_eq!(parse(input.as_bytes()), Err(Error::Protocol), "{input}");
        }
        assert_eq!(parse(&[0xff]), Err(Error::Protocol));
        assert!(parse(b" {\"x\":0,\"y\":true} \n").is_ok());
    }

    #[test]
    fn depth_boundary_and_duplicate_keys_at_each_depth() {
        for depth in 1..=9 {
            let body = format!("{}0{}", "{\"a\":".repeat(depth), "}".repeat(depth));
            assert_eq!(parse(body.as_bytes()).is_ok(), depth <= 8);
            let duplicate = format!(
                "{}{{\"x\":1,\"x\":2}}{}",
                "{\"a\":".repeat(depth - 1),
                "}".repeat(depth - 1)
            );
            assert_eq!(parse(duplicate.as_bytes()), Err(Error::Protocol));
        }
    }
}
