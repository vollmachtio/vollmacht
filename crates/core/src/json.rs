use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// Absolute raw-input bound; individual schemas may impose a smaller limit.
pub const MAX_INPUT_BYTES: usize = 65_536;
const MAX_OBJECT_DEPTH: usize = 8;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// A caller-selected byte cap within the fixed safety ceiling.
///
/// Select this from trusted schema configuration, never a submitted request.
/// The cap includes all original bytes, including surrounding JSON whitespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputLimit(usize);

impl InputLimit {
    pub const MAX: Self = Self(MAX_INPUT_BYTES);

    /// Zero and values above the fixed ceiling have no valid representation.
    pub const fn new(bytes: usize) -> Option<Self> {
        if bytes > 0 && bytes <= MAX_INPUT_BYTES {
            Some(Self(bytes))
        } else {
            None
        }
    }
}

/// An immutable object whose original input passed this syntax profile only.
///
/// No public constructor, mutable accessor or deserialization implementation can
/// bypass parsing. Borrowed values are not independently validated schemas and
/// do not retain evidence about the original spelling for canonicality checks.
#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationObject(Map<String, Value>);

impl ApplicationObject {
    pub fn fields(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// Bounded diagnostics intentionally omit input and upstream parser details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    InputSize,
    InvalidSyntax,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InputSize => "application JSON input size rejected",
            Self::InvalidSyntax => "application JSON syntax rejected",
        })
    }
}

impl std::error::Error for ParseError {}

struct Seed(usize);

fn printable_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("restricted application JSON")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        if value > MAX_INTEGER {
            return Err(E::custom("integer outside profile"));
        }
        Ok(Value::from(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if !printable_ascii(value) {
            return Err(E::custom("string outside profile"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        if self.0 > MAX_OBJECT_DEPTH {
            return Err(de::Error::custom("object depth exceeded"));
        }
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !printable_ascii(&key) || object.contains_key(&key) {
                return Err(de::Error::custom("invalid or duplicate member"));
            }
            let value = map.next_value_seed(Seed(self.0 + 1))?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
    // No signed integer, float, boolean, null or sequence visitor. serde_json
    // preserves their lexical classification here, before any Value conversion.
}

/// Parse one object with printable ASCII strings/keys and unsigned integers.
///
/// Unknown names and empty objects/strings are allowed at this syntax layer.
/// Exact schema, canonical bytes, cryptography and authority are separate gates.
pub fn parse_object(bytes: &[u8], limit: InputLimit) -> Result<ApplicationObject, ParseError> {
    if bytes.is_empty() || bytes.len() > limit.0 {
        return Err(ParseError::InputSize);
    }
    let input = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidSyntax)?;
    if input.starts_with('\u{feff}') {
        return Err(ParseError::InvalidSyntax);
    }
    let mut decoder = serde_json::Deserializer::from_str(input);
    let value = Seed(1)
        .deserialize(&mut decoder)
        .map_err(|_| ParseError::InvalidSyntax)?;
    decoder.end().map_err(|_| ParseError::InvalidSyntax)?;
    match value {
        Value::Object(object) => Ok(ApplicationObject(object)),
        _ => Err(ParseError::InvalidSyntax),
    }
}
