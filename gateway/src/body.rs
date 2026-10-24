use serde::{
    Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fmt};
pub const MAX_BODY: usize = 8 * 1024 * 1024;
pub fn is_json(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    [
        "application/json",
        "application/merge-patch+json",
        "application/json-patch+json",
    ]
    .iter()
    .any(|supported| media_type.eq_ignore_ascii_case(supported))
}
pub fn opaque_metadata(
    bytes: &[u8],
    content_type: &str,
) -> std::result::Result<Value, &'static str> {
    if bytes.len() > MAX_BODY {
        return Err("request body too large");
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    Ok(
        json!({"content_type":content_type,"size_bytes":bytes.len(),"sha256":digest.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()}),
    )
}

pub fn validate_json_for_injection(bytes: &[u8]) -> std::result::Result<(), &'static str> {
    if bytes.len() > MAX_BODY {
        return Err("request body too large");
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    Json(0)
        .deserialize(&mut parser)
        .map_err(|_| "invalid, duplicate-key, or deeply nested JSON")?;
    parser.end().map_err(|_| "trailing data after JSON")?;
    Ok(())
}
struct Json(usize);
impl<'de> DeserializeSeed<'de> for Json {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.0 > 32 {
            return Err(de::Error::custom("JSON nesting limit"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Json {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, n: f64) -> Result<(), E> {
        if n.is_finite() {
            Ok(())
        } else {
            Err(E::custom("non-finite number"))
        }
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Json(self.0 + 1))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            map.next_value_seed(Json(self.0 + 1))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{is_json, validate_json_for_injection};

    #[test]
    fn json_media_type_ignores_case_and_parameters() {
        assert!(is_json("Application/JSON; charset=utf-8"));
        assert!(is_json(" application/merge-patch+json "));
        assert!(!is_json("text/plain"));
    }

    #[test]
    fn credential_json_rejects_duplicate_keys_and_trailing_data() {
        assert!(validate_json_for_injection(br#"{"token":"a","token":"b"}"#).is_err());
        assert!(validate_json_for_injection(br#"{"token":"a"} true"#).is_err());
        assert!(validate_json_for_injection(br#"{"token":"a"}"#).is_ok());
    }

    #[test]
    fn credential_json_enforces_nesting_limit() {
        let nested = format!("{}0{}", "[".repeat(34), "]".repeat(34));
        assert!(validate_json_for_injection(nested.as_bytes()).is_err());
    }
}
