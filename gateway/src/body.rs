use serde::{
    Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fmt};
pub const MAX_BODY: usize = 8 * 1024 * 1024;
pub fn is_json(content_type: &str) -> bool {
    matches!(
        content_type.split(';').next(),
        Some("application/json" | "application/merge-patch+json" | "application/json-patch+json")
    )
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
    use super::*;
    #[test]
    fn fingerprints_exact_body_bytes_without_validating_the_payload() {
        let first = opaque_metadata(b"x=a+b", "application/x-www-form-urlencoded").unwrap();
        let second = opaque_metadata(b"x=a%20b", "application/x-www-form-urlencoded").unwrap();
        assert_ne!(first["sha256"], second["sha256"]);
        assert!(opaque_metadata(b"x=%GG", "application/x-www-form-urlencoded").is_ok());
        assert!(opaque_metadata(&vec![b'a'; MAX_BODY + 1], "text/plain").is_err());
    }
    #[test]
    fn rejects_ambiguous_json_before_credential_injection() {
        for text in [
            r#"{"x":1,"x":2}"#,
            r#"{"x":1,"\u0078":2}"#,
            r#"{"nested":{"x":1,"x":2}}"#,
            "{}{}",
            "NaN",
            "{",
            "[] garbage",
        ] {
            assert!(
                validate_json_for_injection(text.as_bytes()).is_err(),
                "{text}"
            );
        }
        assert!(validate_json_for_injection(&vec![b' '; MAX_BODY + 1]).is_err());
        assert!(
            validate_json_for_injection(
                format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()
            )
            .is_err()
        );
        assert!(validate_json_for_injection(b"{\"x\":\"\xff\"}").is_err());
    }
    #[test]
    fn binds_exact_bytes_and_content_type() {
        let first = opaque_metadata(b"{\"x\":1}", "application/json").unwrap();
        let second = opaque_metadata(b"{\"x\": 1}", "application/json").unwrap();
        assert_ne!(first["sha256"], second["sha256"]);
        assert_eq!(first["size_bytes"], 7);
        assert_eq!(
            opaque_metadata(b"", "").unwrap()["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(first["content_type"], "application/json");
    }
}
