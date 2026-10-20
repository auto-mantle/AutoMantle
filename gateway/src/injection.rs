use crate::{credentials::Credentials, sandbox::Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub placeholder: String,
    pub location: String,
    pub selector: String,
}

pub struct Input<'a> {
    pub headers: &'a [(String, String)],
    pub target: &'a str,
    pub body: &'a [u8],
    pub content_type: &'a str,
}

pub struct Output {
    pub headers: Vec<(String, String)>,
    pub target: String,
    pub body: Vec<u8>,
}

pub fn names(value: &str, credentials: &Credentials) -> Vec<String> {
    let mut seen = BTreeSet::new();
    value
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|name| credentials.has_name(name) && seen.insert(*name))
        .map(str::to_owned)
        .collect()
}

fn replace_name(value: &str, name: &str, secret: &str, limit: usize) -> Result<String> {
    let identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut result = String::new();
    let mut cursor = 0;
    for (start, _) in value.match_indices(name) {
        let end = start + name.len();
        if (start > 0 && identifier(value.as_bytes()[start - 1]))
            || (end < value.len() && identifier(value.as_bytes()[end]))
        {
            continue;
        }
        if result
            .len()
            .saturating_add(start - cursor)
            .saturating_add(secret.len())
            > limit
        {
            return Err("credential replacement exceeds forwarding limit".into());
        }
        result.push_str(&value[cursor..start]);
        result.push_str(secret);
        cursor = end;
    }
    if result.len().saturating_add(value.len() - cursor) > limit {
        return Err("credential replacement exceeds forwarding limit".into());
    }
    result.push_str(&value[cursor..]);
    Ok(result)
}

fn add(
    plan: &mut Vec<Placement>,
    credentials: &Credentials,
    value: &str,
    location: &str,
    selector: &str,
) {
    for placeholder in names(value, credentials) {
        plan.push(Placement {
            placeholder,
            location: location.into(),
            selector: selector.into(),
        });
    }
}

fn json_plan(value: &Value, pointer: &str, credentials: &Credentials, plan: &mut Vec<Placement>) {
    match value {
        Value::String(text) => add(plan, credentials, text, "json", pointer),
        Value::Object(fields) => {
            for (key, value) in fields {
                json_plan(
                    value,
                    &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                    credentials,
                    plan,
                );
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                json_plan(value, &format!("{pointer}/{index}"), credentials, plan);
            }
        }
        _ => {}
    }
}

fn decode(value: &str) -> Result<String> {
    let mut bytes = value.bytes();
    let mut decoded = Vec::new();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or("invalid query encoding")?;
                let low = bytes
                    .next()
                    .and_then(|b| (b as char).to_digit(16))
                    .ok_or("invalid query encoding")?;
                (high * 16 + low) as u8
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded).map_err(|_| "invalid query encoding".into())
}

fn encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

pub fn plan(input: &Input<'_>, credentials: &Credentials) -> Result<Vec<Placement>> {
    if !credentials.has_host_credentials() {
        return Ok(Vec::new());
    }
    let mut plan = Vec::new();
    for (name, value) in input.headers {
        add(&mut plan, credentials, value, "header", name);
    }
    if let Some((_, query)) = input.target.split_once('?') {
        let mut parameters = Vec::new();
        for part in query.split('&') {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            let key = decode(key)?;
            add(&mut plan, credentials, &decode(value)?, "query", &key);
            parameters.push(key);
        }
        for placement in plan.iter().filter(|p| p.location == "query") {
            if parameters
                .iter()
                .filter(|key| **key == placement.selector)
                .count()
                != 1
            {
                return Err("duplicate credential query parameter".into());
            }
        }
    }
    if !input.body.is_empty()
        && crate::body::is_json(input.content_type)
        && !input
            .headers
            .iter()
            .any(|(name, _)| name == "content-encoding")
    {
        crate::body::validate_json_for_injection(input.body)?;
        let value: Value =
            serde_json::from_slice(input.body).map_err(|_| "invalid credential JSON")?;
        json_plan(&value, "", credentials, &mut plan);
    }
    if plan.len() > 32 {
        return Err("too many credential placements".into());
    }
    let mut locations = BTreeSet::new();
    for placement in &plan {
        if !valid(placement) || !locations.insert((&placement.location, &placement.selector)) {
            return Err("invalid or ambiguous credential placement".into());
        }
        if placement.location == "header"
            && input
                .headers
                .iter()
                .filter(|(name, _)| name == &placement.selector)
                .count()
                != 1
        {
            return Err("duplicate credential header".into());
        }
    }
    Ok(plan)
}

pub(crate) fn valid(placement: &Placement) -> bool {
    let key = &placement.selector;
    match placement.location.as_str() {
        "header" => {
            !key.is_empty()
                && key.len() <= 128
                && key
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && ![
                    "host",
                    "content-length",
                    "content-type",
                    "content-encoding",
                    "transfer-encoding",
                    "connection",
                    "proxy-connection",
                    "proxy-authorization",
                    "upgrade",
                    "expect",
                    "te",
                    "trailer",
                    "accept-encoding",
                ]
                .contains(&key.as_str())
        }
        "json" => {
            key.starts_with('/')
                && key.len() <= 1024
                && !key.chars().any(char::is_control)
                && key
                    .split('~')
                    .skip(1)
                    .all(|part| part.starts_with('0') || part.starts_with('1'))
        }
        "query" => {
            !key.is_empty()
                && key.len() <= 128
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        }
        _ => false,
    }
}

pub fn materialize(
    input: &Input<'_>,
    credentials: &Credentials,
    expected: &[Placement],
) -> Result<Output> {
    if plan(input, credentials)? != expected || !credentials.is_current() {
        return Err("credential request changed".into());
    }
    let mut output = Output {
        headers: input.headers.to_vec(),
        target: input.target.into(),
        body: input.body.to_vec(),
    };
    for placement in expected.iter().filter(|p| p.location == "header") {
        let value = output
            .headers
            .iter_mut()
            .find(|(key, _)| key == &placement.selector)
            .ok_or("credential header missing")?;
        let secret = credentials
            .secret(&placement.placeholder)
            .ok_or("credential unavailable")?;
        value.1 = replace_name(&value.1, &placement.placeholder, secret, 32 * 1024)?;
    }
    if expected.iter().any(|p| p.location == "query") {
        let (path, query) = input
            .target
            .split_once('?')
            .ok_or("credential query missing")?;
        let mut parts = Vec::new();
        for part in query.split('&') {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            let decoded = decode(key)?;
            if let Some(placement) = expected
                .iter()
                .find(|p| p.location == "query" && p.selector == decoded)
            {
                let secret = credentials
                    .secret(&placement.placeholder)
                    .ok_or("credential unavailable")?;
                parts.push(format!(
                    "{key}={}",
                    encode(&replace_name(
                        &decode(value)?,
                        &placement.placeholder,
                        secret,
                        32 * 1024
                    )?)
                ));
            } else {
                parts.push(part.into());
            }
        }
        output.target = format!("{path}?{}", parts.join("&"));
    }
    if expected.iter().any(|p| p.location == "json") {
        let mut value: Value =
            serde_json::from_slice(input.body).map_err(|_| "invalid credential JSON")?;
        let mut size = serde_json::to_vec(&value)
            .map_err(|_| "credential JSON unavailable")?
            .len();
        for placement in expected.iter().filter(|p| p.location == "json") {
            let field = value
                .pointer_mut(&placement.selector)
                .ok_or("credential JSON field missing")?;
            let previous = serde_json::to_vec(&*field)
                .map_err(|_| "credential JSON unavailable")?
                .len();
            let original = field.as_str().ok_or("credential JSON field changed")?;
            let secret = credentials
                .secret(&placement.placeholder)
                .ok_or("credential unavailable")?;
            let limit = crate::body::MAX_BODY.saturating_sub(size - previous);
            *field = Value::String(replace_name(
                original,
                &placement.placeholder,
                secret,
                limit,
            )?);
            size = size - previous
                + serde_json::to_vec(&*field)
                    .map_err(|_| "credential JSON unavailable")?
                    .len();
            if size > crate::body::MAX_BODY {
                return Err("credential JSON exceeds forwarding limit".into());
            }
        }
        output.body = serde_json::to_vec(&value).map_err(|_| "credential JSON unavailable")?;
    }
    let header_bytes: usize = output
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + 4)
        .sum();
    if output.body.len() > crate::body::MAX_BODY || output.target.len() + header_bytes > 32 * 1024 {
        return Err("credential request exceeds forwarding limits".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credentials() -> Credentials {
        Credentials::parse(r#"{"credentials":[{"placeholder":"SERVICE_TOKEN","secret":"synthetic-secret-12345&\"\\+="}]}"#).unwrap()
    }
    #[test]
    fn replaces_variable_names_and_keeps_the_original_request_unchanged() {
        let credentials = credentials();
        let headers = vec![("authorization".into(), "Bearer SERVICE_TOKEN".into())];
        let bytes = br#"{"auth":{"token":"SERVICE_TOKEN"},"note":"prefix_SERVICE_TOKEN_suffix","number":123456789012345678901234567890.123456789}"#;
        let input = Input {
            headers: &headers,
            target: "/login?api_key=SERVICE_TOKEN&note=prefix_SERVICE_TOKEN",
            body: bytes,
            content_type: "application/json",
        };
        let plan = plan(&input, &credentials).unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].selector, "authorization");
        assert_eq!(plan[1].selector, "api_key");
        assert_eq!(plan[2].selector, "/auth/token");
        let review = serde_json::to_string(&plan).unwrap();
        assert!(!review.contains("synthetic-secret"));
        let output = materialize(&input, &credentials, &plan).unwrap();
        let secret = credentials.secret("SERVICE_TOKEN").unwrap();
        assert_eq!(output.headers[0].1, format!("Bearer {secret}"));
        assert!(
            output
                .target
                .contains("synthetic-secret-12345%26%22%5C%2B%3D")
        );
        assert!(output.target.ends_with("note=prefix_SERVICE_TOKEN"));
        let json: Value = serde_json::from_slice(&output.body).unwrap();
        assert_eq!(json["auth"]["token"], secret);
        assert_eq!(json["note"], "prefix_SERVICE_TOKEN_suffix");
        assert_eq!(
            json["number"].to_string(),
            "123456789012345678901234567890.123456789"
        );
        assert_eq!(input.body, bytes);
        assert_eq!(input.headers[0].1, "Bearer SERVICE_TOKEN");
        assert!(!String::from_utf8_lossy(input.body).contains(secret));
    }
    #[test]
    fn cannot_materialize_a_partial_or_changed_plan() {
        let credentials = credentials();
        let headers = vec![("x-api-key".into(), "SERVICE_TOKEN".into())];
        let input = Input {
            headers: &headers,
            target: "/?token=SERVICE_TOKEN",
            body: b"",
            content_type: "",
        };
        let mut expected = plan(&input, &credentials).unwrap();
        assert!(materialize(&input, &credentials, &expected[..1]).is_err());
        expected[0].selector = "other-header".into();
        assert!(materialize(&input, &credentials, &expected).is_err());
    }
    #[test]
    fn ambiguous_or_unsafe_locations_are_rejected() {
        let credentials = credentials();
        for headers in [
            vec![
                ("x-token".into(), "SERVICE_TOKEN".into()),
                ("x-token".into(), "ordinary".into()),
            ],
            vec![("host".into(), "SERVICE_TOKEN".into())],
            vec![("content-length".into(), "SERVICE_TOKEN".into())],
        ] {
            assert!(
                plan(
                    &Input {
                        headers: &headers,
                        target: "/",
                        body: b"",
                        content_type: ""
                    },
                    &credentials
                )
                .is_err()
            );
        }
        for target in [
            "/?key=SERVICE_TOKEN&key=other",
            "/?key=SERVICE_TOKEN&%6Bey=SERVICE_TOKEN",
        ] {
            assert!(
                plan(
                    &Input {
                        headers: &[],
                        target,
                        body: b"",
                        content_type: ""
                    },
                    &credentials
                )
                .is_err()
            );
        }
        let duplicate = br#"{"token":"SERVICE_TOKEN","token":"other"}"#;
        assert!(
            plan(
                &Input {
                    headers: &[],
                    target: "/",
                    body: duplicate,
                    content_type: "application/json"
                },
                &credentials
            )
            .is_err()
        );
    }
    #[test]
    fn json_pointers_handle_nested_arrays_and_escaped_field_names() {
        let credentials = credentials();
        let input = Input {
            headers: &[],
            target: "/",
            body: br#"{"a/b~c":[{"token":"SERVICE_TOKEN"}]}"#,
            content_type: "application/json",
        };
        let expected = plan(&input, &credentials).unwrap();
        assert_eq!(expected[0].selector, "/a~1b~0c/0/token");
        let output = materialize(&input, &credentials, &expected).unwrap();
        let value: Value = serde_json::from_slice(&output.body).unwrap();
        assert_eq!(
            value["a/b~c"][0]["token"],
            credentials.secret("SERVICE_TOKEN").unwrap()
        );
    }
    #[test]
    fn opaque_and_compressed_payloads_are_never_interpolated() {
        let credentials = credentials();
        let headers = vec![("content-encoding".into(), "gzip".into())];
        for (headers, content_type) in [
            (headers.as_slice(), "application/json"),
            (&[][..], "text/plain"),
        ] {
            let input = Input {
                headers,
                target: "/",
                body: b"SERVICE_TOKEN",
                content_type,
            };
            assert!(plan(&input, &credentials).unwrap().is_empty());
            assert_eq!(
                materialize(&input, &credentials, &[]).unwrap().body,
                b"SERVICE_TOKEN"
            );
        }
    }
    #[test]
    fn requests_without_host_secrets_keep_existing_opaque_payload_behavior() {
        let input = Input {
            headers: &[],
            target: "/?opaque=%FF",
            body: b"{broken",
            content_type: "application/json",
        };
        let credentials = Credentials::default();
        assert!(plan(&input, &credentials).unwrap().is_empty());
        assert_eq!(
            materialize(&input, &credentials, &[]).unwrap().body,
            input.body
        );
    }
    #[test]
    fn preserves_surrounding_text_without_knowing_the_authentication_scheme() {
        let credentials = credentials();
        let secret = credentials.secret("SERVICE_TOKEN").unwrap();
        for header in [
            "SERVICE_TOKEN",
            "Bearer SERVICE_TOKEN",
            "Token SERVICE_TOKEN",
            "Custom key=SERVICE_TOKEN; again=SERVICE_TOKEN",
        ] {
            let headers = vec![("authorization".into(), header.into())];
            assert!(credentials.validate_guest_headers(
                &headers,
                "profile",
                "api.example.com",
                "POST",
                "/",
                true
            ));
            let input = Input {
                headers: &headers,
                target: "/",
                body: b"",
                content_type: "",
            };
            let expected = plan(&input, &credentials).unwrap();
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].selector, "authorization");
            let output = materialize(&input, &credentials, &expected).unwrap();
            assert_eq!(output.headers[0].1, header.replace("SERVICE_TOKEN", secret));
            assert_eq!(input.headers[0].1, header);
        }
        let input = Input {
            headers: &[],
            target: "/?key=prefix%3ASERVICE_TOKEN%3Asuffix",
            body: br#"{"auth":{"token":"prefix:SERVICE_TOKEN:suffix"}}"#,
            content_type: "application/json",
        };
        let expected = plan(&input, &credentials).unwrap();
        let output = materialize(&input, &credentials, &expected).unwrap();
        assert!(output.target.starts_with("/?key=prefix%3A"));
        assert!(output.target.ends_with("%3Asuffix"));
        let value: Value = serde_json::from_slice(&output.body).unwrap();
        assert_eq!(value["auth"]["token"], format!("prefix:{secret}:suffix"));
    }
    #[test]
    fn does_not_replace_partial_names_or_interpret_inserted_secret_text() {
        assert_eq!(
            replace_name(
                "SERVICE_TOKEN2 X_SERVICE_TOKEN SERVICE_TOKEN_extra",
                "SERVICE_TOKEN",
                "secret",
                1024
            )
            .unwrap(),
            "SERVICE_TOKEN2 X_SERVICE_TOKEN SERVICE_TOKEN_extra"
        );
        assert_eq!(
            replace_name(
                "Token SERVICE_TOKEN SERVICE_TOKEN",
                "SERVICE_TOKEN",
                "prefix-SERVICE_TOKEN",
                1024
            )
            .unwrap(),
            "Token prefix-SERVICE_TOKEN prefix-SERVICE_TOKEN"
        );
    }
    #[test]
    fn repeated_names_cannot_expand_past_forwarding_limits() {
        assert!(replace_name("A A A A", "A", &"x".repeat(4096), 1024).is_err());
        let credentials = credentials();
        let headers = vec![("authorization".into(), "SERVICE_TOKEN ".repeat(2000))];
        let input = Input {
            headers: &headers,
            target: "/",
            body: b"",
            content_type: "",
        };
        let expected = plan(&input, &credentials).unwrap();
        assert!(materialize(&input, &credentials, &expected).is_err());
    }
}
