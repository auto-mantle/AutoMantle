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
    pub body: Option<crate::body::Payload>,
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
        body: None,
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
        for placement in expected.iter().filter(|p| p.location == "json") {
            let field = value
                .pointer_mut(&placement.selector)
                .ok_or("credential JSON field missing")?;
            let original = field.as_str().ok_or("credential JSON field changed")?;
            let secret = credentials
                .secret(&placement.placeholder)
                .ok_or("credential unavailable")?;
            *field = Value::String(replace_name(
                original,
                &placement.placeholder,
                secret,
                usize::MAX,
            )?);
        }
        let mut spool = crate::body::Spool::default();
        serde_json::to_writer(&mut spool, &value)?;
        output.body = Some(spool.finish()?);
    }
    let header_bytes: usize = output
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + 4)
        .sum();
    if output.target.len() + header_bytes > 32 * 1024 {
        return Err("credential request exceeds forwarding limits".into());
    }
    Ok(output)
}
