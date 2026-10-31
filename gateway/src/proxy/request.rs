use super::destination::parse_target;
use super::{Credentials, Result, body};
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub(super) struct Request {
    pub(super) method: String,
    pub(super) host: String,
    pub(super) path: String,
    pub(super) target: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) content_length: usize,
    pub(super) chunked: bool,
    pub(super) content_type: String,
    pub(super) body: body::Payload,
    pub(super) body_metadata: Option<serde_json::Value>,
    pub(super) forwarding_error: Option<(u16, &'static str)>,
}
pub(crate) fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
pub(super) fn writes_body(method: &str) -> bool {
    method != "CONNECT"
}
impl Request {
    pub(super) fn injection_input(&self) -> crate::injection::Input<'_> {
        crate::injection::Input {
            headers: &self.headers,
            target: &self.target,
            body: &self.body,
            content_type: &self.content_type,
        }
    }
    pub(super) fn credential_plan(
        &self,
        credentials: &Credentials,
    ) -> Result<Vec<crate::injection::Placement>> {
        crate::injection::plan(&self.injection_input(), credentials)
    }
    pub(super) fn unsupported_forwarding(&self) -> bool {
        self.forwarding_error.is_some()
            || !forwardable_query(&self.target)
            || self
                .headers
                .iter()
                .any(|(name, value)| match name.as_str() {
                    "upgrade" | "proxy-authorization" | "te" | "trailer" => true,
                    "transfer-encoding" => !value.eq_ignore_ascii_case("chunked"),
                    "expect" => !value.eq_ignore_ascii_case("100-continue"),
                    "connection" | "proxy-connection" => {
                        !value.eq_ignore_ascii_case("close")
                            && !value.eq_ignore_ascii_case("keep-alive")
                    }
                    _ => false,
                })
    }

    pub(super) fn action(&self) -> serde_json::Value {
        let mut action = serde_json::json!({"resource_type":"http", "method":self.method.to_ascii_lowercase(),
            "host":self.host, "path":self.path});
        let mut fingerprint = ring::digest::Context::new(&ring::digest::SHA256);
        for bytes in [
            self.method.as_bytes(),
            self.host.as_bytes(),
            self.target.as_bytes(),
        ]
        .into_iter()
        .chain(
            self.headers
                .iter()
                .flat_map(|(name, value)| [name.as_bytes(), value.as_bytes()]),
        )
        .chain(std::iter::once(&*self.body))
        {
            fingerprint.update(&(bytes.len() as u64).to_be_bytes());
            fingerprint.update(bytes);
        }
        action["request_sha256"] = serde_json::json!(
            fingerprint
                .finish()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        if let Some(body) = &self.body_metadata {
            action["body"] = body.clone();
        }
        action
    }
    pub(super) fn reviewed_action(
        &self,
        credentials: &Credentials,
        plan: Option<&[crate::injection::Placement]>,
    ) -> serde_json::Value {
        let mut action = self.action();
        let mut identities = plan
            .unwrap_or(&[])
            .iter()
            .map(|placement| {
                serde_json::json!({
                    "placeholder": placement.placeholder,
                    "location": placement.location,
                    "selector": placement.selector,
                })
            })
            .collect::<Vec<_>>();
        if let Some(guest) = credentials.identities(&self.headers).as_array() {
            identities.extend(
                guest
                    .iter()
                    .filter(|identity| {
                        identity["placeholder"]
                            .as_str()
                            .is_some_and(|name| name.starts_with("AUTOMANTLE_VM_BEARER_"))
                    })
                    .cloned(),
            );
        }
        if !identities.is_empty() {
            action["credentials"] = serde_json::Value::Array(identities);
        }
        if !self.body.is_empty() && self.body_metadata.is_some() {
            action["body"]["preview"] = if self
                .body_metadata
                .as_ref()
                .is_some_and(|m| m["preview"]["omitted"] == true)
                || !body::is_json(&self.content_type)
                || self
                    .headers
                    .iter()
                    .any(|(name, _)| name == "content-encoding" || name == "cookie")
                || credentials.uses_guest_bearer(&self.headers)
            {
                serde_json::json!({"omitted": true})
            } else {
                credentials.body_preview(&self.body)
            };
        }
        action
    }
}
type ParseResult = std::result::Result<Request, (u16, &'static str)>;

pub(super) fn parse_request(raw: &[u8], tunnel_host: Option<&str>) -> ParseResult {
    let text = std::str::from_utf8(raw).map_err(|_| (400, "invalid request encoding"))?;
    let text = text
        .strip_suffix("\r\n\r\n")
        .ok_or((400, "incomplete request"))?;
    let mut lines = text.split("\r\n");
    let first = lines
        .next()
        .unwrap_or_default()
        .split(' ')
        .collect::<Vec<_>>();
    if first.len() != 3 || !matches!(first[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err((400, "invalid request line"));
    }
    let method = first[0];
    let target = first[1];
    if method.len() > 64 || !valid_method(method) {
        return Err((400, "invalid HTTP method"));
    }
    let (host, path, port, forward_target) = if method == "CONNECT" {
        if tunnel_host.is_some() {
            return Err((403, "nested CONNECT denied"));
        }
        (
            connect_host(target).ok_or((400, "CONNECT requires a DNS name on port 443"))?,
            String::new(),
            443,
            String::new(),
        )
    } else {
        match tunnel_host {
            Some(host) => {
                if !(target.starts_with('/') || method == "OPTIONS" && target == "*") {
                    return Err((400, "invalid HTTPS request path"));
                }
                (
                    host.to_owned(),
                    if target == "*" {
                        "/".into()
                    } else {
                        target.split('?').next().unwrap_or(target).to_owned()
                    },
                    443,
                    target.to_owned(),
                )
            }
            None => {
                let (host, path, origin) = parse_target(target)
                    .ok_or((400, "only absolute plain HTTP URLs are supported"))?;
                (host, path, 80, origin)
            }
        }
    };
    if !valid_host(&host) || (method != "CONNECT" && !valid_path(&path)) {
        return Err((400, "invalid destination or request path"));
    }
    let mut headers = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or((400, "invalid header"))?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| (b < 32 && b != b'\t') || b >= 127)
        {
            return Err((400, "invalid header"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_owned();
        if !seen.insert(name.clone())
            && matches!(
                name.as_str(),
                "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "content-type"
                    | "authorization"
                    | "x-api-key"
            )
        {
            return Err((400, "duplicate framing or identity header"));
        }
        headers.push((name, value));
    }
    if method == "CONNECT"
        && headers
            .iter()
            .any(|(name, _)| matches!(name.as_str(), "authorization" | "x-api-key"))
    {
        return Err((403, "credentials are not allowed on CONNECT"));
    }
    let host_header = headers
        .iter()
        .find(|(n, _)| n == "host")
        .ok_or((400, "Host header required"))?;
    if !(host_header.1.eq_ignore_ascii_case(&host)
        || host_header
            .1
            .eq_ignore_ascii_case(&format!("{host}:{port}")))
    {
        return Err((400, "Host does not match destination"));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value);
    let chunked = headers.iter().any(|(name, _)| name == "transfer-encoding");
    if chunked && (length.is_some() || !writes_body(method)) {
        return Err((400, "ambiguous or unsupported body framing"));
    }
    let content_length = match length {
        None => 0,
        Some(value) => {
            if value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err((400, "invalid Content-Length"));
            }
            value
                .parse::<usize>()
                .map_err(|_| (400, "invalid Content-Length"))?
        }
    };
    let media = headers.iter().find(|(name, _)| name == "content-type");
    let content_type = if writes_body(method) {
        media.map(|(_, value)| value.clone()).unwrap_or_default()
    } else {
        if content_length != 0 || media.is_some() || (method == "CONNECT" && length.is_some()) {
            return Err((400, "body is not supported for this method"));
        }
        String::new()
    };
    Ok(Request {
        method: method.to_owned(),
        host,
        path,
        target: forward_target,
        headers,
        content_length,
        chunked,
        content_type,
        body: body::Payload::default(),
        body_metadata: None,
        forwarding_error: None,
    })
}
pub(super) fn connect_host(authority: &str) -> Option<String> {
    let host = authority.strip_suffix(":443")?.to_ascii_lowercase();
    valid_host(&host).then_some(host)
}
pub(crate) fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
pub(crate) fn valid_path(path: &str) -> bool {
    policy_path(path).is_some_and(|canonical| canonical == path)
}
fn policy_path(path: &str) -> Option<String> {
    if path.len() > 2048 || !path.starts_with('/') || !path.is_ascii() {
        return None;
    }
    let mut decoded = Vec::new();
    let mut bytes = path.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let high = (bytes.next()? as char).to_digit(16)?;
            let low = (bytes.next()? as char).to_digit(16)?;
            let b = (high * 16 + low) as u8;
            if b"/\\%".contains(&b) {
                return None;
            }
            decoded.push(b);
        } else {
            decoded.push(b);
        }
    }
    let text = std::str::from_utf8(&decoded).ok()?;
    if text.contains("//") || text.split('/').any(|s| matches!(s, "." | "..")) {
        return None;
    }
    let mut canonical = String::new();
    for b in decoded {
        if b >= 128 {
            canonical.push_str(&format!("%{b:02X}"));
        } else if b.is_ascii_alphanumeric() || b"/_~!$&'()+,;=:@.-".contains(&b) {
            canonical.push(b as char);
        } else {
            return None;
        }
    }
    Some(canonical)
}
fn forwardable_query(target: &str) -> bool {
    let Some((_, query)) = target.split_once('?') else {
        return true;
    };
    let mut bytes = query.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !byte.is_ascii_alphanumeric() && !b"/_~!$&'()+,;=:@.-?".contains(&byte) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::parse_request;

    #[test]
    fn absolute_http_query_keeps_its_forwarding_target() {
        let request = parse_request(
            b"GET http://example.com?item=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            None,
        )
        .unwrap();

        assert_eq!(request.host, "example.com");
        assert_eq!(request.path, "/");
        assert_eq!(request.target, "/?item=1");
    }

    #[test]
    fn tunnel_request_preserves_origin_and_policy_path() {
        let request = parse_request(
            b"GET /v1/items?item=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            Some("example.com"),
        )
        .unwrap();

        assert_eq!(request.path, "/v1/items");
        assert_eq!(request.target, "/v1/items?item=1");
    }

    #[test]
    fn request_rejects_noncanonical_paths_and_method_tokens() {
        for raw in [
            &b"GET /allowed/../admin HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            &b"GET /allowed/%2Fadmin HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            &b"GE\tT /allowed HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        ] {
            assert!(parse_request(raw, Some("example.com")).is_err());
        }
    }
}
