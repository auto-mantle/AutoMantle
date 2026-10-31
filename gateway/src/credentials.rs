use crate::{sandbox::Result, tls::protected_read};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

mod store;
pub(crate) use store::SaveCredential;

#[derive(Clone, Default)]
pub struct Credentials {
    entries: Vec<Entry>,
    guest_bearer: Vec<GuestBearer>,
    managed_file: Option<std::path::PathBuf>,
    managed_digest: Option<Vec<u8>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Config {
    #[serde(default)]
    credentials: Vec<Entry>,
    #[serde(default)]
    guest_bearer: Vec<GuestBearer>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GuestBearer {
    agent_profile_id: String,
    host: String,
    methods: Vec<String>,
    paths: Vec<String>,
}
const GUEST_ID_PREFIX: &str = "AUTOMANTLE_VM_BEARER_";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Entry {
    placeholder: String,
    secret: String,
    #[serde(default)]
    scopes: Vec<Scope>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Scope {
    pub agent_profile_id: String,
    pub host: String,
    pub paths: Vec<String>,
    pub location: String,
    pub selector: String,
}

fn valid_scope_path(path: &str) -> bool {
    path.len() <= 2049
        && (crate::proxy::valid_path(path)
            || (path.ends_with("/*")
                && path.strip_suffix('*').is_some_and(crate::proxy::valid_path)))
}

impl GuestBearer {
    fn valid(&self) -> bool {
        crate::sandbox::valid_uuid(&self.agent_profile_id)
            && crate::proxy::valid_host(&self.host)
            && self.host == self.host.to_ascii_lowercase()
            && !self.methods.is_empty()
            && self.methods.len() <= 100
            && self.methods.iter().all(|method| {
                method.len() <= 64
                    && method == &method.to_ascii_uppercase()
                    && crate::proxy::valid_method(method)
            })
            && self.methods.iter().collect::<BTreeSet<_>>().len() == self.methods.len()
            && !self.paths.is_empty()
            && self.paths.len() <= 100
            && self
                .paths
                .iter()
                .all(|path| path == "/*" || crate::proxy::valid_path(path))
            && self.paths.iter().collect::<BTreeSet<_>>().len() == self.paths.len()
    }
}

impl Scope {
    fn valid(&self) -> bool {
        crate::sandbox::valid_uuid(&self.agent_profile_id)
            && crate::proxy::valid_host(&self.host)
            && self.host == self.host.to_ascii_lowercase()
            && !self.paths.is_empty()
            && self.paths.len() <= 100
            && self.paths.iter().all(|p| valid_scope_path(p))
            && self.paths.iter().collect::<BTreeSet<_>>().len() == self.paths.len()
            && crate::injection::valid(&crate::injection::Placement {
                placeholder: "SCOPE_CHECK".into(),
                location: self.location.clone(),
                selector: self.selector.clone(),
            })
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_uppercase() || *b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
impl Credentials {
    pub fn has_host_credentials(&self) -> bool {
        !self.entries.is_empty()
    }
    pub fn has_name(&self, name: &str) -> bool {
        self.entries.iter().any(|entry| entry.placeholder == name)
    }
    pub fn secret(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.placeholder == name)
            .map(|entry| entry.secret.as_str())
    }
    pub fn permits(
        &self,
        plan: &[crate::injection::Placement],
        profile: &str,
        host: &str,
        _method: &str,
        path: &str,
        secure: bool,
    ) -> bool {
        plan.iter().all(|placement| {
            secure
                && self.entries.iter().any(|entry| {
                    entry.placeholder == placement.placeholder
                        && entry.scopes.iter().any(|scope| {
                            scope.agent_profile_id.eq_ignore_ascii_case(profile)
                                && scope.host == host
                                && scope.location == placement.location
                                && scope.selector == placement.selector
                                && scope.paths.iter().any(|pattern| {
                                    pattern
                                        .strip_suffix('*')
                                        .map_or(pattern == path, |prefix| path.starts_with(prefix))
                                })
                        })
                })
        })
    }
    pub fn validate_guest_headers(
        &self,
        headers: &[(String, String)],
        profile: &str,
        host: &str,
        method: &str,
        path: &str,
        secure: bool,
    ) -> bool {
        let guest: Vec<_> = headers
            .iter()
            .filter(|(_, value)| crate::injection::names(value, self).is_empty())
            .cloned()
            .collect();
        self.validate(&guest, profile, host, method, path, secure)
    }

    pub fn with_managed(mut self, path: std::path::PathBuf) -> Self {
        self.managed_file = Some(path);
        self
    }
    pub fn snapshot(&self) -> Result<Self> {
        let Some(path) = &self.managed_file else {
            return Ok(self.clone());
        };
        let raw = Self::managed_raw(path)?;
        let managed = if raw.is_empty() {
            Self::default()
        } else {
            Self::parse(&raw)?
        };
        let mut combined = self.clone();
        combined.entries.extend(managed.entries);
        combined.guest_bearer.extend(managed.guest_bearer);
        let mut validated = Self::parse(
            &serde_json::to_string(&Config {
                credentials: combined.entries,
                guest_bearer: combined.guest_bearer,
            })
            .map_err(|_| "credential snapshot unavailable")?,
        )?;
        validated.managed_file = Some(path.clone());
        validated.managed_digest = Some(Self::digest(&raw));
        Ok(validated)
    }
    fn digest(raw: &str) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, raw.as_bytes())
            .as_ref()
            .to_vec()
    }
    pub fn managed_raw(path: &Path) -> Result<String> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(_) => Err("credential store unavailable".into()),
            Ok(_) => protected_read(path, true).map_err(|_| "credential store unavailable".into()),
        }
    }
    pub fn is_current(&self) -> bool {
        match (&self.managed_file, &self.managed_digest) {
            (Some(path), Some(expected)) => {
                Self::managed_raw(path).is_ok_and(|raw| Self::digest(&raw) == *expected)
            }
            _ => true,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&protected_read(path, true)?)
    }

    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let config: Config = serde_json::from_str(raw).map_err(|_| "invalid credential config")?;
        if config.credentials.len() + config.guest_bearer.len() > 32 {
            return Err("credential config supports at most 32 bindings".into());
        }
        let mut placeholders = BTreeSet::new();
        for entry in &config.credentials {
            if !valid_name(&entry.placeholder)
                || entry.placeholder.starts_with(GUEST_ID_PREFIX)
                || !placeholders.insert(&entry.placeholder)
                || !(16..=4096).contains(&entry.secret.len())
                || !entry.secret.bytes().all(|b| (33..=126).contains(&b))
                || config
                    .credentials
                    .iter()
                    .any(|other| entry.secret == other.placeholder)
                || entry.scopes.len() > 100
                || entry.scopes.iter().any(|scope| !scope.valid())
            {
                return Err("invalid credential binding".into());
            }
        }
        if config.guest_bearer.iter().any(|entry| !entry.valid()) {
            return Err("invalid guest Bearer binding".into());
        }
        Ok(Self {
            entries: config.credentials,
            guest_bearer: config.guest_bearer,
            managed_file: None,
            managed_digest: None,
        })
    }

    pub fn validate(
        &self,
        headers: &[(String, String)],
        profile: &str,
        host: &str,
        method: &str,
        path: &str,
        secure: bool,
    ) -> bool {
        headers.iter().all(|(name, value)| {
            if self.contains_secret(value.as_bytes()) {
                return false;
            }
            if name == "cookie" {
                return secure;
            }
            if !matches!(name.as_str(), "authorization" | "x-api-key") {
                return true;
            }
            secure
                && name == "authorization"
                && self.guest_token(value).is_some()
                && self.guest_bearer.iter().any(|entry| {
                    entry.agent_profile_id.eq_ignore_ascii_case(profile)
                        && entry.host == host
                        && entry.methods.iter().any(|m| m == method)
                        && entry.paths.iter().any(|p| p == "/*" || p == path)
                })
        })
    }

    pub fn forward_guest_token(&self, name: &str, value: &str) -> Option<String> {
        (name == "authorization"
            && !self.guest_bearer.is_empty()
            && self.guest_token(value).is_some())
        .then(|| value.to_owned())
    }

    fn guest_token<'a>(&self, value: &'a str) -> Option<&'a str> {
        let token = value.strip_prefix("Bearer ")?;
        if token.is_empty()
            || token.len() > 4096
            || token.contains("AUTOMANTLE_")
            || self.entries.iter().any(|entry| token == entry.placeholder)
            || self.contains_secret(token.as_bytes())
        {
            return None;
        }
        let unpadded = token.trim_end_matches('=');
        if unpadded.is_empty()
            || !unpadded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
        {
            return None;
        }
        Some(token)
    }

    pub fn uses_guest_bearer(&self, headers: &[(String, String)]) -> bool {
        !self.guest_bearer.is_empty()
            && headers
                .iter()
                .any(|(name, value)| name == "authorization" && self.guest_token(value).is_some())
    }
    pub fn contains_secret(&self, bytes: &[u8]) -> bool {
        self.entries.iter().any(|entry| {
            bytes
                .windows(entry.secret.len())
                .any(|w| w == entry.secret.as_bytes())
        })
    }

    pub fn identities(&self, headers: &[(String, String)]) -> serde_json::Value {
        serde_json::Value::Array(headers.iter().filter_map(|(name, value)| {
            if name == "authorization"
                && !self.guest_bearer.is_empty()
                && let Some(token) = self.guest_token(value)
            {
                let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
                let hash = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<String>();
                return Some(serde_json::json!({"placeholder":format!("{GUEST_ID_PREFIX}{hash}"), "header":name}));
            }
            None
        }).collect())
    }

    pub fn body_preview(&self, bytes: &[u8]) -> serde_json::Value {
        // Large bodies are forwarded, but do not need to become large policy previews.
        if bytes.len() > 16 * 1024 {
            return serde_json::json!({"omitted":true});
        }
        if crate::body::validate_json_for_injection(bytes).is_err() {
            return serde_json::json!({"omitted":true});
        }
        let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return serde_json::json!({"omitted":true});
        };
        let mut redacted = false;
        self.redact(&mut value, &mut redacted);
        let json = value.to_string();
        if json.len() > 16 * 1024 || self.contains_secret(json.as_bytes()) {
            serde_json::json!({"omitted":true})
        } else {
            serde_json::json!({"json":json,"redacted":redacted})
        }
    }

    fn redact(&self, value: &mut serde_json::Value, redacted: &mut bool) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    let key = key
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .collect::<String>()
                        .to_ascii_lowercase();
                    if [
                        "password",
                        "secret",
                        "token",
                        "apikey",
                        "authorization",
                        "cookie",
                        "credential",
                        "privatekey",
                    ]
                    .iter()
                    .any(|name| key.contains(name))
                    {
                        *value = serde_json::json!("[REDACTED]");
                        *redacted = true;
                    } else {
                        self.redact(value, redacted);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    self.redact(value, redacted);
                }
            }
            serde_json::Value::String(text) if self.contains_secret(text.as_bytes()) => {
                *value = serde_json::json!("[REDACTED]");
                *redacted = true;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Credentials;
    use crate::injection::Placement;

    #[test]
    fn host_credentials_require_tls_even_with_a_matching_scope() {
        let profile = "12345678-1234-1234-1234-123456789abc";
        let config = serde_json::json!({
            "credentials": [{
                "placeholder": "API_KEY",
                "secret": "a-secret-with-16-chars",
                "scopes": [{
                    "agentProfileId": profile,
                    "host": "example.com",
                    "paths": ["/v1/*"],
                    "location": "header",
                    "selector": "x-api-key"
                }]
            }]
        });
        let credentials = Credentials::parse(&config.to_string()).unwrap();
        let plan = [Placement {
            placeholder: "API_KEY".into(),
            location: "header".into(),
            selector: "x-api-key".into(),
        }];

        assert!(!credentials.permits(&plan, profile, "example.com", "GET", "/v1/items", false));
        assert!(credentials.permits(&plan, profile, "example.com", "GET", "/v1/items", true));
    }
}
