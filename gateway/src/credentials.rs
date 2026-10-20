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

fn valid_profile(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn valid_scope_path(path: &str) -> bool {
    path.len() <= 2049
        && (crate::proxy::valid_path(path)
            || (path.ends_with("/*")
                && path.strip_suffix('*').is_some_and(crate::proxy::valid_path)))
}

impl GuestBearer {
    fn valid(&self) -> bool {
        valid_profile(&self.agent_profile_id)
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
        valid_profile(&self.agent_profile_id)
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
            if name == "authorization" && !self.guest_bearer.is_empty() {
                if let Some(token) = self.guest_token(value) {
                    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
                    let hash = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<String>();
                    return Some(serde_json::json!({"placeholder":format!("{GUEST_ID_PREFIX}{hash}"), "header":name}));
                }
            }
            None
        }).collect())
    }

    pub fn body_preview(&self, bytes: &[u8]) -> serde_json::Value {
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
    use super::*;
    pub(super) const PROFILE: &str = "10000000-0000-0000-0000-000000000001";
    fn config() -> serde_json::Value {
        serde_json::json!({"credentials":[{"placeholder":"AUTOMANTLE_TEST_TOKEN", "secret":"test-secret-value-12345",
            "scopes":[]}]})
    }

    fn scope(host: &str, location: &str, selector: &str) -> serde_json::Value {
        serde_json::json!({"agentProfileId":PROFILE,"host":host,"paths":["/api/*"],"location":location,"selector":selector})
    }
    #[test]
    fn host_scopes_bind_profile_destination_path_and_every_placement_independently_of_policy() {
        let mut raw = config();
        raw["credentials"][0]["scopes"] = serde_json::json!([
            scope("api.example.com", "header", "authorization"),
            scope("login.example.com", "json", "/auth/token")
        ]);
        let credentials = Credentials::parse(&raw.to_string()).unwrap();
        let placement = |location: &str, selector: &str| crate::injection::Placement {
            placeholder: "AUTOMANTLE_TEST_TOKEN".into(),
            location: location.into(),
            selector: selector.into(),
        };
        let header = placement("header", "authorization");
        assert!(credentials.permits(
            &[header.clone()],
            PROFILE,
            "api.example.com",
            "GET",
            "/api/items",
            true
        ));
        assert!(credentials.permits(
            &[header.clone()],
            PROFILE,
            "api.example.com",
            "POST",
            "/api/items",
            true
        ));
        assert!(!credentials.permits(
            &[header.clone()],
            PROFILE,
            "other.example.com",
            "GET",
            "/api/items",
            true
        ));
        assert!(!credentials.permits(
            &[header.clone()],
            "20000000-0000-0000-0000-000000000002",
            "api.example.com",
            "GET",
            "/api/items",
            true
        ));
        assert!(!credentials.permits(
            &[header.clone()],
            PROFILE,
            "api.example.com",
            "GET",
            "/api",
            true
        ));
        assert!(!credentials.permits(
            &[header.clone()],
            PROFILE,
            "api.example.com",
            "GET",
            "/api-other/items",
            true
        ));
        assert!(!credentials.permits(
            &[header.clone()],
            PROFILE,
            "api.example.com",
            "GET",
            "/api/items",
            false
        ));
        assert!(!credentials.permits(
            &[placement("json", "/auth/token")],
            PROFILE,
            "api.example.com",
            "POST",
            "/api/items",
            true
        ));
        assert!(credentials.permits(
            &[placement("json", "/auth/token")],
            PROFILE,
            "login.example.com",
            "POST",
            "/api/items",
            true
        ));
        assert!(!credentials.permits(
            &[header, placement("json", "/description")],
            PROFILE,
            "api.example.com",
            "GET",
            "/api/items",
            true
        ));
        assert!(!Credentials::parse(&config().to_string()).unwrap().permits(
            &[placement("header", "authorization")],
            PROFILE,
            "api.example.com",
            "GET",
            "/api",
            true
        ));
    }
    #[test]
    fn malformed_scope_is_rejected_without_exposing_the_secret() {
        for change in [
            serde_json::json!({"host":"*.example.com"}),
            serde_json::json!({"paths":["/api/**"]}),
            serde_json::json!({"paths":["/api//x/*"]}),
            serde_json::json!({"agentProfileId":""}),
            serde_json::json!({"selector":"host"}),
            serde_json::json!({"location":"json","selector":"/bad~2pointer"}),
        ] {
            let mut value = scope("api.example.com", "header", "authorization");
            for (key, next) in change.as_object().unwrap() {
                value[key] = next.clone();
            }
            let mut raw = config();
            raw["credentials"][0]["scopes"] = serde_json::json!([value]);
            let error = Credentials::parse(&raw.to_string())
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("test-secret"));
        }
    }
    #[test]
    fn old_credential_fields_and_method_scopes_are_rejected() {
        let mut old = config();
        old["credentials"][0]["header"] = serde_json::json!("authorization");
        assert!(Credentials::parse(&old.to_string()).is_err());

        let mut old = config();
        let mut old_scope = scope("api.example.com", "header", "authorization");
        old_scope["legacyMethods"] = serde_json::json!(["GET"]);
        old["credentials"][0]["scopes"] = serde_json::json!([old_scope]);
        assert!(Credentials::parse(&old.to_string()).is_err());
    }
    #[test]
    fn plain_variable_names_are_exact_scoped_aliases_even_with_guest_oauth() {
        let mut raw = config();
        raw["credentials"][0]["placeholder"] = serde_json::json!("GITHUB_TOKEN");
        raw["credentials"][0]["scopes"] =
            serde_json::json!([scope("api.example.com", "header", "authorization")]);
        raw["guestBearer"] = serde_json::json!([{"agentProfileId":PROFILE,"host":"api.example.com","methods":["GET"],"paths":["/*"]}]);
        let c = Credentials::parse(&raw.to_string()).unwrap();
        let headers = vec![("authorization".into(), "Bearer GITHUB_TOKEN".into())];
        assert!(!c.uses_guest_bearer(&headers));
        assert!(
            c.forward_guest_token("authorization", "Bearer GITHUB_TOKEN")
                .is_none()
        );
        assert!(c.identities(&headers).as_array().unwrap().is_empty());
        let placement = crate::injection::Placement {
            placeholder: "GITHUB_TOKEN".into(),
            location: "header".into(),
            selector: "authorization".into(),
        };
        assert!(c.permits(
            &[placement.clone()],
            PROFILE,
            "api.example.com",
            "GET",
            "/api/item",
            true
        ));
        assert!(!c.permits(
            &[placement],
            PROFILE,
            "other.example.com",
            "GET",
            "/api/item",
            true
        ));
        for name in ["A", "_KEY", "DB_URL"] {
            raw["credentials"][0]["placeholder"] = serde_json::json!(name);
            assert!(Credentials::parse(&raw.to_string()).is_ok());
        }
        for name in [
            "",
            "bad-name",
            "lowercase",
            "1TOKEN",
            "AUTOMANTLE_VM_BEARER_FAKE",
        ] {
            raw["credentials"][0]["placeholder"] = serde_json::json!(name);
            assert!(Credentials::parse(&raw.to_string()).is_err());
        }
    }
    #[test]
    fn managed_values_are_write_only_persistent_rotatable_and_revocable() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::MetadataExt;
        let f = crate::storage::tests::Fixture::new();
        let make = |secret: Option<&str>| SaveCredential {
            name: "GITHUB_TOKEN".into(),
            secret: secret.map(str::to_owned),
            scopes: None,
        };
        let provider = Credentials::default().with_managed(f.store.credential_path());
        assert!(provider.snapshot().unwrap().entries.is_empty());
        let public = f
            .store
            .save_credential(make(Some("synthetic-secret-original-123")), true)
            .unwrap();
        assert!(public.get("secret").is_none());
        assert!(
            !f.store
                .list_credentials()
                .unwrap()
                .to_string()
                .contains("synthetic-secret")
        );
        let snapshot = provider.snapshot().unwrap();
        assert_eq!(
            snapshot.secret("GITHUB_TOKEN").unwrap(),
            "synthetic-secret-original-123"
        );
        assert!(snapshot.is_current());
        assert!(
            f.store
                .save_credential(make(Some("synthetic-secret-duplicate-123")), true)
                .is_err()
        );
        f.store.save_credential(make(None), false).unwrap();
        assert_eq!(
            provider.snapshot().unwrap().secret("GITHUB_TOKEN").unwrap(),
            "synthetic-secret-original-123"
        );
        f.store
            .save_credential(make(Some("synthetic-secret-rotated-456")), false)
            .unwrap();
        assert!(!snapshot.is_current());
        let current = provider.snapshot().unwrap();
        assert_eq!(
            current.secret("GITHUB_TOKEN").unwrap(),
            "synthetic-secret-rotated-456"
        );
        let meta = std::fs::metadata(f.store.credential_path()).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), 0);
        let reopened = crate::storage::Store {
            directory: f.store.directory.clone(),
        };
        assert_eq!(
            reopened.list_credentials().unwrap()[0]["name"],
            "GITHUB_TOKEN"
        );
        assert!(
            std::fs::read_to_string(reopened.credential_path())
                .unwrap()
                .contains("synthetic-secret-rotated-456")
        );
        f.store.delete_credential("GITHUB_TOKEN").unwrap();
        assert!(!current.is_current());
        assert!(provider.snapshot().unwrap().entries.is_empty());
        assert!(!provider.snapshot().unwrap().validate(
            &[("authorization".into(), "Bearer GITHUB_TOKEN".into())],
            PROFILE,
            "api.example.com",
            "GET",
            "/api",
            true
        ));
        std::fs::remove_file(f.store.credential_path()).unwrap();
        std::os::unix::fs::symlink(&f.source, f.store.credential_path()).unwrap();
        assert!(provider.snapshot().is_err());
        assert!(f.store.list_credentials().is_err());
    }
    #[test]
    fn invalid_credential_never_replaces_existing_secret_and_errors_are_sanitized() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let f = crate::storage::tests::Fixture::new();
        let value = |secret: &str| SaveCredential {
            name: "API_KEY".into(),
            secret: Some(secret.into()),
            scopes: None,
        };
        f.store
            .save_credential(value("synthetic-original-secret-123"), true)
            .unwrap();
        let before = std::fs::read(f.store.credential_path()).unwrap();
        let error = f
            .store
            .save_credential(value("synthetic rejected secret 456"), false)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("synthetic"));
        assert_eq!(std::fs::read(f.store.credential_path()).unwrap(), before);
    }

    #[test]
    fn guest_bearer_is_opt_in_exact_https_scope_and_fingerprint_only() {
        let mut raw = config();
        raw["guestBearer"] = serde_json::json!([{"agentProfileId":PROFILE,"host":"api.example.com","methods":["POST"],"paths":["/api"]}]);
        let credentials = Credentials::parse(&raw.to_string()).unwrap();
        let headers = vec![(
            "authorization".into(),
            "Bearer synthetic-vm-login-token".into(),
        )];
        assert!(credentials.validate(&headers, PROFILE, "api.example.com", "POST", "/api", true));
        for (profile, host, method, path, secure) in [
            (PROFILE, "api.example.com", "POST", "/api", false),
            (
                "20000000-0000-0000-0000-000000000001",
                "api.example.com",
                "POST",
                "/api",
                true,
            ),
            (PROFILE, "other.example.com", "POST", "/api", true),
            (PROFILE, "api.example.com", "GET", "/api", true),
            (PROFILE, "api.example.com", "POST", "/other", true),
        ] {
            assert!(!credentials.validate(&headers, profile, host, method, path, secure));
        }
        assert!(!Credentials::default().validate(
            &headers,
            PROFILE,
            "api.example.com",
            "POST",
            "/api",
            true
        ));
        assert_eq!(
            credentials
                .forward_guest_token("authorization", &headers[0].1)
                .unwrap(),
            headers[0].1
        );
        let identity = credentials.identities(&headers);
        assert!(!identity.to_string().contains("synthetic-vm-login-token"));
        assert!(
            identity[0]["placeholder"]
                .as_str()
                .unwrap()
                .starts_with(GUEST_ID_PREFIX)
        );
        assert_ne!(
            identity,
            credentials.identities(&[(
                "authorization".into(),
                "Bearer changed-vm-login-token".into()
            )])
        );
        for value in [
            "Basic synthetic",
            "Bearer ",
            "Bearer bad token",
            "Bearer a=b",
            "Bearer AUTOMANTLE_UNKNOWN",
            "Bearer test-secret-value-12345",
        ] {
            assert!(!credentials.validate(
                &[("authorization".into(), value.into())],
                PROFILE,
                "api.example.com",
                "POST",
                "/api",
                true
            ));
        }
        assert!(!credentials.validate(
            &[("x-api-key".into(), "synthetic-vm-login-token".into())],
            PROFILE,
            "api.example.com",
            "POST",
            "/api",
            true
        ));
        raw["credentials"] = serde_json::json!([]);
        assert!(Credentials::parse(&raw.to_string()).is_ok());
        for (field, value) in [
            ("host", serde_json::json!("*.example.com")),
            ("paths", serde_json::json!(["/api/*/other"])),
            ("methods", serde_json::json!(["post"])),
            ("secret", serde_json::json!("synthetic-vm-login-token")),
            ("agentProfileId", serde_json::json!("bad")),
        ] {
            let mut bad = raw.clone();
            bad["guestBearer"][0][field] = value;
            assert!(Credentials::parse(&bad.to_string()).is_err());
        }
        raw["guestBearer"][0]["paths"] = serde_json::json!(["/*"]);
        let broad = Credentials::parse(&raw.to_string()).unwrap();
        assert!(broad.validate(
            &headers,
            PROFILE,
            "api.example.com",
            "POST",
            "/new-api",
            true
        ));
        assert!(!broad.validate(
            &headers,
            PROFILE,
            "other.example.com",
            "POST",
            "/new-api",
            true
        ));
        assert!(!broad.validate(
            &headers,
            PROFILE,
            "api.example.com",
            "GET",
            "/new-api",
            true
        ));
    }
    #[test]
    fn rejects_unsafe_ambiguous_and_unknown_configuration_without_secret_errors() {
        for (field, value) in [
            ("secret", serde_json::json!("secret\r\nInjected: yes")),
            ("secret", serde_json::json!("short")),
            ("host", serde_json::json!("*.example.com")),
            ("paths", serde_json::json!(["/api?token=x"])),
            ("methods", serde_json::json!(["get"])),
            ("header", serde_json::json!("host")),
            ("unexpected", serde_json::json!("test-secret-value-12345")),
        ] {
            let mut raw = config();
            raw["credentials"][0][field] = value;
            let error = Credentials::parse(&raw.to_string())
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("test-secret"));
        }
        let mut raw = config();
        let duplicate = raw["credentials"][0].clone();
        raw["credentials"].as_array_mut().unwrap().push(duplicate);
        assert!(Credentials::parse(&raw.to_string()).is_err());
        assert!(Credentials::parse(r#"{"credentials":[],"credentials":[]}"#).is_err());
    }
    #[test]
    fn config_loader_rejects_relative_paths_and_symlink_components() {
        assert!(Credentials::load(Path::new("credentials.json")).is_err());
        assert!(Credentials::load(Path::new("/proc/self/status")).is_err());
        assert!(Credentials::load(Path::new("/tmp/automantle-credentials.json")).is_err());
    }
    #[test]
    fn review_exposes_only_identities_and_masks_nested_sensitive_values() {
        let credentials = Credentials::parse(&config().to_string()).unwrap();
        let identities = credentials.identities(&[(
            "authorization".into(),
            "Bearer AUTOMANTLE_TEST_TOKEN".into(),
        )]);
        assert_eq!(identities, serde_json::json!([]));
        let bytes = br#"{"amount":42,"password":"private","items":[{"api_key":"private","note":"test-secret-value-12345"}]}"#;
        let preview = credentials.body_preview(bytes);
        assert_eq!(preview["redacted"], true);
        let json = preview["json"].as_str().unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains("test-secret"));
        assert!(json.contains("42"));
        assert!(json.contains("[REDACTED]"));
        let large = serde_json::to_vec(&"x".repeat(17000)).unwrap();
        assert_eq!(
            credentials.body_preview(&large),
            serde_json::json!({"omitted":true})
        );
        let key = br#"{"test-secret-value-12345":"value"}"#;
        assert_eq!(
            credentials.body_preview(key),
            serde_json::json!({"omitted":true})
        );
    }
}
