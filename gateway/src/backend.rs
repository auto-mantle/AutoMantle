mod expiration;

use crate::{
    request_lifecycle::{EndReason, RequestLifecycle, RequestMonitor},
    sandbox::Result,
};
use chrono::{DateTime, Utc};
use expiration::ExpirationReporter;
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const MAX_JSON: u64 = 256 * 1024;
#[derive(Clone)]
pub struct Backend {
    client: Client,
    base: String,
    expiration: ExpirationReporter,
}

pub struct Authorization {
    allowed: bool,
    approval: Option<PendingApproval>,
}
struct PendingApproval {
    backend: Backend,
    id: String,
    profile: String,
    finished: bool,
}
impl Authorization {
    fn immediate(allowed: bool) -> Self {
        Self {
            allowed,
            approval: None,
        }
    }
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }
    pub fn expire(&mut self, reason: EndReason) {
        self.allowed = false;
        if let Some(approval) = self.approval.as_mut() {
            approval.expire(reason);
        }
    }
    pub fn dispatched(&mut self) {
        if let Some(approval) = self.approval.as_mut() {
            approval.finished = true;
        }
    }
    pub fn has_approval(&self) -> bool {
        self.approval.is_some()
    }
}
impl PendingApproval {
    fn expire(&mut self, reason: EndReason) {
        if !self.finished {
            self.finished = true;
            self.backend
                .expire_approval(&self.id, &self.profile, reason);
        }
    }
}
impl Drop for PendingApproval {
    fn drop(&mut self) {
        self.expire(EndReason::RequestNotExecuted);
    }
}

impl Backend {
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.len() > 16 * 1024
        {
            return Err(
                "gateway config must be a private gateway-owned regular file, mode 0600, at most 16 KiB"
                    .into(),
            );
        }
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;
        let config: Value =
            serde_json::from_str(&raw).map_err(|_| "invalid gateway config JSON")?;
        let fields = config.as_object().ok_or("invalid gateway config")?;
        if fields.keys().any(|k| k != "backendUrl") {
            return Err("unknown gateway config field".into());
        }
        let field = |name| -> Result<String> {
            config[name]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| "missing gateway configuration value".into())
        };
        let base = field("backendUrl")?;
        let url = Url::parse(&base).map_err(|_| "invalid backend URL")?;
        validate_url(&url)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()?;
        let backend = Self::new(client, url.as_str().trim_end_matches('/').to_owned())?;
        let health = backend.request("/gateway/health", None, &|| true)?;
        if health["status"] != "ready" {
            return Err("local backend is not ready".into());
        }
        Ok(backend)
    }

    fn new(client: Client, base: String) -> Result<Self> {
        let expiration = ExpirationReporter::start(client.clone(), base.clone())?;
        Ok(Self {
            client,
            base,
            expiration,
        })
    }

    fn decode(response: reqwest::blocking::Response) -> Result<Value> {
        if !response.status().is_success() {
            return Err("backend rejected request".into());
        }
        let mut bytes = Vec::new();
        response.take(MAX_JSON + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_JSON {
            return Err("backend response too large".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid backend response".into())
    }

    pub fn validate_profile(&self, profile: &str) -> Result<()> {
        if !uuid(profile) {
            return Err("an Agent Profile UUID is required".into());
        }
        let result = self.request(&format!("/gateway/agent-profiles/{profile}"), None, &|| {
            true
        })?;
        if result["id"] != profile {
            return Err("Agent Profile is missing, deleted, or does not match".into());
        }
        Ok(())
    }

    fn send(
        &self,
        path: &str,
        body: Option<&Value>,
        active: &dyn Fn() -> bool,
    ) -> Result<reqwest::blocking::Response> {
        if !active() {
            return Err("gateway request cancelled".into());
        }
        let url = format!("{}{path}", self.base);
        let request = match body {
            Some(v) => self.client.post(url).json(v),
            None => self.client.get(url),
        };
        request
            .header("X-Automantle-Gateway", "local")
            .send()
            .map_err(|_| "local backend unavailable".into())
    }

    fn request(
        &self,
        path: &str,
        body: Option<&Value>,
        active: &dyn Fn() -> bool,
    ) -> Result<Value> {
        Self::decode(self.send(path, body, active)?)
    }

    fn evaluate(&self, action: &Value, active: &dyn Fn() -> bool) -> Result<Option<Value>> {
        let response = self.send("/gateway/evaluate", Some(action), active)?;
        if matches!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Ok(None);
        }
        Self::decode(response).map(Some)
    }
    pub fn report_history(&self, event: &Value) {
        let result = self
            .client
            .post(format!("{}/gateway/request-history", self.base))
            .header("X-Automantle-Gateway", "local")
            .timeout(Duration::from_millis(750))
            .json(event)
            .send();
        if !matches!(result, Ok(response) if response.status().is_success()) {
            eprintln!("network history=unavailable");
        }
    }

    pub fn report_network_history(&self, events: &[Value]) {
        let result = self
            .client
            .post(format!("{}/gateway/network-history", self.base))
            .header("X-Automantle-Gateway", "local")
            .timeout(Duration::from_millis(750))
            .json(events)
            .send();
        if !matches!(result, Ok(response) if response.status().is_success()) {
            eprintln!("network-policy audit_backend=unavailable; metadata retained in host log");
        }
    }

    pub fn start_setup(&self, profile: &str, deadline: Instant) -> Result<String> {
        let active = || Instant::now() < deadline;
        let lifetime = deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .clamp(1, 86400);
        let session = self.request(
            "/gateway/setup",
            Some(&json!({"agentProfileId":profile,"lifetimeSeconds":lifetime})),
            &active,
        )?;
        let id = session["id"]
            .as_str()
            .filter(|id| uuid(id))
            .ok_or("invalid setup session")?;
        if session["agentProfileId"] != profile
            || Utc::now() >= setup_expiry(&session["expiresAt"])?
        {
            return Err("invalid setup session".into());
        }
        eprintln!("network mode=setup; open the dashboard for connection prompts");
        Ok(id.to_owned())
    }

    pub fn finish_setup(&self, profile: &str, id: &str) {
        let result = self
            .client
            .post(format!("{}/gateway/setup/{profile}/{id}/finish", self.base))
            .header("X-Automantle-Gateway", "local")
            .timeout(Duration::from_millis(750))
            .send();
        if !matches!(result, Ok(response) if response.status().is_success()) {
            eprintln!("network setup_cleanup=unavailable; setup expires automatically");
        }
    }

    fn expire_approval(&self, id: &str, profile: &str, reason: EndReason) {
        if expiration::send(&self.client, &self.base, id, profile, reason) {
            return;
        }
        self.expiration.retry(id, profile, reason);
    }

    fn wait_for_approval(
        &self,
        profile: &str,
        action: &Value,
        id: &str,
        lifecycle: &RequestLifecycle<'_>,
        monitor: &mut dyn RequestMonitor,
    ) -> Result<Authorization> {
        let active = || lifecycle.host_active();
        let mut authorization = Authorization {
            allowed: false,
            approval: Some(PendingApproval {
                backend: self.clone(),
                id: id.to_owned(),
                profile: profile.to_owned(),
                finished: false,
            }),
        };
        loop {
            if let Some(reason) = lifecycle.end_reason(monitor) {
                authorization.expire(reason);
                return Ok(authorization);
            }
            let status =
                match self.request(&format!("/gateway/approval-requests/{id}"), None, &active) {
                    Ok(status) => status,
                    Err(error) => {
                        if let Some(reason) = lifecycle.end_reason(monitor) {
                            authorization.expire(reason);
                        }
                        return Err(error);
                    }
                };
            if status["id"] != id
                || status["agentProfileId"]
                    .as_str()
                    .map(str::to_ascii_lowercase)
                    != Some(profile.to_ascii_lowercase())
                || status["actionMetadata"]["action"] != *action
            {
                return Err("approval does not match pending action".into());
            }
            if let Some(reason) = lifecycle.end_reason(monitor) {
                authorization.expire(reason);
                return Ok(authorization);
            }
            match status["status"].as_str() {
                Some("APPROVED") => {
                    authorization.allowed = true;
                    return Ok(authorization);
                }
                Some("REJECTED" | "EXPIRED") => {
                    authorization.dispatched();
                    return Ok(authorization);
                }
                Some("PENDING") => {}
                _ => return Err("invalid approval status".into()),
            }
            for _ in 0..10 {
                if let Some(reason) = lifecycle.end_reason(monitor) {
                    authorization.expire(reason);
                    return Ok(authorization);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    pub fn authorize_action_recorded(
        &self,
        profile: &str,
        action: &Value,
        request_id: Option<&str>,
        setup_session: Option<&str>,
        lifecycle: &RequestLifecycle<'_>,
        monitor: &mut dyn RequestMonitor,
    ) -> Result<Authorization> {
        let active = || lifecycle.host_active();
        if !active() {
            return Ok(Authorization::immediate(false));
        }
        let mut evaluation = json!({"agentProfileId":profile,"action":action});
        if let Some(id) = request_id {
            evaluation["requestId"] = json!(id);
        }
        if let Some(id) = setup_session {
            evaluation["setupSessionId"] = json!(id);
        }
        let Some(result) = self.evaluate(&evaluation, &active)? else {
            return Ok(Authorization::immediate(false));
        };
        match result["decision"].as_str() {
            Some("ALLOW") => Ok(Authorization::immediate(active())),
            Some("DENY") => Ok(Authorization::immediate(false)),
            Some("REQUIRE_APPROVAL") => {
                let id = result["approvalRequestId"]
                    .as_str()
                    .filter(|s| uuid(s))
                    .ok_or("invalid approval ID")?;
                self.wait_for_approval(profile, action, id, lifecycle, monitor)
            }
            _ => Err("unknown policy decision".into()),
        }
    }
}
fn validate_url(url: &Url) -> Result<()> {
    if !matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    ) || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("backend URL must be a loopback HTTP(S) origin".into());
    }
    Ok(())
}
fn setup_expiry(value: &Value) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.as_str().ok_or("missing setup session expiry")?)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| "invalid setup session expiry".into())
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
