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

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

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
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 16 * 1024
        {
            return Err(
                "gateway config must be a root-owned regular file, mode 0600, at most 16 KiB"
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
    #[cfg(test)]
    pub fn authorize(
        &self,
        profile: &str,
        method: &str,
        host: &str,
        path: &str,
        stopped: &AtomicBool,
        cancelled: &AtomicBool,
        vm_deadline: Instant,
    ) -> Result<bool> {
        let action = json!({"resource_type":"http", "method":method.to_ascii_lowercase(), "host":host, "path":path});
        self.authorize_action(profile, &action, stopped, cancelled, vm_deadline)
    }

    #[cfg(test)]
    pub fn authorize_action(
        &self,
        profile: &str,
        action: &Value,
        stopped: &AtomicBool,
        cancelled: &AtomicBool,
        vm_deadline: Instant,
    ) -> Result<bool> {
        let lifecycle = RequestLifecycle::new(stopped, cancelled, vm_deadline);
        let mut result =
            self.authorize_action_recorded(profile, action, None, None, &lifecycle, &mut || None)?;
        let allowed = result.is_allowed();
        result.dispatched();
        Ok(allowed)
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener};
    const PROFILE: &str = "10000000-0000-0000-0000-000000000001";
    const ID: &str = "20000000-0000-0000-0000-000000000001";
    #[test]
    fn backend_url_is_restricted_to_a_local_origin() {
        for url in [
            "http://127.0.0.1:8081",
            "http://localhost:8081",
            "http://[::1]:8081",
            "https://localhost:8081",
        ] {
            assert!(validate_url(&Url::parse(url).unwrap()).is_ok(), "{url}");
        }
        for url in [
            "https://example.com",
            "http://192.168.1.10",
            "http://127.0.0.1:8081/api",
            "http://user@localhost",
            "http://localhost?query=1",
            "http://localhost#fragment",
        ] {
            assert!(validate_url(&Url::parse(url).unwrap()).is_err(), "{url}");
        }
    }
    pub(crate) fn server(
        responses: Vec<(u16, Value)>,
    ) -> (Backend, thread::JoinHandle<Vec<(String, Value)>>) {
        server_observed(responses, |_| {})
    }
    pub(crate) fn server_observed(
        responses: Vec<(u16, Value)>,
        mut observed: impl FnMut(usize) + Send + 'static,
    ) -> (Backend, thread::JoinHandle<Vec<(String, Value)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (code, mut value) in responses {
                loop {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut header = Vec::new();
                    let mut byte = [0];
                    while !header.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                    }
                    let header = String::from_utf8(header).unwrap();
                    let size = header
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    let mut body = vec![0; size];
                    stream.read_exact(&mut body).unwrap();
                    if header.starts_with("POST /gateway/request-history ") && code != 204 {
                        write!(
                            stream,
                            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                        continue;
                    }
                    requests.push((
                        header,
                        if body.is_empty() {
                            Value::Null
                        } else {
                            serde_json::from_slice(&body).unwrap()
                        },
                    ));
                    observed(requests.len());
                    if value.get("actionMetadata").is_some()
                        && value["actionMetadata"]["action"].is_null()
                    {
                        value["actionMetadata"]["action"] = requests
                            .iter()
                            .find(|request| request.0.starts_with("POST /gateway/evaluate "))
                            .unwrap()
                            .1["action"]
                            .clone();
                    }
                    let body = value.to_string();
                    write!(stream, "HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    break;
                }
            }
            requests
        });
        (
            Backend::new(
                Client::builder()
                    .no_proxy()
                    .redirect(Policy::none())
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
                base,
            )
            .unwrap(),
            worker,
        )
    }
    fn authorize(backend: &Backend) -> Result<bool> {
        backend.authorize(
            PROFILE,
            "GET",
            "example.com",
            "/api",
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
    }
    #[test]
    fn backend_rejected_action_is_denied() {
        let (backend, worker) = server(vec![(400, json!({"error":"invalid action"}))]);
        assert!(!authorize(&backend).unwrap());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.starts_with("POST /gateway/evaluate "));
    }
    #[test]
    fn history_reporting_uses_local_barrier_without_authentication() {
        let (backend, worker) = server(vec![(204, Value::Null)]);
        let event = json!({"requestId":ID,"agentProfileId":PROFILE,"host":"example.com","port":443,"method":"CONNECT","reason":"HTTPS_DISABLED"});
        backend.report_history(&event);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.starts_with("POST /gateway/request-history "));
        assert!(
            requests[0]
                .0
                .to_ascii_lowercase()
                .contains("x-automantle-gateway: local")
        );
        assert!(
            !requests[0]
                .0
                .to_ascii_lowercase()
                .contains("authorization:")
        );
        assert_eq!(requests[0].1, event);
    }

    #[test]
    fn failed_approval_expiration_is_retried() {
        let (backend, worker) = server(vec![(503, Value::Null), (204, Value::Null)]);
        backend.expire_approval(ID, PROFILE, EndReason::ClientClosed);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2);
        for (request, body) in requests {
            assert!(request.starts_with(&format!("POST /gateway/approval-requests/{ID}/expire ")));
            assert_eq!(body["agentProfileId"], PROFILE);
            assert_eq!(body["reason"], "CLIENT_CLOSED");
        }
    }

    #[test]
    fn setup_session_is_bound_to_profile_and_waits_for_approval_before_allowing() {
        for status in ["APPROVED", "REJECTED"] {
            let setup_id = "30000000-0000-0000-0000-000000000001";
            let expires = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
            let (backend, worker) = server(vec![
                (
                    201,
                    json!({"id":setup_id,"agentProfileId":PROFILE,"expiresAt":expires}),
                ),
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":ID}),
                ),
                (200, approval(status)),
                (204, Value::Null),
            ]);
            let deadline = Instant::now() + Duration::from_secs(30);
            let session = backend.start_setup(PROFILE, deadline).unwrap();
            let action =
                json!({"resource_type":"http","method":"get","host":"example.com","path":"/api"});
            let allowed = backend
                .authorize_action_recorded(
                    PROFILE,
                    &action,
                    Some(ID),
                    Some(&session),
                    &RequestLifecycle::new(
                        &AtomicBool::new(false),
                        &AtomicBool::new(false),
                        deadline,
                    ),
                    &mut || None,
                )
                .unwrap();
            let mut allowed = allowed;
            assert_eq!(allowed.is_allowed(), status == "APPROVED");
            allowed.dispatched();
            backend.finish_setup(PROFILE, &session);
            let requests = worker.join().unwrap();
            assert_eq!(requests.len(), 4);
            assert!(requests[0].0.starts_with("POST /gateway/setup "));
            assert_eq!(requests[0].1["agentProfileId"], PROFILE);
            assert_eq!(requests[1].1["setupSessionId"], setup_id);
            assert_eq!(requests[1].1["requestId"], ID);
            assert!(requests[2].0.starts_with("GET /gateway/approval-requests/"));
            assert!(
                requests[3]
                    .0
                    .starts_with(&format!("POST /gateway/setup/{PROFILE}/{setup_id}/finish "))
            );
        }
    }

    #[test]
    fn setup_never_overrides_a_deny_and_rejects_expired_session_registration() {
        let (backend, worker) = server(vec![(200, json!({"decision":"DENY"}))]);
        assert!(!backend
            .authorize_action_recorded(
                PROFILE,
                &json!({"resource_type":"http","method":"get","host":"example.com","path":"/api"}),
                None,
                Some(ID),
                &RequestLifecycle::new(&AtomicBool::new(false),&AtomicBool::new(false),Instant::now()+Duration::from_secs(5)),
                &mut ||None,
            )
            .unwrap().is_allowed());
        assert_eq!(worker.join().unwrap()[0].1["setupSessionId"], ID);
        let expires = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let (backend, worker) = server(vec![(
            201,
            json!({"id":ID,"agentProfileId":PROFILE,"expiresAt":expires}),
        )]);
        assert!(
            backend
                .start_setup(PROFILE, Instant::now() + Duration::from_secs(5))
                .is_err()
        );
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    fn approval(status: &str) -> Value {
        json!({"id":ID,"agentProfileId":PROFILE,"status":status,
            "actionMetadata":{"action":{"resource_type":"http","method":"get","host":"example.com","path":"/api"}}})
    }
    #[test]
    fn sends_fixed_profile_and_actual_action_without_authentication() {
        let (backend, worker) = server(vec![(200, json!({"decision":"ALLOW"}))]);
        assert!(authorize(&backend).unwrap());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].0.starts_with("POST /gateway/evaluate "));
        let headers = requests[0].0.to_ascii_lowercase();
        assert!(headers.contains("x-automantle-gateway: local"));
        assert!(!headers.contains("authorization:"));
        assert_eq!(requests[0].1["agentProfileId"], PROFILE);
        assert_eq!(requests[0].1["action"]["path"], "/api");
    }
    #[test]
    fn deny_unknown_and_server_failure_never_allow() {
        for (code, decision) in [(200, "DENY"), (200, "UNKNOWN"), (503, "ALLOW")] {
            let (backend, worker) = server(vec![(code, json!({"decision":decision}))]);
            assert!(!authorize(&backend).unwrap_or(false));
            worker.join().unwrap();
        }
    }
    #[test]
    fn rejected_request_is_not_retried_or_authenticated() {
        let (backend, worker) = server(vec![(401, Value::Null)]);
        assert!(authorize(&backend).is_err());
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    #[test]
    fn approval_is_bound_to_exact_action_and_profile() {
        for mismatch in ["none", "path", "profile", "status", "id"] {
            let mut status = approval("APPROVED");
            match mismatch {
                "path" => status["actionMetadata"]["action"]["path"] = json!("/other"),
                "profile" => status["agentProfileId"] = json!(ID),
                "status" => status["status"] = json!("UNKNOWN"),
                "id" => status["id"] = json!(PROFILE),
                _ => {}
            }
            let mut responses = vec![
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":ID}),
                ),
                (200, status),
            ];
            if mismatch != "none" {
                responses.push((204, Value::Null));
            }
            let (backend, worker) = server(responses);
            assert_eq!(authorize(&backend).unwrap_or(false), mismatch == "none");
            worker.join().unwrap();
        }
    }
    #[test]
    fn rejected_and_expired_approvals_block() {
        for status in ["REJECTED", "EXPIRED"] {
            let (backend, worker) = server(vec![
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":ID}),
                ),
                (200, approval(status)),
            ]);
            assert!(!authorize(&backend).unwrap());
            worker.join().unwrap();
        }
    }
    #[test]
    fn stopped_proxy_cancelled_or_expired_vm_never_contacts_backend() {
        for state in ["stopped", "cancelled", "expired"] {
            let (backend, worker) = server(vec![]);
            let deadline = if state == "expired" {
                Instant::now() - Duration::from_secs(1)
            } else {
                Instant::now() + Duration::from_secs(5)
            };
            assert!(
                !backend
                    .authorize(
                        PROFILE,
                        "GET",
                        "example.com",
                        "/api",
                        &AtomicBool::new(state == "stopped"),
                        &AtomicBool::new(state == "cancelled"),
                        deadline
                    )
                    .unwrap()
            );
            assert!(worker.join().unwrap().is_empty());
        }
    }
    #[test]
    fn client_closure_is_preserved_when_approval_poll_fails() {
        let closed = std::sync::Arc::new(AtomicBool::new(false));
        let signal = closed.clone();
        let (backend, worker) = server_observed(
            vec![
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":ID}),
                ),
                (503, Value::Null),
                (204, Value::Null),
            ],
            move |count| {
                if count == 2 {
                    signal.store(true, Ordering::Relaxed);
                }
            },
        );
        let stopped = AtomicBool::new(false);
        let cancelled = AtomicBool::new(false);
        let lifecycle = RequestLifecycle::new(
            &stopped,
            &cancelled,
            Instant::now() + Duration::from_secs(5),
        );
        let mut monitor = || {
            closed
                .load(Ordering::Relaxed)
                .then_some(EndReason::ClientClosed)
        };
        assert!(backend.authorize_action_recorded(
            PROFILE,
            &json!({"resource_type":"http","method":"get","host":"example.com","path":"/api"}),
            None, None, &lifecycle, &mut monitor,
        ).is_err());
        let calls = worker.join().unwrap();
        assert_eq!(calls[2].1["reason"], "CLIENT_CLOSED");
    }
    #[test]
    fn pending_approval_is_cancelled_without_forwarding() {
        let (signal, ready) = std::sync::mpsc::channel();
        let (backend, worker) = server_observed(
            vec![
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":ID}),
                ),
                (200, approval("PENDING")),
                (204, Value::Null),
            ],
            move |count| {
                if count == 2 {
                    signal.send(()).unwrap();
                }
            },
        );
        let cancelled = AtomicBool::new(false);
        thread::scope(|scope| {
            let cancel = &cancelled;
            scope.spawn(move || {
                ready.recv_timeout(Duration::from_secs(3)).unwrap();
                cancel.store(true, Ordering::Relaxed);
            });
            assert!(
                !backend
                    .authorize(
                        PROFILE,
                        "GET",
                        "example.com",
                        "/api",
                        &AtomicBool::new(false),
                        &cancelled,
                        Instant::now() + Duration::from_secs(5)
                    )
                    .unwrap()
            );
        });
        let calls = worker.join().unwrap();
        assert_eq!(calls[2].1["reason"], "REQUEST_CANCELLED");
    }
}
