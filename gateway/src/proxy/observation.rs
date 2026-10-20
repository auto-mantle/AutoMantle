use super::{
    Authorization, Context, RequestLifecycle, RequestMonitor, Result, valid_host, valid_method,
    valid_path,
};

pub(super) struct Observation<'a> {
    context: &'a Context,
    pub(super) id: String,
    pub(super) host: Option<String>,
    pub(super) port: Option<u16>,
    pub(super) method: Option<String>,
    pub(super) path: Option<String>,
    pub(super) terminal: bool,
    pub(super) authorization: Option<Authorization>,
}
impl<'a> Observation<'a> {
    pub(super) fn new(context: &'a Context) -> Result<Self> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "request tracking unavailable")?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let id = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        Ok(Self {
            context,
            id,
            host: None,
            port: None,
            method: None,
            path: None,
            terminal: false,
            authorization: None,
        })
    }
    pub(super) fn request_active(&mut self, client: &mut dyn RequestMonitor) -> bool {
        let Some(authorization) = self
            .authorization
            .as_mut()
            .filter(|authorization| authorization.has_approval())
        else {
            if !self.context.active() {
                self.report("CANCELLED");
                return false;
            }
            return true;
        };
        let lifecycle = RequestLifecycle::new(
            &self.context.stopped,
            &self.context.cancelled,
            self.context.deadline,
        );
        if let Some(reason) = lifecycle.end_reason(client) {
            authorization.expire(reason);
            self.report("COMPLETED");
            return false;
        }
        true
    }
    pub(super) fn capture(&mut self, raw: &[u8], tunnel: Option<&str>) {
        let Some(line) = std::str::from_utf8(raw)
            .ok()
            .and_then(|text| text.lines().next())
        else {
            return;
        };
        let mut words = line.split_ascii_whitespace();
        let (Some(method), Some(target)) = (words.next(), words.next()) else {
            return;
        };
        if method.len() > 64 || !valid_method(method) {
            return;
        }
        self.method = Some(method.to_owned());
        if let Some(host) = tunnel {
            self.host = Some(host.to_owned());
            self.port = Some(443);
            self.path = valid_path(target).then(|| target.to_owned());
        } else if method == "CONNECT" {
            if let Some((host, port)) = target.rsplit_once(':') {
                if valid_host(host) && port == "443" {
                    self.host = Some(host.to_ascii_lowercase());
                    self.port = Some(443);
                }
            }
        } else if let Ok(url) = reqwest::Url::parse(target) {
            if url.scheme() == "http" && url.username().is_empty() && url.password().is_none() {
                if let Some(host) = url.host_str().filter(|host| valid_host(host)) {
                    self.host = Some(host.to_ascii_lowercase());
                    self.port = Some(url.port().unwrap_or(80));
                    self.path = (url.query().is_none()
                        && url.fragment().is_none()
                        && valid_path(url.path()))
                    .then(|| url.path().to_owned());
                }
            }
        }
    }
    pub(super) fn report(&mut self, reason: &str) {
        let safe = |value: &Option<String>| {
            value
                .as_ref()
                .filter(|text| !self.context.credentials.contains_secret(text.as_bytes()))
                .cloned()
        };
        self.context.backend.report_history(&serde_json::json!({
            "requestId": self.id, "agentProfileId": self.context.profile,
            "host": safe(&self.host), "port": self.port, "method": safe(&self.method), "path": safe(&self.path), "reason": reason
        }));
        self.terminal = true;
    }
}
