use crate::{request_lifecycle::EndReason, sandbox::Result};
use reqwest::{StatusCode, blocking::Client};
use serde_json::json;
use std::{
    sync::mpsc::{self, SyncSender, TrySendError},
    thread,
    time::Duration,
};

const RETRY_QUEUE_CAPACITY: usize = 1024;

struct Expiration {
    id: String,
    profile: String,
    reason: EndReason,
}

#[derive(Clone)]
pub(super) struct ExpirationReporter {
    sender: SyncSender<Expiration>,
}

impl ExpirationReporter {
    pub(super) fn start(client: Client, base: String) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Expiration>(RETRY_QUEUE_CAPACITY);
        thread::Builder::new()
            .name("approval-expiration".into())
            .spawn(move || {
                while let Ok(expiration) = receiver.recv() {
                    loop {
                        thread::sleep(Duration::from_secs(1));
                        if send(
                            &client,
                            &base,
                            &expiration.id,
                            &expiration.profile,
                            expiration.reason,
                        ) {
                            break;
                        }
                    }
                }
            })?;
        Ok(Self { sender })
    }

    pub(super) fn retry(&self, id: &str, profile: &str, reason: EndReason) {
        let expiration = Expiration {
            id: id.to_owned(),
            profile: profile.to_owned(),
            reason,
        };
        if let Err(error) = self.sender.try_send(expiration) {
            match error {
                TrySendError::Full(_) => eprintln!("approval expiration_reporting=queue_full"),
                TrySendError::Disconnected(_) => {
                    eprintln!("approval expiration_reporting=unavailable")
                }
            }
        }
    }
}

pub(super) fn send(
    client: &Client,
    base: &str,
    id: &str,
    profile: &str,
    reason: EndReason,
) -> bool {
    let result = client
        .post(format!("{base}/gateway/approval-requests/{id}/expire"))
        .header("X-Automantle-Gateway", "local")
        .timeout(Duration::from_millis(750))
        .json(&json!({"agentProfileId":profile,"reason":reason.code()}))
        .send();
    matches!(result, Ok(response) if response.status().is_success() || response.status() == StatusCode::NOT_FOUND)
}
