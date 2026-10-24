use crate::{
    backend::Backend,
    packet_gate::{PacketGate, PacketGateConfig},
    privileged,
    sandbox::{Result, VmNetwork},
};
use serde_json::json;
use std::{
    fs::File,
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};

pub(super) struct NetworkLease {
    config: VmNetwork,
    id: String,
    capture_tap: String,
    inspection_tap: String,
    guest_sender: Option<File>,
    pub(super) gate: Option<PacketGate>,
    active: bool,
}

impl NetworkLease {
    pub(super) fn create(id: &str) -> Result<Self> {
        let suffix = crate::linux::run_suffix(id)?;
        let (value, guest_sender) =
            privileged::request(json!({"command":"create-network","id":id}))?;
        let result = (|| -> Result<Self> {
            let config: VmNetwork = serde_json::from_value(value)?;
            let guest_sender = guest_sender.ok_or("helper did not return guest network handle")?;
            Ok(Self {
                config,
                id: id.into(),
                capture_tap: format!("amc{}", &suffix[..10]),
                inspection_tap: format!("ami{}", &suffix[..10]),
                guest_sender: Some(guest_sender),
                gate: None,
                active: true,
            })
        })();
        match result {
            Ok(lease) => Ok(lease),
            Err(error) => {
                if let Err(cleanup) =
                    privileged::request(json!({"command":"remove-network","id":id}))
                {
                    return Err(format!("network setup failed: {error}; cleanup: {cleanup}").into());
                }
                Err(error)
            }
        }
    }

    pub(super) fn start_policy(
        &mut self,
        backend: Backend,
        profile: String,
        run: String,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<()> {
        let guest = self
            .guest_sender
            .take()
            .ok_or("guest network handle was consumed")?;
        self.gate = Some(PacketGate::start(PacketGateConfig {
            network: &self.config,
            capture_tap: &self.capture_tap,
            inspection_tap: &self.inspection_tap,
            guest,
            backend,
            profile,
            run,
            cancelled,
            deadline,
        })?);
        Ok(())
    }

    pub(super) fn config(&self) -> &VmNetwork {
        &self.config
    }

    pub(super) fn remove(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.gate = None;
        privileged::request(json!({"command":"remove-network","id":self.id}))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for NetworkLease {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("network cleanup failed for {}: {error}", self.id);
        }
    }
}
