use std::{
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    ClientClosed,
    ConnectionReset,
    TransportError,
    RequestCancelled,
    RequestDeadlineExceeded,
    GatewayStopped,
    RequestNotExecuted,
}
impl EndReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::ClientClosed => "CLIENT_CLOSED",
            Self::ConnectionReset => "CONNECTION_RESET",
            Self::TransportError => "TRANSPORT_ERROR",
            Self::RequestCancelled => "REQUEST_CANCELLED",
            Self::RequestDeadlineExceeded => "REQUEST_DEADLINE_EXCEEDED",
            Self::GatewayStopped => "GATEWAY_STOPPED",
            Self::RequestNotExecuted => "REQUEST_NOT_EXECUTED",
        }
    }
}

pub trait RequestMonitor {
    fn end_reason(&mut self) -> Option<EndReason>;
}
impl<F: FnMut() -> Option<EndReason>> RequestMonitor for F {
    fn end_reason(&mut self) -> Option<EndReason> {
        self()
    }
}

pub struct RequestLifecycle<'a> {
    stopped: &'a AtomicBool,
    cancelled: &'a AtomicBool,
    deadline: Instant,
    ended: Cell<Option<EndReason>>,
}
impl<'a> RequestLifecycle<'a> {
    pub fn new(stopped: &'a AtomicBool, cancelled: &'a AtomicBool, deadline: Instant) -> Self {
        Self {
            stopped,
            cancelled,
            deadline,
            ended: Cell::new(None),
        }
    }
    pub fn host_active(&self) -> bool {
        self.host_reason().is_none() && self.ended.get().is_none()
    }
    fn host_reason(&self) -> Option<EndReason> {
        if self.stopped.load(Ordering::Relaxed) {
            Some(EndReason::GatewayStopped)
        } else if self.cancelled.load(Ordering::Relaxed) {
            Some(EndReason::RequestCancelled)
        } else if Instant::now() >= self.deadline {
            Some(EndReason::RequestDeadlineExceeded)
        } else {
            None
        }
    }
    pub fn end_reason(&self, monitor: &mut dyn RequestMonitor) -> Option<EndReason> {
        let reason = self
            .ended
            .get()
            .or_else(|| self.host_reason())
            .or_else(|| monitor.end_reason());
        self.ended.set(reason);
        reason
    }
}
