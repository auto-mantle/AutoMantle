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

#[cfg(test)]
impl RequestMonitor for Vec<u8> {
    fn end_reason(&mut self) -> Option<EndReason> {
        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn inactivity_does_not_imply_expiration_and_stream_events_are_generic() {
        let stopped = AtomicBool::new(false);
        let cancelled = AtomicBool::new(false);
        let request = RequestLifecycle::new(
            &stopped,
            &cancelled,
            Instant::now() + Duration::from_secs(30),
        );
        assert_eq!(request.end_reason(&mut || None), None);
        assert_eq!(
            request.end_reason(&mut || Some(EndReason::RequestCancelled)),
            Some(EndReason::RequestCancelled)
        );
        assert_eq!(
            request.end_reason(&mut || None),
            Some(EndReason::RequestCancelled)
        );
    }
    #[test]
    fn host_cancellation_is_distinct_from_client_closure() {
        let stopped = AtomicBool::new(false);
        let cancelled = AtomicBool::new(true);
        let request = RequestLifecycle::new(
            &stopped,
            &cancelled,
            Instant::now() + Duration::from_secs(30),
        );
        assert_eq!(
            request.end_reason(&mut || None),
            Some(EndReason::RequestCancelled)
        );
    }
}
