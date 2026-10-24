use crate::request_lifecycle::EndReason;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Socket {
    inner: TcpStream,
    stopped: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    lifetime: Instant,
    phase: Instant,
}
impl Socket {
    pub fn new(
        inner: TcpStream,
        stopped: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
        lifetime: Instant,
        phase: Duration,
    ) -> io::Result<Self> {
        inner.set_read_timeout(Some(Duration::from_millis(250)))?;
        inner.set_write_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self {
            inner,
            stopped,
            cancelled,
            lifetime,
            phase: Instant::now() + phase,
        })
    }
    pub fn phase(&mut self, duration: Duration) {
        self.phase = Instant::now() + duration;
    }
    pub fn waiting_for_policy(&mut self) {
        self.phase = self.lifetime;
    }
    pub fn finish(&mut self) {
        let _ = self.inner.shutdown(std::net::Shutdown::Write);
        self.phase = Instant::now() + Duration::from_millis(500);
        let mut remaining = 128 * 1024;
        let mut buffer = [0_u8; 8192];
        while remaining > 0 && self.check().is_ok() {
            let size = buffer.len().min(remaining);
            match self.inner.read(&mut buffer[..size]) {
                Ok(0) | Err(_) => break,
                Ok(count) => remaining -= count,
            }
        }
    }

    pub fn peer_end_reason(&self) -> Option<EndReason> {
        let mut event = libc::pollfd {
            fd: self.inner.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 {
            return (io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
                .then_some(EndReason::TransportError);
        }
        if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Some(match self.inner.take_error() {
                Ok(Some(error)) if error.kind() == io::ErrorKind::ConnectionReset => {
                    EndReason::ConnectionReset
                }
                _ => EndReason::TransportError,
            });
        }
        (event.revents & (libc::POLLRDHUP | libc::POLLHUP) != 0).then_some(EndReason::ClientClosed)
    }

    pub fn read_available(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = unsafe {
            libc::recv(
                self.inner.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.stopped.load(Ordering::Relaxed) || self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request cancelled",
            ));
        }
        if Instant::now() >= self.lifetime.min(self.phase) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline exceeded",
            ));
        }
        Ok(())
    }
}
fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.inner.read(bytes) {
                Err(e) if retry(&e) => continue,
                result => return result,
            }
        }
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.inner.write(bytes) {
                Err(e) if retry(&e) => continue,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}
