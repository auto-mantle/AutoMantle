use crate::request_lifecycle::EndReason;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    os::{
        fd::{AsRawFd, RawFd},
        unix::net::UnixStream,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}
impl From<TcpStream> for Stream {
    fn from(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }
}
impl From<UnixStream> for Stream {
    fn from(stream: UnixStream) -> Self {
        Self::Unix(stream)
    }
}
impl Stream {
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            Self::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_write_timeout(timeout),
            Self::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(how),
            Self::Unix(stream) => stream.shutdown(how),
        }
    }
    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            Self::Tcp(stream) => stream.take_error(),
            Self::Unix(stream) => stream.take_error(),
        }
    }
}
impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(stream) => stream.as_raw_fd(),
            Self::Unix(stream) => stream.as_raw_fd(),
        }
    }
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(bytes),
            Self::Unix(stream) => stream.read(bytes),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            Self::Unix(stream) => stream.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::Unix(stream) => stream.flush(),
        }
    }
}

pub struct Socket {
    inner: Stream,
    stopped: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    lifetime: Instant,
    phase: Instant,
}
impl Socket {
    pub fn new(
        inner: impl Into<Stream>,
        stopped: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
        lifetime: Instant,
        phase: Duration,
    ) -> io::Result<Self> {
        let inner = inner.into();
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
        let _ = self.inner.shutdown(Shutdown::Write);
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
