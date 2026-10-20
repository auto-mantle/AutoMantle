use super::{EventSink, MAX_CONSOLE, RunEvent};
use crate::sandbox::Result;
use std::{
    io::Read,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

pub(super) struct ConsolePump {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
}
impl ConsolePump {
    pub(super) fn start(mut stream: UnixStream, event: EventSink) -> Result<Self> {
        stream.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("vm-console".into())
            .spawn(move || {
                let mut total = 0u64;
                let mut bytes = [0u8; 8192];
                loop {
                    match stream.read(&mut bytes) {
                        Ok(0) => return Ok(()),
                        Ok(count) => {
                            total += count as u64;
                            if total > MAX_CONSOLE {
                                return Err("guest console exceeded 16 MiB".into());
                            }
                            event(RunEvent::Console(bytes[..count].to_vec()));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopping.load(Ordering::Relaxed) {
                                return Ok(());
                            }
                            let mut poll = libc::pollfd {
                                fd: stream.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            if unsafe { libc::poll(&mut poll, 1, 20) } < 0 {
                                let error = std::io::Error::last_os_error();
                                if error.kind() != std::io::ErrorKind::Interrupted {
                                    return Err(error.to_string());
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Ok(()),
                        Err(e) => return Err(e.to_string()),
                    }
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
    pub(super) fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
    }
    pub(super) fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .take()
            .ok_or("console reader already finished")?
            .join()
            .map_err(|_| "console reader panicked")?
            .map_err(|e| e.into())
    }
}
impl Drop for ConsolePump {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
