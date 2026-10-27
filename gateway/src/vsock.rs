use crate::sandbox::Result;
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const PROXY_PORT: &str = "_3128";
const MAX_CONNECTIONS: usize = 16;

pub struct VsockBridge {
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    socket: PathBuf,
}
impl VsockBridge {
    pub fn start(
        vsock_base: &Path,
        proxy_socket: &Path,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self> {
        let mut name: OsString = vsock_base.as_os_str().to_owned();
        name.push(PROXY_PORT);
        let socket = PathBuf::from(name);
        let listener = UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let target = proxy_socket.to_owned();
        let worker = thread::Builder::new()
            .name("vm-vsock-bridge".into())
            .spawn(move || {
                let mut connections: Vec<JoinHandle<()>> = Vec::new();
                while !stop.load(Ordering::Relaxed)
                    && !cancelled.load(Ordering::Relaxed)
                    && Instant::now() < deadline
                {
                    connections.retain(|connection| !connection.is_finished());
                    match listener.accept() {
                        Ok((guest, _)) if connections.len() < MAX_CONNECTIONS => {
                            let target = target.clone();
                            let stop = Arc::clone(&stop);
                            let cancelled = Arc::clone(&cancelled);
                            if let Ok(connection) = thread::Builder::new()
                                .name("vm-vsock-stream".into())
                                .spawn(move || {
                                    if let Err(error) =
                                        connect(guest, &target, stop, cancelled, deadline)
                                    {
                                        eprintln!("VSOCK bridge connection failed: {error}");
                                    }
                                })
                            {
                                connections.push(connection);
                            }
                        }
                        Ok((guest, _)) => {
                            let _ = guest.shutdown(Shutdown::Both);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            eprintln!("VSOCK bridge accept failed: {error}");
                            break;
                        }
                    }
                }
                stop.store(true, Ordering::Relaxed);
                for connection in connections {
                    let _ = connection.join();
                }
            })?;
        Ok(Self {
            stopped,
            worker: Some(worker),
            socket,
        })
    }

    pub fn check(&self) -> Result<()> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err("VSOCK bridge stopped unexpectedly".into());
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
}
impl Drop for VsockBridge {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.socket);
    }
}

fn connect(
    guest: UnixStream,
    target: &Path,
    stopped: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<()> {
    let proxy = UnixStream::connect(target)?;
    let guest_reader = guest.try_clone()?;
    let proxy_writer = proxy.try_clone()?;
    let stop = Arc::clone(&stopped);
    let cancel = Arc::clone(&cancelled);
    let upstream = thread::spawn(move || {
        relay(guest_reader, proxy_writer, stop, cancel, deadline);
    });
    relay(proxy, guest, stopped, cancelled, deadline);
    let _ = upstream.join();
    Ok(())
}

fn relay(
    mut source: UnixStream,
    mut target: UnixStream,
    stopped: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) {
    let _ = source.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = target.set_write_timeout(Some(Duration::from_millis(250)));
    let mut bytes = [0_u8; 8192];
    while !stopped.load(Ordering::Relaxed)
        && !cancelled.load(Ordering::Relaxed)
        && Instant::now() < deadline
    {
        match source.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) if target.write_all(&bytes[..count]).is_ok() => {}
            Ok(_) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    let _ = target.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt};

    #[test]
    fn guest_stream_reaches_only_the_private_proxy_socket() {
        let directory =
            std::env::temp_dir().join(format!("automantle-vsock-test-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let proxy = directory.join("proxy.sock");
        let listener = UnixListener::bind(&proxy).unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = directory.join("vsock");
        let bridge = VsockBridge::start(
            &base,
            &proxy,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let mut guest = UnixStream::connect(directory.join("vsock_3128")).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        guest.write_all(b"guest request").unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(2);
        let (mut host, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && Instant::now() < accept_deadline =>
                {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("VSOCK bridge did not connect to proxy: {error}"),
            }
        };
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut received = [0u8; 13];
        host.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"guest request");
        host.write_all(b"host response").unwrap();
        let mut reply = [0u8; 13];
        guest.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"host response");
        drop(guest);
        drop(host);
        drop(bridge);
        drop(listener);
        fs::remove_file(&proxy).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
