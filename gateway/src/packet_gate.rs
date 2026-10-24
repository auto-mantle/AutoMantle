use crate::{
    backend::Backend,
    network_policy::{Decision, Metadata, NetworkPolicy, audit_event},
    sandbox::{Result, VmNetwork},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub struct PacketGate {
    stop: Arc<AtomicBool>,
    received: Arc<AtomicU64>,
    failed: Arc<AtomicBool>,
    worker: Option<JoinHandle<std::result::Result<(), String>>>,
}
pub(crate) struct PacketGateConfig<'a> {
    pub network: &'a VmNetwork,
    pub capture_tap: &'a str,
    pub inspection_tap: &'a str,
    pub guest: File,
    pub backend: Backend,
    pub profile: String,
    pub run: String,
    pub cancelled: Arc<AtomicBool>,
    pub deadline: Instant,
}
pub(crate) fn open_tap(name: &str) -> Result<File> {
    if name.len() >= libc::IFNAMSIZ || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid policy interface name".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &request) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
pub(crate) fn guest_sender(name: &str) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_ifindex = index as i32;
    if unsafe {
        libc::bind(
            fd,
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
fn send_frame(file: &mut File, frame: &[u8]) -> Result<()> {
    let written = file.write(frame)?;
    if written != frame.len() {
        return Err("partial Ethernet frame write".into());
    }
    Ok(())
}
type Counts = BTreeMap<(Decision, Metadata), (u64, u64)>;
fn flush(
    counts: &mut Counts,
    sender: &SyncSender<Vec<Value>>,
    profile: &str,
    run: &str,
) -> Result<()> {
    if counts.is_empty() {
        return Ok(());
    }
    let events = counts
        .iter()
        .map(|((decision, meta), (packets, bytes))| {
            audit_event(profile, run, *decision, meta, *packets, *bytes)
        })
        .collect::<Result<Vec<_>>>()?;
    counts.clear();
    if let Err(error) = sender.try_send(events) {
        let events = match error {
            mpsc::TrySendError::Full(v) | mpsc::TrySendError::Disconnected(v) => v,
        };
        for event in events {
            eprintln!("network-policy {event}");
        }
        return Err("network audit unavailable or overloaded".into());
    }
    Ok(())
}

fn dropped_packets(path: &str) -> Result<u64> {
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}

fn capture_frames(
    capture: &mut File,
    inspection: &mut File,
    policy: &NetworkPolicy,
    counts: &mut Counts,
    received: &AtomicU64,
) -> Result<()> {
    let mut bytes = [0u8; 65536];
    for _ in 0..64 {
        let count = match capture.read(&mut bytes) {
            Ok(0) => return Err("network policy interface closed".into()),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        };
        received.fetch_add(1, Ordering::Relaxed);
        let frame = &bytes[..count];
        let (decision, metadata) = policy.evaluate(frame);
        let entry = counts.entry((decision, metadata)).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += count as u64;
        if decision.passes() {
            send_frame(inspection, frame)?;
        }
    }
    Ok(())
}

fn relay_frames(inspection: &mut File, guest: &mut File) -> Result<()> {
    let mut bytes = [0u8; 65536];
    for _ in 0..64 {
        match inspection.read(&mut bytes) {
            Ok(0) => return Err("inspection interface closed".into()),
            Ok(count) => send_frame(guest, &bytes[..count])?,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn check_capture_loss(
    paths: &[String; 2],
    baseline: &[u64; 2],
    run: &str,
    received: &AtomicU64,
) -> Result<()> {
    for (path, old) in paths.iter().zip(baseline) {
        let dropped = dropped_packets(path)?;
        if dropped > *old {
            eprintln!(
                "network-policy run={run} capture_loss={} observed_packets={}",
                dropped - old,
                received.load(Ordering::Relaxed)
            );
            return Err("kernel packet capture lost frames; stopping VM".into());
        }
    }
    Ok(())
}

impl PacketGate {
    pub(crate) fn start(config: PacketGateConfig<'_>) -> Result<Self> {
        let PacketGateConfig {
            network,
            capture_tap,
            inspection_tap,
            mut guest,
            backend,
            profile,
            run,
            cancelled,
            deadline,
        } = config;
        let policy = NetworkPolicy::new(network)?;
        let mut capture = open_tap(capture_tap)?;
        let mut inspection = open_tap(inspection_tap)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let failed = Arc::new(AtomicBool::new(false));
        let failure = Arc::clone(&failed);
        let received = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&received);
        let dropped_paths = [
            format!("/sys/class/net/{capture_tap}/statistics/tx_dropped"),
            format!("/sys/class/net/{}/statistics/rx_dropped", network.tap),
        ];
        let worker = thread::Builder::new()
            .name("vm-network-policy".into())
            .spawn(move || {
                let (sender, receiver) = mpsc::sync_channel::<Vec<Value>>(16);
                let logger = thread::Builder::new()
                    .name("vm-network-audit".into())
                    .spawn(move || {
                        for events in receiver {
                            for event in &events {
                                eprintln!("network-policy {event}");
                            }
                            backend.report_network_history(&events);
                        }
                    })
                    .map_err(|error| error.to_string())?;
                let mut counts = Counts::new();
                let result = (|| -> Result<()> {
                    let baseline = [
                        dropped_packets(&dropped_paths[0])?,
                        dropped_packets(&dropped_paths[1])?,
                    ];
                    let mut last_flush = Instant::now();
                    while !stopping.load(Ordering::Relaxed)
                        && !cancelled.load(Ordering::Relaxed)
                        && Instant::now() < deadline
                    {
                        let mut polls = [
                            libc::pollfd {
                                fd: capture.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            },
                            libc::pollfd {
                                fd: inspection.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            },
                        ];
                        if unsafe {
                            libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 50)
                        } < 0
                        {
                            let error = std::io::Error::last_os_error();
                            if error.kind() == std::io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(error.into());
                        }
                        if polls.iter().any(|poll| {
                            poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                        }) {
                            return Err("network policy interface lost".into());
                        }
                        if polls[0].revents & libc::POLLIN != 0 {
                            capture_frames(
                                &mut capture,
                                &mut inspection,
                                &policy,
                                &mut counts,
                                &counter,
                            )?;
                            if counts.len() >= 128 {
                                flush(&mut counts, &sender, &profile, &run)?;
                                last_flush = Instant::now();
                            }
                        }
                        if polls[1].revents & libc::POLLIN != 0 {
                            relay_frames(&mut inspection, &mut guest)?;
                        }
                        if last_flush.elapsed() >= Duration::from_secs(1) {
                            check_capture_loss(&dropped_paths, &baseline, &run, &counter)?;
                            flush(&mut counts, &sender, &profile, &run)?;
                            last_flush = Instant::now();
                        }
                    }
                    Ok(())
                })();
                let flushed = flush(&mut counts, &sender, &profile, &run);
                drop(sender);
                let logged = logger
                    .join()
                    .map_err(|_| "network audit worker panicked".to_string());
                if result.is_err() || flushed.is_err() || logged.is_err() {
                    failure.store(true, Ordering::Relaxed);
                }
                result
                    .and(flushed)
                    .map_err(|error| error.to_string())
                    .and(logged)
            })?;
        Ok(Self {
            stop,
            received,
            failed,
            worker: Some(worker),
        })
    }
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
    pub fn check(&self) -> Result<()> {
        if self.failed.load(Ordering::Relaxed)
            || self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
        {
            return Err(format!(
                "network policy worker stopped after {} frames",
                self.received()
            )
            .into());
        }
        Ok(())
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
impl Drop for PacketGate {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take()
            && let Err(error) = worker
                .join()
                .unwrap_or_else(|_| Err("network policy worker panicked".into()))
        {
            eprintln!("network-policy failure={error}");
        }
    }
}
