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
fn guest_sender(name: &str) -> Result<File> {
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
    let events = std::mem::take(counts)
        .into_iter()
        .map(|((decision, meta), (packets, bytes))| {
            audit_event(profile, run, decision, &meta, packets, bytes)
        })
        .collect::<Vec<_>>();
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
impl PacketGate {
    pub fn start(
        network: &VmNetwork,
        capture_tap: &str,
        inspection_tap: &str,
        backend: Backend,
        profile: String,
        run: String,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self> {
        let policy = NetworkPolicy::new(network)?;
        let mut capture = open_tap(capture_tap)?;
        let mut inspection = open_tap(inspection_tap)?;
        let mut guest = guest_sender(&network.tap)?;
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
        let worker = thread::Builder::new().name("vm-network-policy".into()).spawn(move || {
            let (sender, receiver) = mpsc::sync_channel::<Vec<Value>>(16);
            let logger = thread::Builder::new().name("vm-network-audit".into()).spawn(move || {
                for events in receiver {
                    for event in &events { eprintln!("network-policy {event}"); }
                    backend.report_network_history(&events);
                }
            }).map_err(|e|e.to_string())?;
            let mut counts = Counts::new(); let mut last_flush = Instant::now();
            let baseline = dropped_paths.iter().map(|path| std::fs::read_to_string(path).map_err(|e|e.to_string()).and_then(|s|s.trim().parse::<u64>().map_err(|e|e.to_string()))).collect::<std::result::Result<Vec<_>, _>>()?;
            let mut bytes = [0u8; 65536];
            let result = (|| -> Result<()> {
                while !stopping.load(Ordering::Relaxed) && !cancelled.load(Ordering::Relaxed) && Instant::now() < deadline {
                    let mut polls = [libc::pollfd {fd:capture.as_raw_fd(),events:libc::POLLIN,revents:0},
                        libc::pollfd {fd:inspection.as_raw_fd(),events:libc::POLLIN,revents:0}];
                    if unsafe { libc::poll(polls.as_mut_ptr(),2,50) } < 0 {
                        let error=std::io::Error::last_os_error(); if error.kind()==std::io::ErrorKind::Interrupted {continue;} return Err(error.into());
                    }
                    if polls.iter().any(|p| p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0) {return Err("network policy interface lost".into());}
                    if polls[0].revents & libc::POLLIN != 0 {
                        for _ in 0..64 {
                            let count = match capture.read(&mut bytes) {
                                Ok(0) => return Err("network policy interface closed".into()), Ok(n)=>n,
                                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>break, Err(e)=>return Err(e.into()) };
                            counter.fetch_add(1,Ordering::Relaxed);
                            let frame=&bytes[..count]; let (decision,meta)=policy.evaluate(frame);
                            let entry=counts.entry((decision,meta)).or_insert((0,0)); entry.0+=1;entry.1+=count as u64;
                            if decision.passes() {send_frame(&mut inspection,frame)?;}
                            if counts.len()>=128 {flush(&mut counts,&sender,&profile,&run)?;last_flush=Instant::now();}
                        }
                    }
                    if polls[1].revents & libc::POLLIN != 0 {
                        for _ in 0..64 {
                            match inspection.read(&mut bytes) { Ok(0)=>return Err("inspection interface closed".into()),
                                Ok(n)=>send_frame(&mut guest,&bytes[..n])?,
                                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>break,Err(e)=>return Err(e.into()) }
                        }
                    }
                    if last_flush.elapsed()>=Duration::from_secs(1) {
                        for (path, old) in dropped_paths.iter().zip(&baseline) {
                            let dropped=std::fs::read_to_string(path)?.trim().parse::<u64>()?;
                            if dropped > *old { eprintln!("network-policy run={run} capture_loss={} observed_packets={}", dropped-old,counter.load(Ordering::Relaxed));
                                return Err("kernel packet capture lost frames; stopping VM".into()); }
                        }
                        flush(&mut counts,&sender,&profile,&run)?;last_flush=Instant::now();
                    }
                }
                Ok(())
            })();
            if result.is_err() {failure.store(true,Ordering::Relaxed);}
            let flushed=flush(&mut counts,&sender,&profile,&run);
            if flushed.is_err() {failure.store(true,Ordering::Relaxed); }
            drop(sender);
            let logged=logger.join().map_err(|_|"network audit worker panicked".to_string());
            if logged.is_err() {failure.store(true,Ordering::Relaxed); }
            result.and(flushed).map_err(|e|e.to_string()).and(logged)
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
        if let Some(worker) = self.worker.take() {
            if let Err(error) = worker
                .join()
                .unwrap_or_else(|_| Err("network policy worker panicked".into()))
            {
                eprintln!("network-policy failure={error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_failure_is_visible_before_audit_worker_finishes() {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let gate = PacketGate {
            stop,
            received: Arc::new(AtomicU64::new(7)),
            failed: Arc::new(AtomicBool::new(true)),
            worker: Some(thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(())
            })),
        };
        assert!(!gate.worker.as_ref().unwrap().is_finished());
        assert!(gate.check().is_err());
    }
}
