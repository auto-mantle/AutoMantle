use crate::{
    backend::Backend,
    hypervisor_api,
    proxy::Proxy,
    rootless,
    sandbox::{Result, RunRequest},
    vsock::VsockBridge,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

mod console;
pub(crate) mod host_command;
pub(crate) mod preflight;
use console::ConsolePump;
use host_command::checked;
pub use preflight::doctor;

const RUN_PREFIX: &str = "automantle-vm-";
pub enum RunEvent {
    State(&'static str),
    Console(Vec<u8>),
    Terminal(UnixStream),
}
pub type EventSink = Arc<dyn Fn(RunEvent) + Send + Sync>;

pub fn valid_run_id(id: &str) -> bool {
    run_suffix(id).is_ok()
}
pub(crate) fn run_suffix(id: &str) -> Result<&str> {
    let suffix = id.strip_prefix(RUN_PREFIX).ok_or("invalid run ID")?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid run ID".into());
    }
    Ok(suffix)
}
fn random_id_bytes() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn new_run_id() -> Result<String> {
    let bytes = random_id_bytes()?;
    Ok(format!(
        "{RUN_PREFIX}{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
pub(crate) fn new_uuid() -> Result<String> {
    let mut bytes = random_id_bytes()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
const MAX_IMAGE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CONSOLE: u64 = 16 * 1024 * 1024;

struct Run {
    id: String,
    directory: PathBuf,
    destroyed: bool,
    service_started: bool,
    console: Option<ConsolePump>,
    disk_directory: PathBuf,
    bridge: Option<VsockBridge>,
    proxy: Option<Proxy>,
    persistent_root: Option<PathBuf>,
}

impl Run {
    fn create(id: String) -> Result<Self> {
        if !valid_run_id(&id) {
            return Err("invalid run ID".into());
        }
        let (directory, disk_directory) = rootless::create_run(&id)?;
        Ok(Self {
            id,
            directory,
            disk_directory,
            destroyed: false,
            service_started: false,
            console: None,
            bridge: None,
            proxy: None,
            persistent_root: None,
        })
    }

    fn socket(&self) -> PathBuf {
        self.directory.join("api.sock")
    }

    fn vsock_cid(&self) -> Result<u32> {
        let suffix = run_suffix(&self.id)?;
        Ok(u32::from_str_radix(&suffix[..8], 16)?.max(3))
    }

    fn prepare(
        &mut self,
        request: &RunRequest,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<()> {
        if let Some(initramfs) = &request.initramfs {
            copy_image(
                initramfs,
                &self.disk_directory.join("initramfs"),
                true,
                cancelled,
                deadline,
            )?;
        }
        copy_image(
            &request.kernel,
            &self.disk_directory.join("kernel"),
            true,
            cancelled,
            deadline,
        )?;
        copy_image(
            &request.rootfs,
            &self.disk_directory.join("rootfs"),
            request.saved_disk.is_none(),
            cancelled,
            deadline,
        )?;
        if request.preparation {
            self.persistent_root = Some(request.rootfs.clone());
        }
        if let Some(template) = &request.scratch_template {
            copy_image(
                template,
                &self.disk_directory.join("scratch"),
                false,
                cancelled,
                deadline,
            )?;
        } else {
            let disk = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(self.disk_directory.join("scratch"))?;
            disk.set_len(request.scratch_mib * 1024 * 1024)?;
        }
        fs::write(
            self.disk_directory.join("vm.json"),
            serde_json::to_vec_pretty(
                &request.vm_config_rootless(
                    &self.directory,
                    &self.disk_directory,
                    request
                        .proxy_network
                        .then(|| self.vsock_cid())
                        .transpose()?,
                ),
            )?,
        )?;
        Ok(())
    }

    fn start(&mut self, request: &RunRequest, lifetime: Duration) -> Result<()> {
        rootless::start_vmm(
            &self.id,
            request,
            request.memory_mib,
            request.vcpus,
            lifetime,
        )?;
        self.service_started = true;
        Ok(())
    }

    fn state(&self) -> Result<String> {
        rootless::state(&self.id)
    }

    fn pump_console(&mut self) -> Result<()> {
        if let Some(proxy) = &self.proxy {
            proxy.check()?;
        }
        if let Some(bridge) = &self.bridge {
            bridge.check()?;
        }
        if let Some(reader) = self.console.take_if(|reader| reader.is_finished()) {
            reader.finish()?;
        }
        Ok(())
    }

    fn release_persistent_root(&mut self, clean: bool) -> Result<()> {
        let Some(source) = self.persistent_root.as_ref() else {
            return Ok(());
        };
        let parent = source.parent().ok_or("invalid saved disk path")?;
        let disk = self.disk_directory.join("rootfs");
        let destination = if clean {
            source.clone()
        } else {
            parent.join(format!("rootfs.{}.recovery", self.id))
        };
        File::open(&disk)?.sync_all()?;
        match fs::rename(&disk, &destination) {
            Ok(()) => (),
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                let staged = parent.join(format!("rootfs.{}.stage", self.id));
                let result = (|| -> Result<()> {
                    copy_image(
                        &disk,
                        &staged,
                        false,
                        &AtomicBool::new(false),
                        Instant::now() + Duration::from_secs(3600),
                    )?;
                    File::open(&staged)?.sync_all()?;
                    fs::rename(&staged, &destination)?;
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&staged);
                }
                result?;
            }
            Err(error) => return Err(error.into()),
        }
        File::open(parent)?.sync_all()?;
        if !clean {
            eprintln!(
                "run={} saved disk unchanged; recover VM writes from {}",
                self.id,
                destination.display()
            );
        }
        self.persistent_root = None;
        Ok(())
    }
    fn cleanup(&mut self, clean: bool) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        if let Some(proxy) = self.proxy.as_ref() {
            proxy.stop();
        }
        if let Some(bridge) = self.bridge.as_ref() {
            bridge.stop();
        }
        if self.service_started {
            rootless::stop_vmm(&self.id)?;
            self.service_started = false;
        }
        let mut errors = Vec::new();
        if let Err(error) = self.console.take().map_or(Ok(()), ConsolePump::finish) {
            errors.push(format!("console: {error}"));
        }
        self.bridge = None;
        self.proxy = None;
        if let Err(error) = self.release_persistent_root(clean) {
            errors.push(format!("saved disk: {error}"));
        }
        if self.persistent_root.is_none() {
            match rootless::destroy_run(&self.id) {
                Ok(()) => self.destroyed = true,
                Err(error) => errors.push(format!("run directory: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("cleanup failed: {}", errors.join("; ")).into())
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup(false) {
            eprintln!("cleanup failed for {}: {error}", self.id);
        }
    }
}

pub fn request_shutdown(id: &str) -> Result<()> {
    if !valid_run_id(id) {
        return Err("Invalid run ID".into());
    }
    hypervisor_api::request(
        rootless::connect_vmm(id, "api")?,
        "PUT",
        "vm.power-button",
        &[],
        Instant::now() + Duration::from_secs(2),
    )?;
    Ok(())
}

pub fn run(
    request: RunRequest,
    backend: Backend,
    id: String,
    cancelled: Arc<AtomicBool>,
    event: EventSink,
) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("VM launch must run through the unprivileged gateway".into());
    }
    backend.validate_profile(&request.agent_profile_id)?;
    preflight::check(&request.hypervisor, request.proxy_network)?;
    let lifetime = if request.timeout.is_zero() {
        Duration::from_secs(100 * 365 * 24 * 60 * 60)
    } else {
        request.timeout
    };
    let deadline = Instant::now() + lifetime;
    check_deadline(&cancelled, deadline)?;
    let tls = request
        .tls_ca_config
        .as_ref()
        .map(|path| crate::tls::Tls::load(path, deadline))
        .transpose()?;
    let credentials = request
        .credentials_config
        .as_ref()
        .map(|path| crate::credentials::Credentials::load(path))
        .transpose()?
        .unwrap_or_default();
    let credentials = if let Some(path) = &request.managed_credentials {
        credentials.with_managed(path.clone())
    } else {
        credentials
    };
    let mut vm = Run::create(id)?;
    let networking = request.proxy_network;
    if networking {
        let proxy_socket = vm.directory.join("proxy.sock");
        vm.proxy = Some(Proxy::start_unix(
            crate::proxy::ProxyConfig {
                backend,
                profile: request.agent_profile_id.clone(),
                tls,
                credentials,
                cancelled: Arc::clone(&cancelled),
                deadline,
                setup_mode: request.setup_mode,
            },
            &proxy_socket,
        )?);
        vm.bridge = Some(VsockBridge::start(
            &vm.directory.join("vsock"),
            &proxy_socket,
            Arc::clone(&cancelled),
            deadline,
        )?);
        eprintln!("run={} proxy=guest-loopback-vsock:3128", vm.id);
    }
    eprintln!(
        "run={} state=preparing network={}",
        vm.id,
        if networking {
            "controlled-http"
        } else {
            "disabled"
        }
    );
    event(RunEvent::State("preparing"));
    let result = (|| -> Result<()> {
        vm.prepare(&request, &cancelled, deadline)?;
        check_deadline(&cancelled, deadline)?;
        if let Some(bridge) = &vm.bridge {
            bridge.check()?;
        }
        vm.start(&request, deadline.saturating_duration_since(Instant::now()))?;
        let boot_deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        loop {
            check_deadline(&cancelled, boot_deadline)?;
            if rootless::connect_vmm(&vm.id, "api")
                .and_then(|socket| {
                    hypervisor_api::request(socket, "GET", "vmm.ping", &[], boot_deadline)
                })
                .is_ok()
            {
                break;
            }
            if vm.state()? == "failed" {
                return Err(format!(
                    "VMM failed to start; inspect journalctl --user -u {}",
                    vm.id
                )
                .into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        hypervisor_api::request(
            rootless::connect_vmm(&vm.id, "api")?,
            "PUT",
            "vm.create",
            &serde_json::to_vec(&request.vm_config_rootless(
                &vm.directory,
                &vm.disk_directory,
                request.proxy_network.then(|| vm.vsock_cid()).transpose()?,
            ))?,
            boot_deadline,
        )?;
        let serial = rootless::connect_vmm(&vm.id, "serial")?;
        serial.set_nonblocking(true)?;
        event(RunEvent::Terminal(serial.try_clone()?));
        vm.console = Some(ConsolePump::start(serial, Arc::clone(&event))?);
        hypervisor_api::request(
            rootless::connect_vmm(&vm.id, "api")?,
            "PUT",
            "vm.boot",
            &[],
            boot_deadline,
        )?;
        event(RunEvent::State("running"));
        eprintln!("run={} state=running api={}", vm.id, vm.socket().display());
        loop {
            check_deadline(&cancelled, deadline)?;
            vm.pump_console()?;
            let state = vm.state()?;
            if matches!(state.as_str(), "exited" | "dead" | "failed") {
                let output = checked(Command::new("/usr/bin/systemctl").args([
                    "--user",
                    "show",
                    &vm.id,
                    "--property=Result",
                    "--value",
                ]))?;
                let result = String::from_utf8(output.stdout)?;
                if state == "failed" || result.trim() != "success" {
                    return Err(format!(
                        "VMM stopped: {}; inspect journalctl --user -u {}",
                        result.trim(),
                        vm.id
                    )
                    .into());
                }
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        vm.pump_console()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = vm.pump_console();
    }
    let cleanup = vm.cleanup(result.is_ok());
    eprintln!(
        "run={} state={}",
        vm.id,
        if result.is_ok() && cleanup.is_ok() {
            "stopped"
        } else {
            "failed"
        }
    );
    match (result, cleanup) {
        (Err(run), Err(cleanup)) => Err(format!("{run}; cleanup: {cleanup}").into()),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

fn check_deadline(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        return Err("run interrupted".into());
    }
    if Instant::now() >= deadline {
        return Err("sandbox execution exceeded its timeout".into());
    }
    Ok(())
}

pub(crate) fn copy_image(
    source: &Path,
    destination: &Path,
    readonly: bool,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    let meta = input.metadata()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_IMAGE {
        return Err(format!(
            "{} must be a nonempty regular image, at most 64 GiB",
            source.display()
        )
        .into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut copied = 0;
    loop {
        check_deadline(cancelled, deadline)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > meta.len() {
            return Err("source image changed while copying".into());
        }
        if buffer[..count].iter().all(|b| *b == 0) {
            output.seek(SeekFrom::Current(count as i64))?;
        } else {
            output.write_all(&buffer[..count])?;
        }
    }
    if copied != meta.len() {
        return Err("source image changed while copying".into());
    }
    output.set_len(copied)?;
    output.set_permissions(fs::Permissions::from_mode(if readonly {
        0o444
    } else {
        0o600
    }))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{new_uuid, run_suffix};

    #[test]
    fn run_suffix_requires_a_complete_hex_identifier() {
        let id = "automantle-vm-0123456789abcdef0123456789abcdef";
        assert_eq!(run_suffix(id).unwrap(), "0123456789abcdef0123456789abcdef");
        assert!(run_suffix("automantle-vm-0123456789abcdef").is_err());
        assert!(run_suffix("automantle-vm-0123456789abcdef0123456789abcdeg").is_err());
        assert!(run_suffix("vm-0123456789abcdef0123456789abcdef").is_err());
    }

    #[test]
    fn saved_disk_commits_on_clean_stop_and_preserves_recovery_on_failure() {
        use super::Run;
        use std::fs;
        let base =
            std::env::temp_dir().join(format!("automantle-disk-test-{}", std::process::id()));
        let saved = base.join("saved");
        let run = base.join("run");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&saved).unwrap();
        fs::create_dir(&run).unwrap();
        let source = saved.join("rootfs");
        let private = run.join("rootfs");
        fs::write(&source, b"original").unwrap();
        fs::write(&private, b"updated").unwrap();
        let mut vm = Run {
            id: "automantle-vm-0123456789abcdef0123456789abcdef".into(),
            directory: base.clone(),
            destroyed: true,
            service_started: false,
            console: None,
            disk_directory: run.clone(),
            bridge: None,
            proxy: None,
            persistent_root: Some(source.clone()),
        };
        vm.release_persistent_root(true).unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"updated");
        assert!(!private.exists());
        fs::write(&private, b"recoverable").unwrap();
        vm.persistent_root = Some(source.clone());
        vm.release_persistent_root(false).unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"updated");
        assert_eq!(
            fs::read(saved.join(format!("rootfs.{}.recovery", vm.id))).unwrap(),
            b"recoverable"
        );
        fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn generated_uuid_has_v4_version_and_variant() {
        let id = new_uuid().unwrap();
        assert!(crate::sandbox::valid_uuid(&id));
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(b"89ab".contains(&id.as_bytes()[19]));
    }
}
