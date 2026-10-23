use crate::{
    backend::Backend,
    hypervisor_api,
    proxy::Proxy,
    sandbox::{Result, RunRequest},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
mod host_command;
mod network;
mod preflight;
use console::ConsolePump;
use host_command::{checked, command};
use network::HostNetwork;
pub use preflight::doctor;

const RUN_PREFIX: &str = "automantle-vm-";
pub enum RunEvent {
    State(&'static str),
    Console(Vec<u8>),
    Terminal(UnixStream),
}
pub type EventSink = Arc<dyn Fn(RunEvent) + Send + Sync>;

pub fn valid_run_id(id: &str) -> bool {
    id.strip_prefix(RUN_PREFIX)
        .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
pub fn new_run_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!(
        "{RUN_PREFIX}{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
const MAX_IMAGE: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CONSOLE: u64 = 16 * 1024 * 1024;

struct Run {
    id: String,
    service_user: String,
    directory: PathBuf,
    service_started: bool,
    console: Option<ConsolePump>,
    network: Option<HostNetwork>,
    proxy: Option<Proxy>,
    persistent_root: Option<PathBuf>,
    runtime_root: Option<PathBuf>,
}

impl Run {
    fn create(id: String) -> Result<Self> {
        if !valid_run_id(&id) {
            return Err("invalid run ID".into());
        }
        let directory = Path::new("/run").join(&id);
        let suffix = id
            .strip_prefix(RUN_PREFIX)
            .ok_or("invalid generated run ID")?;
        let service_user = format!("amv{}", &suffix[..10]);
        checked(Command::new("/usr/sbin/useradd").args([
            "--system",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            "--groups",
            "kvm",
            &service_user,
        ]))?;
        if let Err(error) = fs::create_dir(&directory) {
            let _ = command(Command::new("/usr/sbin/userdel").arg(&service_user));
            return Err(error.into());
        }
        if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(&directory);
            let _ = command(Command::new("/usr/sbin/userdel").arg(&service_user));
            return Err(error.into());
        }
        Ok(Self {
            id,
            service_user,
            directory,
            service_started: false,
            console: None,
            network: None,
            proxy: None,
            persistent_root: None,
            runtime_root: None,
        })
    }

    fn socket(&self) -> PathBuf {
        self.directory.join("api.sock")
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
                &self.directory.join("initramfs"),
                true,
                cancelled,
                deadline,
            )?;
        }
        copy_image(
            &request.kernel,
            &self.directory.join("kernel"),
            true,
            cancelled,
            deadline,
        )?;
        if request.saved_disk.is_some() {
            let source = if request.preparation {
                request.rootfs.clone()
            } else {
                let path = request
                    .rootfs
                    .parent()
                    .ok_or("invalid saved disk path")?
                    .join(format!("{}.runtime", self.id));
                self.runtime_root = Some(path.clone());
                copy_image(&request.rootfs, &path, false, cancelled, deadline)?;
                path
            };
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(self.directory.join("rootfs"))?;
            self.persistent_root = Some(source.clone());
            checked(
                Command::new("/usr/bin/mount")
                    .arg("--bind")
                    .arg(&source)
                    .arg(self.directory.join("rootfs")),
            )?;
        } else {
            copy_image(
                &request.rootfs,
                &self.directory.join("rootfs"),
                request.saved_disk.is_none(),
                cancelled,
                deadline,
            )?;
        }
        if let Some(template) = &request.scratch_template {
            copy_image(
                template,
                &self.directory.join("scratch"),
                false,
                cancelled,
                deadline,
            )?;
        } else {
            let disk = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(self.directory.join("scratch"))?;
            disk.set_len(request.scratch_mib * 1024 * 1024)?;
        }
        fs::write(
            self.directory.join("vm.json"),
            serde_json::to_vec_pretty(&request.vm_config(
                &self.directory,
                self.network.as_ref().map(HostNetwork::config),
            ))?,
        )?;
        let uid = checked(Command::new("/usr/bin/id").args(["-u", &self.service_user]))?;
        let gid = checked(Command::new("/usr/bin/id").args(["-g", &self.service_user]))?;
        let uid = String::from_utf8(uid.stdout)?.trim().parse::<u32>()?;
        let gid = String::from_utf8(gid.stdout)?.trim().parse::<u32>()?;
        for path in [
            self.directory.clone(),
            self.directory.join("kernel"),
            self.directory.join("rootfs"),
            self.directory.join("scratch"),
            self.directory.join("vm.json"),
        ] {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if request.initramfs.is_some() {
            let path =
                std::ffi::CString::new(self.directory.join("initramfs").as_os_str().as_bytes())?;
            if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    fn start(&mut self, request: &RunRequest, lifetime: Duration) -> Result<()> {
        let mut cmd = Command::new("/usr/bin/systemd-run");
        cmd.args(["--quiet", "--service-type=exec", "--unit", &self.id]);
        let with_network = self.network.is_some();
        for property in [
            format!("User={}", self.service_user),
            "DynamicUser=no".into(),
            "SupplementaryGroups=kvm".into(),
            format!("RuntimeDirectory={}", self.id),
            "RuntimeDirectoryMode=0700".into(),
            "RuntimeDirectoryPreserve=yes".into(),
            "UMask=0077".into(),
            "RemainAfterExit=yes".into(),
            format!("PrivateNetwork={}", if with_network { "no" } else { "yes" }),
            format!(
                "RestrictAddressFamilies={}",
                if with_network {
                    "AF_UNIX AF_INET"
                } else {
                    "AF_UNIX"
                }
            ),
            "ProtectSystem=strict".into(),
            "ProtectHome=yes".into(),
            "NoNewPrivileges=yes".into(),
            "CapabilityBoundingSet=".into(),
            "ProtectKernelTunables=yes".into(),
            "ProtectKernelModules=yes".into(),
            "ProtectControlGroups=yes".into(),
            "RestrictSUIDSGID=yes".into(),
            "ProtectProc=invisible".into(),
            "DevicePolicy=closed".into(),
            "DeviceAllow=/dev/kvm rw".into(),
            "LimitCORE=0".into(),
            format!(
                "LimitFSIZE={}",
                fs::metadata(self.directory.join("rootfs"))?
                    .len()
                    .max(1024 * 1024 * 1024)
            ),
            "KillMode=control-group".into(),
            "TimeoutStopSec=3s".into(),
            if request.timeout.is_zero() {
                "RuntimeMaxSec=infinity".into()
            } else {
                format!("RuntimeMaxSec={}s", lifetime.as_secs().max(1))
            },
            format!("MemoryMax={}M", request.memory_mib + 256),
            "MemorySwapMax=0".into(),
            format!("CPUQuota={}%", request.vcpus * 100),
            format!("TasksMax={}", request.vcpus * 2 + 64),
            format!(
                "ReadOnlyPaths={}/kernel {}/vm.json{}",
                self.directory.display(),
                self.directory.display(),
                if request.saved_disk.is_none() {
                    format!(" {}/rootfs", self.directory.display())
                } else {
                    String::new()
                }
            ),
            "StandardOutput=null".into(),
            "StandardError=journal".into(),
        ] {
            cmd.arg("--property").arg(property);
        }
        if with_network {
            cmd.arg("--property").arg("DeviceAllow=/dev/net/tun rw");
        }
        if request.initramfs.is_some() {
            cmd.arg("--property").arg(format!(
                "ReadOnlyPaths={}/initramfs",
                self.directory.display()
            ));
        }
        cmd.arg("--")
            .arg(fs::canonicalize(&request.hypervisor)?)
            .arg("--api-socket")
            .arg(self.socket())
            .args(["--seccomp", "true"]);
        self.service_started = true;
        checked(&mut cmd)?;
        Ok(())
    }

    fn state(&self) -> Result<String> {
        let output = checked(Command::new("/usr/bin/systemctl").args([
            "show",
            &self.id,
            "--property=SubState",
            "--value",
        ]))?;
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }

    fn pump_console(&mut self) -> Result<()> {
        if let Some(gate) = self.network.as_ref().and_then(|n| n.gate.as_ref()) {
            gate.check()?;
        }
        if let Some(reader) = self.console.take_if(|reader| reader.is_finished()) {
            reader.finish()?;
        }
        Ok(())
    }

    fn release_persistent_root(&mut self) -> Result<()> {
        let Some(source) = &self.persistent_root else {
            return Ok(());
        };
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(source)?
            .sync_all()?;
        let path = std::ffi::CString::new(source.as_os_str().as_bytes())?;
        if unsafe { libc::chown(path.as_ptr(), 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        fs::set_permissions(source, fs::Permissions::from_mode(0o600))?;
        checked(Command::new("/usr/bin/umount").arg(self.directory.join("rootfs")))?;
        self.persistent_root = None;
        Ok(())
    }

    fn remove_runtime_root(&mut self) -> Result<()> {
        let Some(path) = &self.runtime_root else {
            return Ok(());
        };
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        self.runtime_root = None;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if let Some(proxy) = self.proxy.as_ref() {
            proxy.stop();
        }
        if let Some(gate) = self.network.as_ref().and_then(|n| n.gate.as_ref()) {
            gate.stop();
        }
        if self.service_started {
            let stop = command(Command::new("/usr/bin/systemctl").args(["stop", &self.id]))?;
            if !stop.status.success() {
                let state = self.state()?;
                if !matches!(state.as_str(), "dead" | "failed" | "") {
                    return Err(format!("could not stop {}; preserving its files", self.id).into());
                }
            }
            self.service_started = false;
            let _ = command(Command::new("/usr/bin/systemctl").args(["reset-failed", &self.id]));
        }
        let mut errors = Vec::new();
        if let Err(error) = self.console.take().map_or(Ok(()), ConsolePump::finish) {
            errors.push(format!("console: {error}"));
        }
        self.proxy = None;
        if let Err(error) = self.release_persistent_root() {
            errors.push(format!("saved disk: {error}"));
        }
        if self.persistent_root.is_none() {
            if let Err(error) = self.remove_runtime_root() {
                errors.push(format!("runtime disk: {error}"));
            }
        }
        if let Some(network) = self.network.as_mut() {
            match network.remove() {
                Ok(()) => self.network = None,
                Err(error) => errors.push(format!("network: {error}")),
            }
        }
        if self.persistent_root.is_none() && self.runtime_root.is_none() && self.network.is_none() {
            match remove_run_directory(&self.directory, &self.id) {
                Ok(()) => {
                    match command(Command::new("/usr/sbin/userdel").arg(&self.service_user)) {
                        Ok(userdel)
                            if userdel.status.success()
                                || String::from_utf8_lossy(&userdel.stderr)
                                    .contains("does not exist") => {}
                        Ok(userdel) => errors.push(format!(
                            "run account {}: {}",
                            self.service_user,
                            String::from_utf8_lossy(&userdel.stderr).trim()
                        )),
                        Err(error) => errors.push(format!("run account: {error}")),
                    }
                }
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
        if let Err(error) = self.cleanup() {
            eprintln!("cleanup failed for {}: {error}", self.id);
        }
    }
}

pub fn request_shutdown(id: &str) -> Result<()> {
    if !valid_run_id(id) {
        return Err("Invalid run ID".into());
    }
    hypervisor_api::request(
        &Path::new("/run").join(id).join("api.sock"),
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
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "VM launch requires sudo for systemd setup; run doctor without sudo first".into(),
        );
    }
    backend.validate_profile(&request.agent_profile_id)?;
    preflight::check(&request.hypervisor)?;
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
        let mut network = HostNetwork::create(&vm.id, &vm.service_user)?;
        network.start_policy(
            backend.clone(),
            request.agent_profile_id.clone(),
            vm.id.clone(),
            Arc::clone(&cancelled),
            deadline,
        )?;
        let host_ip = network.config.host_ip.clone();
        vm.network = Some(network);
        vm.proxy = Some(Proxy::start(
            &host_ip,
            backend,
            request.agent_profile_id.clone(),
            tls,
            credentials,
            Arc::clone(&cancelled),
            deadline,
            request.setup_mode,
        )?);
        eprintln!("run={} proxy=http://{}:3128", vm.id, host_ip);
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
        if let Some(gate) = vm
            .network
            .as_ref()
            .and_then(|network| network.gate.as_ref())
        {
            gate.check()?;
        }
        vm.start(&request, deadline.saturating_duration_since(Instant::now()))?;
        let boot_deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        loop {
            check_deadline(&cancelled, boot_deadline)?;
            if vm.socket().exists()
                && hypervisor_api::request(&vm.socket(), "GET", "vmm.ping", &[], boot_deadline)
                    .is_ok()
            {
                break;
            }
            if vm.state()? == "failed" {
                return Err(format!("VMM failed to start; inspect journalctl -u {}", vm.id).into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        hypervisor_api::request(
            &vm.socket(),
            "PUT",
            "vm.create",
            &serde_json::to_vec(
                &request.vm_config(&vm.directory, vm.network.as_ref().map(HostNetwork::config)),
            )?,
            boot_deadline,
        )?;
        let serial = UnixStream::connect(vm.directory.join("serial.sock"))?;
        serial.set_nonblocking(true)?;
        event(RunEvent::Terminal(serial.try_clone()?));
        vm.console = Some(ConsolePump::start(serial, Arc::clone(&event))?);
        hypervisor_api::request(&vm.socket(), "PUT", "vm.boot", &[], boot_deadline)?;
        event(RunEvent::State("running"));
        eprintln!("run={} state=running api={}", vm.id, vm.socket().display());
        loop {
            check_deadline(&cancelled, deadline)?;
            vm.pump_console()?;
            let state = vm.state()?;
            if matches!(state.as_str(), "exited" | "dead" | "failed") {
                let output = checked(Command::new("/usr/bin/systemctl").args([
                    "show",
                    &vm.id,
                    "--property=Result",
                    "--value",
                ]))?;
                let result = String::from_utf8(output.stdout)?;
                if state == "failed" || result.trim() != "success" {
                    return Err(format!(
                        "VMM stopped: {}; inspect journalctl -u {}",
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
    let cleanup = vm.cleanup();
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

fn remove_run_directory(directory: &Path, id: &str) -> Result<()> {
    let suffix = id.strip_prefix(RUN_PREFIX).ok_or("invalid run ID")?;
    if suffix.len() != 32
        || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
        || directory != Path::new("/run").join(id)
    {
        return Err("refusing cleanup outside the exact run directory".into());
    }
    match fs::symlink_metadata(directory) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = fs::read_link(directory)?;
            let private = Path::new("/run/private").join(id);
            if target != private && target != Path::new("private").join(id) {
                return Err("refusing cleanup of an unexpected runtime link".into());
            }
            let parent = Path::new("/run/private");
            let parent_meta = fs::symlink_metadata(parent)?;
            if !parent_meta.is_dir()
                || parent_meta.uid() != 0
                || parent_meta.mode() & 0o022 != 0
                || fs::canonicalize(parent)? != parent
            {
                return Err("refusing cleanup through an untrusted private directory".into());
            }
            remove_exact_directory(&private)?;
            fs::remove_file(directory)?;
            return Ok(());
        }
        Ok(meta) if !meta.is_dir() => {
            return Err("refusing cleanup of a replaced run directory".into());
        }
        _ => (),
    }
    remove_exact_directory(directory)
}

fn remove_exact_directory(directory: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(directory) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    if !meta.is_dir() || fs::canonicalize(directory)? != directory {
        return Err("refusing cleanup through a symlink".into());
    }
    fs::remove_dir_all(directory)?;
    Ok(())
}
