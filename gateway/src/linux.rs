use crate::{
    backend::Backend,
    hypervisor_api, privileged,
    proxy::Proxy,
    sandbox::{Result, RunRequest},
};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
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
pub(crate) mod host_command;
pub(crate) mod network;
mod network_client;
pub(crate) mod preflight;
use console::ConsolePump;
use host_command::{checked, command};
use network_client::NetworkLease;
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
    directory: PathBuf,
    destroyed: bool,
    service_started: bool,
    console: Option<ConsolePump>,
    network: Option<NetworkLease>,
    proxy: Option<Proxy>,
    persistent_root: Option<File>,
    runtime_root: Option<PathBuf>,
}

impl Run {
    fn create(id: String) -> Result<Self> {
        if !valid_run_id(&id) {
            return Err("invalid run ID".into());
        }
        let directory = Path::new("/run").join(&id);
        privileged::request(json!({"command":"create-run","id":id}))?;
        Ok(Self {
            id,
            directory,
            destroyed: false,
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
            self.persistent_root = Some(OpenOptions::new().read(true).open(source)?);
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
                self.network.as_ref().map(NetworkLease::config),
            ))?,
        )?;
        privileged::request_with_file(
            json!({
                "command":"prepare-run", "id":self.id,
                "saved":self.persistent_root.is_some(),
                "initramfs":request.initramfs.is_some(),
            }),
            self.persistent_root.as_ref(),
        )?;
        Ok(())
    }

    fn start(&mut self, request: &RunRequest, lifetime: Duration) -> Result<()> {
        self.service_started = true;
        privileged::request(json!({
            "command":"start-vmm", "id":self.id,
            "settings":{
                "memoryMib":request.memory_mib,
                "vcpus":request.vcpus,
                "lifetimeSeconds":if request.timeout.is_zero() {0} else {lifetime.as_secs().max(1)},
                "network":self.network.is_some(),
                "saved":request.saved_disk.is_some(),
                "preparation":request.preparation,
                "initramfs":request.initramfs.is_some(),
                "hypervisor":request.hypervisor,
            }
        }))?;
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
        let Some(source) = self.persistent_root.as_ref() else {
            return Ok(());
        };
        privileged::request_with_file(
            json!({"command":"release-saved","id":self.id}),
            Some(source),
        )?;
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
        if self.destroyed {
            return Ok(());
        }
        if let Some(proxy) = self.proxy.as_ref() {
            proxy.stop();
        }
        if let Some(gate) = self.network.as_ref().and_then(|n| n.gate.as_ref()) {
            gate.stop();
        }
        if self.service_started {
            privileged::request(json!({"command":"stop-vmm","id":self.id}))?;
            self.service_started = false;
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
            match privileged::request(json!({"command":"destroy-run","id":self.id})) {
                Ok(_) => self.destroyed = true,
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
        privileged::connect_vmm(id, "api")?,
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
        let mut network = NetworkLease::create(&vm.id)?;
        network.start_policy(
            backend.clone(),
            request.agent_profile_id.clone(),
            vm.id.clone(),
            Arc::clone(&cancelled),
            deadline,
        )?;
        let host_ip = network.config().host_ip.clone();
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
            if privileged::connect_vmm(&vm.id, "api")
                .and_then(|socket| {
                    hypervisor_api::request(socket, "GET", "vmm.ping", &[], boot_deadline)
                })
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
            privileged::connect_vmm(&vm.id, "api")?,
            "PUT",
            "vm.create",
            &serde_json::to_vec(
                &request.vm_config(&vm.directory, vm.network.as_ref().map(NetworkLease::config)),
            )?,
            boot_deadline,
        )?;
        let serial = privileged::connect_vmm(&vm.id, "serial")?;
        serial.set_nonblocking(true)?;
        event(RunEvent::Terminal(serial.try_clone()?));
        vm.console = Some(ConsolePump::start(serial, Arc::clone(&event))?);
        hypervisor_api::request(
            privileged::connect_vmm(&vm.id, "api")?,
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

pub(crate) fn remove_run_directory(directory: &Path, id: &str) -> Result<()> {
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
