use crate::{
    backend::Backend,
    linux::{self, EventSink, RunEvent},
    sandbox::{self, Result, RunRequest},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

const SOCKET: &str = "/run/automantle-gateway/control.sock";
const CONSOLE_LIMIT: usize = 256 * 1024;
const REQUEST_LIMIT: usize = 64 * 1024;
const MAX_ACTIVE_RUNS: usize = 4;
const MAX_RUN_HISTORY: usize = 128;
const MAX_IMPORTS: usize = 4;

fn string_args(
    request: &Value,
    missing: &'static str,
    invalid: &'static str,
) -> Result<Vec<String>> {
    request["args"]
        .as_array()
        .ok_or(missing)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(invalid.into()))
        .collect()
}

type Runner = Arc<
    dyn Fn(
            RunRequest,
            Backend,
            String,
            Arc<AtomicBool>,
            EventSink,
        ) -> std::result::Result<(), String>
        + Send
        + Sync,
>;

struct Record {
    profile: String,
    saved_disk: Option<String>,
    storage_mode: &'static str,
    setup_mode: bool,
    state: String,
    error: Option<String>,
    console: VecDeque<u8>,
    console_total: u64,
    terminal: Option<UnixStream>,
}
impl Record {
    fn new(request: &RunRequest) -> Self {
        Self {
            profile: request.agent_profile_id.clone(),
            saved_disk: request.saved_disk.clone(),
            storage_mode: if request.preparation {
                "prepare"
            } else {
                "runtime"
            },
            setup_mode: request.setup_mode,
            state: "queued".into(),
            error: None,
            console: VecDeque::new(),
            console_total: 0,
            terminal: None,
        }
    }

    fn apply(&mut self, event: RunEvent) {
        match event {
            RunEvent::State(state) => {
                if self.state != "stopping" {
                    self.state = state.into();
                }
            }
            RunEvent::Console(bytes) => {
                self.console_total += bytes.len() as u64;
                self.console.extend(bytes);
                while self.console.len() > CONSOLE_LIMIT {
                    self.console.pop_front();
                }
            }
            RunEvent::Terminal(stream) => self.terminal = Some(stream),
        }
    }

    fn finish(&mut self, result: std::result::Result<(), String>) {
        self.terminal = None;
        match result {
            Ok(()) => self.state = "stopped".into(),
            Err(error) if error == "run interrupted" => self.state = "stopped".into(),
            Err(error) => {
                self.state = "failed".into();
                self.error = Some(error);
            }
        }
    }
}
fn record_guard(record: &Mutex<Record>) -> MutexGuard<'_, Record> {
    record.lock().unwrap_or_else(|poisoned| {
        eprintln!("VM record lock poisoned; recovering state");
        poisoned.into_inner()
    })
}
struct Task {
    record: Arc<Mutex<Record>>,
    cancel: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}
struct Import {
    cancel: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}
#[derive(Clone)]
struct Defaults {
    kernel: PathBuf,
    rootfs: PathBuf,
    tls: PathBuf,
    credentials: Option<PathBuf>,
}
impl Default for Defaults {
    fn default() -> Self {
        Self {
            kernel: "/var/lib/automantle/kernel".into(),
            rootfs: "/var/lib/automantle/linux.ext4".into(),
            tls: "/var/lib/automantle/tls/tls.json".into(),
            credentials: None,
        }
    }
}
struct Manager {
    backend: Backend,
    config: PathBuf,
    hypervisor: PathBuf,
    storage: crate::storage::Store,
    tasks: BTreeMap<String, Task>,
    imports: Vec<Import>,
    runner: Runner,
    defaults: Defaults,
    machine_runs: BTreeMap<String, String>,
}

impl Manager {
    fn spawn_import(
        &mut self,
        mut stream: UnixStream,
        operation: impl FnOnce(&AtomicBool) -> Result<Value> + Send + 'static,
    ) {
        let mut worker_stream = match stream.try_clone() {
            Ok(stream) => stream,
            Err(error) => {
                let _ = writeln!(stream, "{}", json!({"error":error.to_string()}));
                return;
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        match thread::Builder::new()
            .name("vm-import".into())
            .spawn(move || {
                let reply = match operation(&worker_cancel) {
                    Ok(result) => json!({"result":result}),
                    Err(error) => json!({"error":error.to_string()}),
                };
                let _ = writeln!(worker_stream, "{reply}");
            }) {
            Ok(worker) => self.imports.push(Import { cancel, worker }),
            Err(error) => {
                let _ = writeln!(stream, "{}", json!({"error":error.to_string()}));
            }
        }
    }

    fn busy_machine(&self, id: &str) -> bool {
        self.tasks.values().any(|task| {
            !task.worker.is_finished()
                && record_guard(&task.record).saved_disk.as_deref() == Some(id)
        })
    }
    fn import_machine(&mut self, request: Value, mut stream: UnixStream) {
        self.imports
            .retain_mut(|import| !import.worker.is_finished());
        let response = (|| -> Result<(Option<String>, crate::machines::Settings)> {
            if self.imports.len() >= MAX_IMPORTS {
                return Err("Four VM copies are already in progress".into());
            }
            let command = request["command"].as_str().ok_or("command is required")?;
            let allowed = if command == "copy-machine" {
                vec!["command", "id", "name"]
            } else {
                vec!["command", "settings"]
            };
            if request
                .as_object()
                .is_none_or(|r| r.keys().any(|k| !allowed.contains(&k.as_str())))
            {
                return Err("Unknown VM creation field".into());
            }
            let source = if command == "copy-machine" {
                let id = request["id"]
                    .as_str()
                    .ok_or("VM ID is required")?
                    .to_owned();
                if self.busy_machine(&id) {
                    return Err("Stop the VM before copying it".into());
                }
                Some(id)
            } else {
                None
            };
            let settings = if let Some(id) = &source {
                let mut s = self.storage.machine(id)?.settings;
                s.name = request["name"]
                    .as_str()
                    .ok_or("Copy name is required")?
                    .to_owned();
                s
            } else {
                serde_json::from_value(request["settings"].clone())?
            };
            settings.validate()?;
            self.backend.validate_profile(&settings.agent_profile_id)?;
            Ok((source, settings))
        })();
        let (source, settings) = match response {
            Ok(value) => value,
            Err(e) => {
                let _ = writeln!(stream, "{}", json!({"error":e.to_string()}));
                return;
            }
        };
        let store = self.storage.clone();
        let base = self.defaults.rootfs.clone();
        self.spawn_import(stream, move |cancel| {
            let vm = match source {
                Some(id) => store.copy_machine(&id, settings.name, cancel),
                None => store.create_machine(settings, &base, cancel),
            }?;
            Ok(serde_json::to_value(vm)?)
        });
    }
    fn list_machines(&self) -> Result<Value> {
        let mut result = Vec::new();
        for machine in self.storage.machines()? {
            let mut value = serde_json::to_value(&machine)?;
            let run = self
                .machine_runs
                .get(&machine.id)
                .and_then(|id| self.tasks.get(id).map(|task| (id, task)));
            value["os"] = json!("Linux");
            value["state"] = json!("stopped");
            value["runId"] = Value::Null;
            value["error"] = Value::Null;
            value["terminalReady"] = json!(false);
            if let Some((id, task)) = run {
                let record = record_guard(&task.record);
                value["runId"] = json!(id);
                value["state"] = json!(record.state);
                value["error"] = json!(record.error);
                value["terminalReady"] = json!(record.terminal.is_some());
            }
            result.push(value);
        }
        Ok(json!(result))
    }
    fn start_machine(&mut self, id: &str) -> Result<Value> {
        let vm = self.storage.machine(id)?;
        if self.busy_machine(id) {
            return Err("VM is already active".into());
        }
        let mut args = vec![
            "--saved-disk".into(),
            id.into(),
            "--storage-mode".into(),
            "prepare".into(),
            "--kernel".into(),
            self.defaults.kernel.to_string_lossy().into_owned(),
            "--agent-profile-id".into(),
            vm.settings.agent_profile_id,
            "--memory-mib".into(),
            vm.settings.memory_mib.to_string(),
            "--vcpu-count".into(),
            vm.settings.vcpu_count.to_string(),
            "--timeout-seconds".into(),
            "0".into(),
            "--network".into(),
            "proxy".into(),
            "--mode".into(),
            if vm.settings.setup { "setup" } else { "normal" }.into(),
        ];
        if self.defaults.tls.is_file() {
            args.extend([
                "--tls-ca-config".into(),
                self.defaults.tls.to_string_lossy().into_owned(),
            ]);
        }
        if let Some(path) = &self.defaults.credentials {
            args.extend([
                "--credentials-config".into(),
                path.to_string_lossy().into_owned(),
            ]);
        }
        let run = self.launch(&args)?;
        let run_id = run["id"].as_str().ok_or("Missing run ID")?;
        self.machine_runs.insert(id.into(), run_id.into());
        eprintln!("machine={id} run={run_id}");
        self.list_machines()?
            .as_array()
            .ok_or("Missing VM definitions")?
            .iter()
            .find(|v| v["id"] == id)
            .cloned()
            .ok_or_else(|| "Missing VM definition".into())
    }
    fn stop_machine(&mut self, id: &str, force: bool) -> Result<Value> {
        self.storage.machine(id)?;
        let run = self.machine_runs.get(id).ok_or("VM is stopped")?;
        let task = self.tasks.get(run).ok_or("VM is stopped")?;
        if task.worker.is_finished() {
            let record = record_guard(&task.record);
            return Ok(json!({"state":record.state}));
        }
        if force {
            task.cancel.store(true, Ordering::Relaxed);
        } else {
            {
                let record = record_guard(&task.record);
                if record.state == "stopping" {
                    return Ok(json!({"state":"stopping"}));
                }
                if record.state != "running" {
                    return Err("Wait until the VM has booted, or use Force stop".into());
                }
            }
            linux::request_shutdown(run)?;
        }
        let mut record = record_guard(&task.record);
        if !task.worker.is_finished() {
            record.state = "stopping".into();
        }
        Ok(json!({"state":record.state}))
    }

    fn import_disk(&mut self, request: Value, mut stream: UnixStream) {
        self.imports
            .retain_mut(|import| !import.worker.is_finished());
        if self.imports.len() >= MAX_IMPORTS {
            let _ = writeln!(
                stream,
                "{}",
                json!({"error":"four disk imports are already active"})
            );
            return;
        }
        let store = self.storage.clone();
        self.spawn_import(stream, move |cancel| {
            if request
                .as_object()
                .is_none_or(|r| r.keys().any(|k| !matches!(k.as_str(), "command" | "args")))
            {
                return Err("unknown import request field".into());
            }
            let args = string_args(&request, "disk args are required", "invalid disk argument")?;
            let values = sandbox::options(&args, &["--name", "--rootfs"])?;
            store.create_cancellable(
                values.get("--name").ok_or("--name is required")?,
                Path::new(values.get("--rootfs").ok_or("--rootfs is required")?),
                cancel,
            )
        });
    }

    fn launch_request(
        &self,
        args: &[String],
    ) -> Result<(RunRequest, Option<crate::storage::Lease>)> {
        if args
            .iter()
            .any(|a| matches!(a.as_str(), "--gateway-config" | "--cloud-hypervisor"))
        {
            return Err("connection config and Cloud Hypervisor belong to gateway start, not each VM launch".into());
        }
        let mut args = args.to_vec();
        args.extend([
            "--gateway-config".into(),
            self.config.to_string_lossy().into_owned(),
            "--cloud-hypervisor".into(),
            self.hypervisor.to_string_lossy().into_owned(),
        ]);
        let mut request = RunRequest::parse(&args)?;
        request.managed_credentials = Some(self.storage.credential_path());
        debug_assert_eq!(request.gateway_config, self.config);
        self.backend.validate_profile(&request.agent_profile_id)?;
        if self
            .tasks
            .values()
            .filter(|t| !t.worker.is_finished())
            .count()
            >= MAX_ACTIVE_RUNS
        {
            return Err("four VMs are already active".into());
        }
        let disk_lease = request
            .saved_disk
            .as_deref()
            .map(|name| self.storage.acquire(name, request.preparation))
            .transpose()?;
        if let Some(lease) = &disk_lease {
            request.rootfs = lease.path.clone();
        }
        Ok((request, disk_lease))
    }

    fn trim_run_history(&mut self) -> Result<()> {
        while self.tasks.len() >= MAX_RUN_HISTORY {
            let id = self
                .tasks
                .iter()
                .find(|(_, t)| t.worker.is_finished())
                .map(|(id, _)| id.clone())
                .ok_or("run history is full")?;
            let task = self.tasks.remove(&id).ok_or("completed run disappeared")?;
            let _ = task.worker.join();
        }
        Ok(())
    }

    fn launch(&mut self, args: &[String]) -> Result<Value> {
        let (request, disk_lease) = self.launch_request(args)?;
        self.trim_run_history()?;
        let id = linux::new_run_id()?;
        let record = Arc::new(Mutex::new(Record::new(&request)));
        let cancel = Arc::new(AtomicBool::new(false));
        let events = Arc::clone(&record);
        let event: EventSink = Arc::new(move |event| {
            record_guard(&events).apply(event);
        });
        let backend = self.backend.clone();
        let runner = Arc::clone(&self.runner);
        let finished = Arc::clone(&record);
        let cancellation = Arc::clone(&cancel);
        let run_id = id.clone();
        let worker = thread::Builder::new().name(id.clone()).spawn(move || {
            let _disk_lease = disk_lease;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runner(request, backend, run_id, cancellation, event)
            }));
            let result =
                result.unwrap_or_else(|_| Err("VM worker panicked; inspect gateway logs".into()));
            record_guard(&finished).finish(result);
        })?;
        self.tasks.insert(
            id.clone(),
            Task {
                record,
                cancel,
                worker,
            },
        );
        Ok(json!({"id":id,"state":"queued"}))
    }

    fn terminal_read(&self, id: &str, request: &Value) -> Result<Value> {
        let task = self.tasks.get(id).ok_or("unknown VM run")?;
        let record = record_guard(&task.record);
        let offset = request["offset"].as_u64().ok_or("offset is required")?;
        if offset > record.console_total {
            return Err("terminal offset is ahead of output".into());
        }
        let oldest = record.console_total - record.console.len() as u64;
        let start = offset.max(oldest);
        let data = record
            .console
            .iter()
            .skip((start - oldest) as usize)
            .take(64 * 1024)
            .copied()
            .collect::<Vec<_>>();
        Ok(json!({
            "id": id,
            "agentProfileId": record.profile,
            "savedDisk": record.saved_disk,
            "storageMode": record.storage_mode,
            "setupMode": record.setup_mode,
            "state": record.state,
            "ready": record.terminal.is_some(),
            "start": start,
            "next": start + data.len() as u64,
            "gap": offset < oldest,
            "data": data,
        }))
    }

    fn terminal_write(&self, id: &str, request: &Value) -> Result<Value> {
        let task = self.tasks.get(id).ok_or("unknown VM run")?;
        let mut record = record_guard(&task.record);
        let data = request["data"]
            .as_array()
            .ok_or("terminal bytes are required")?;
        if data.is_empty() || data.len() > 4096 {
            return Err("terminal input must contain 1-4096 bytes".into());
        }
        let bytes = data
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .filter(|byte| *byte <= 255)
                    .map(|byte| byte as u8)
                    .ok_or("invalid terminal byte")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if record.state != "running" {
            return Err("VM is not running".into());
        }
        let stream = record.terminal.as_mut().ok_or("terminal is not ready")?;
        let written = stream.write(&bytes)?;
        Ok(json!({"written":written}))
    }

    fn save_credential(&self, request: &Value, create: bool) -> Result<Value> {
        let credential: crate::credentials::SaveCredential =
            serde_json::from_value(request["credential"].clone())
                .map_err(|_| "Invalid credential fields")?;
        self.storage.save_credential(credential, create)
    }

    fn change_machine(&mut self, request: &Value, delete: bool) -> Result<Value> {
        let id = request["id"].as_str().ok_or("VM ID is required")?;
        if self.busy_machine(id) {
            return Err("Stop the VM before editing or deleting it".into());
        }
        if delete {
            self.storage.delete_machine(id)?;
            self.machine_runs.remove(id);
            return Ok(json!({"deleted":true}));
        }
        let settings: crate::machines::Settings =
            serde_json::from_value(request["settings"].clone())?;
        settings.validate()?;
        self.backend.validate_profile(&settings.agent_profile_id)?;
        Ok(serde_json::to_value(
            self.storage.update_machine(id, settings)?,
        )?)
    }

    fn list_runs(&self) -> Value {
        json!(
            self.tasks
                .iter()
                .map(|(id, task)| {
                    let record = record_guard(&task.record);
                    json!({
                        "id": id,
                        "agentProfileId": record.profile,
                        "savedDisk": record.saved_disk,
                        "storageMode": record.storage_mode,
                        "setupMode": record.setup_mode,
                        "state": record.state,
                        "error": record.error,
                    })
                })
                .collect::<Vec<_>>()
        )
    }

    fn run_logs(&self, id: &str) -> Result<Value> {
        let task = self.tasks.get(id).ok_or("unknown VM run")?;
        let record = record_guard(&task.record);
        let console = record.console.iter().copied().collect::<Vec<_>>();
        Ok(json!({
            "id": id,
            "agentProfileId": record.profile,
            "savedDisk": record.saved_disk,
            "storageMode": record.storage_mode,
            "state": record.state,
            "error": record.error,
            "console": String::from_utf8_lossy(&console),
        }))
    }

    fn stop_run(&self, id: &str) -> Result<Value> {
        let task = self.tasks.get(id).ok_or("unknown VM run")?;
        let mut record = record_guard(&task.record);
        if !task.worker.is_finished() {
            task.cancel.store(true, Ordering::Relaxed);
            record.state = "stopping".into();
        }
        Ok(json!({"id":id,"state":record.state}))
    }

    fn command(&mut self, request: &Value) -> Result<Value> {
        let command = request["command"].as_str().ok_or("command is required")?;
        let fields = request.as_object().ok_or("expected an object")?;
        if fields.keys().any(|k| {
            !matches!(
                k.as_str(),
                "command" | "args" | "id" | "offset" | "data" | "settings" | "name" | "credential"
            )
        }) {
            return Err("unknown request field".into());
        }
        match command {
            "credential-list" => self.storage.list_credentials(),
            "credential-create" => self.save_credential(request, true),
            "credential-update" => self.save_credential(request, false),
            "credential-delete" => self.storage.delete_credential(
                request["name"]
                    .as_str()
                    .ok_or("Credential name is required")?,
            ),
            "list-machines" => self.list_machines(),
            "start-machine" => {
                self.start_machine(request["id"].as_str().ok_or("VM ID is required")?)
            }
            "shutdown-machine" | "force-stop-machine" => self.stop_machine(
                request["id"].as_str().ok_or("VM ID is required")?,
                command == "force-stop-machine",
            ),
            "update-machine" => self.change_machine(request, false),
            "delete-machine" => self.change_machine(request, true),
            "terminal-read" => {
                let id = request["id"].as_str().ok_or("run ID is required")?;
                self.terminal_read(id, request)
            }
            "terminal-write" => {
                let id = request["id"].as_str().ok_or("run ID is required")?;
                self.terminal_write(id, request)
            }
            "create-disk" => {
                let args = string_args(request, "disk args are required", "invalid disk argument")?;
                let values = sandbox::options(&args, &["--name", "--rootfs"])?;
                self.storage.create(
                    values.get("--name").ok_or("--name is required")?,
                    Path::new(values.get("--rootfs").ok_or("--rootfs is required")?),
                )
            }
            "list-disks" => self.storage.list(),
            "launch" => {
                let args = string_args(
                    request,
                    "launch args are required",
                    "invalid launch argument",
                )?;
                self.launch(&args)
            }
            "list" => Ok(self.list_runs()),
            "logs" => {
                let id = request["id"].as_str().ok_or("run ID is required")?;
                self.run_logs(id)
            }
            "stop-vm" => {
                let id = request["id"].as_str().ok_or("run ID is required")?;
                self.stop_run(id)
            }
            _ => Err("unknown gateway command".into()),
        }
    }
    fn shutdown(&mut self) {
        for import in &self.imports {
            import.cancel.store(true, Ordering::Relaxed);
        }
        for task in self.tasks.values() {
            task.cancel.store(true, Ordering::Relaxed);
        }
        for import in std::mem::take(&mut self.imports) {
            let _ = import.worker.join();
        }
        for (_, task) in std::mem::take(&mut self.tasks) {
            let _ = task.worker.join();
        }
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

mod client;
mod control;
pub use control::cli;
