use super::{
    Defaults, Manager, REQUEST_LIMIT, SOCKET,
    client::{client_request, terminal_cli},
};
use crate::{
    backend::Backend,
    linux,
    sandbox::{self, Result},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub(super) fn read_request(stream: &UnixStream) -> Result<Value> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    BufReader::new(stream.take((REQUEST_LIMIT + 1) as u64)).read_until(b'\n', &mut bytes)?;
    if bytes.len() > REQUEST_LIMIT || bytes.last() != Some(&b'\n') {
        return Err("request must be bounded newline-delimited JSON".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn bind(path: &Path, group: Option<u32>) -> Result<(UnixListener, SocketGuard)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("socket path must be absolute without parent traversal".into());
    }
    let parent = path.parent().ok_or("missing socket directory")?;
    if !parent.exists() {
        fs::DirBuilder::new().mode(0o700).create(parent)?;
    }
    for directory in parent.ancestors() {
        let m = fs::symlink_metadata(directory)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(
                "socket directories must be real, root-owned, and not writable by other users"
                    .into(),
            );
        }
    }
    let m = fs::symlink_metadata(parent)?;
    if m.mode() & 0o077 != 0 && !(group == Some(m.gid()) && m.mode() & 0o077 == 0o010) {
        return Err("socket parent must have mode 0700".into());
    }
    let listener = UnixListener::bind(path)?;
    let m = fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.into(),
        device: m.dev(),
        inode: m.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if let Some(group) = group {
        for target in [parent, path] {
            use std::os::unix::ffi::OsStrExt;
            let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
            if unsafe { libc::chown(target.as_ptr(), 0, group) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o710))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    }
    Ok((listener, guard))
}

fn handle_connection(manager: &mut Manager, mut stream: UnixStream) -> Result<bool> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_request(&stream);
    match request {
        Ok(request)
            if matches!(
                request["command"].as_str(),
                Some("create-machine" | "copy-machine")
            ) =>
        {
            manager.import_machine(request, stream);
            Ok(false)
        }
        Ok(request) if request["command"] == "create-disk" => {
            manager.import_disk(request, stream);
            Ok(false)
        }
        request => {
            let stop = request
                .as_ref()
                .is_ok_and(|r| r == &json!({"command":"stop"}));
            let response = if stop {
                manager.shutdown();
                Ok(json!({"state":"stopped"}))
            } else {
                request.and_then(|r| manager.command(&r))
            };
            let reply = match response {
                Ok(result) => json!({"result":result}),
                Err(error) => json!({"error":error.to_string()}),
            };
            let _ = writeln!(stream, "{reply}");
            Ok(stop)
        }
    }
}

pub fn cli(args: &[String]) -> Result<()> {
    let command = args
        .first()
        .map(String::as_str)
        .ok_or("command is required")?;
    if command == "start" && unsafe { libc::geteuid() } != 0 {
        return Err("gateway management requires sudo on Linux/WSL".into());
    }
    let mut values = args[1..].to_vec();
    let mut socket = PathBuf::from(SOCKET);
    if let Some(index) = values.iter().position(|a| a == "--socket") {
        socket = values
            .get(index + 1)
            .ok_or("--socket requires a path")?
            .into();
        values.drain(index..index + 2);
    }
    if command == "start" {
        let values = sandbox::options(
            &values,
            &[
                "--gateway-config",
                "--cloud-hypervisor",
                "--disk-directory",
                "--control-group",
                "--default-kernel",
                "--default-rootfs",
                "--tls-ca-config",
                "--credentials-config",
            ],
        )?;
        let config = PathBuf::from(
            values
                .get("--gateway-config")
                .ok_or("--gateway-config is required")?,
        );
        let hypervisor = PathBuf::from(
            values
                .get("--cloud-hypervisor")
                .map(String::as_str)
                .unwrap_or("/usr/local/bin/cloud-hypervisor"),
        );
        let group = values
            .get("--control-group")
            .map(|name| -> Result<u32> {
                let name = std::ffi::CString::new(name.as_str())?;
                let group = unsafe { libc::getgrnam(name.as_ptr()) };
                if group.is_null() {
                    return Err("unknown local control group".into());
                }
                Ok(unsafe { (*group).gr_gid })
            })
            .transpose()?;
        let (listener, _guard) = bind(&socket, group)?;
        let backend = Backend::load(&config)?;
        let mut manager = Manager {
            backend,
            config,
            hypervisor,
            storage: crate::storage::Store {
                directory: values
                    .get("--disk-directory")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| "/var/lib/automantle/vms".into()),
            },
            defaults: Defaults {
                kernel: values
                    .get("--default-kernel")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| Defaults::default().kernel),
                rootfs: values
                    .get("--default-rootfs")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| Defaults::default().rootfs),
                tls: values
                    .get("--tls-ca-config")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| Defaults::default().tls),
                credentials: values.get("--credentials-config").map(PathBuf::from),
            },
            machine_runs: BTreeMap::new(),
            tasks: BTreeMap::new(),
            imports: Vec::new(),
            runner: Arc::new(|r, b, id, c, e| {
                linux::run(r, b, id, c, e).map_err(|e| e.to_string())
            }),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let signals = [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]
            .into_iter()
            .map(|s| signal_hook::flag::register(s, Arc::clone(&shutdown)))
            .collect::<std::io::Result<Vec<_>>>()?;
        listener.set_nonblocking(true)?;
        eprintln!(
            "gateway ready: {}; use another terminal for VM commands",
            socket.display()
        );
        let result = (|| -> Result<()> {
            while !shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if handle_connection(&mut manager, stream)? {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50))
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })();
        manager.shutdown();
        for id in signals {
            signal_hook::low_level::unregister(id);
        }
        return result;
    }
    if command == "terminal" && values.len() == 1 {
        return terminal_cli(&socket, &values[0]);
    }
    let request = match command {
        "launch" | "create-disk" => json!({"command":command,"args":values}),
        "list" | "list-disks" | "stop" if values.is_empty() => json!({"command":command}),
        "logs" | "stop-vm" if values.len() == 1 => json!({"command":command,"id":values[0]}),
        _ => {
            return Err(
                "use start, create-disk, list-disks, launch, list, logs RUN_ID, stop-vm RUN_ID, or stop; see --help".into(),
            );
        }
    };
    let response = client_request(&socket, &request)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
