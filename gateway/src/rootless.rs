use crate::{
    linux::host_command::{checked, command},
    sandbox::{Result, RunRequest},
};
use std::{
    env,
    fs::{self, DirBuilder},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn trusted_user_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(format!("untrusted user runtime directory: {}", path.display()).into());
    }
    Ok(())
}

pub fn data_parent() -> Result<PathBuf> {
    let base = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or("HOME or XDG_DATA_HOME is required")?;
    if !base.is_absolute() {
        return Err("data directory must be absolute".into());
    }
    fs::create_dir_all(&base)?;
    let application = base.join("automantle");
    if !application.exists() {
        DirBuilder::new().mode(0o700).create(&application)?;
    }
    trusted_user_directory(&application)?;
    let runs = application.join("runs");
    if !runs.exists() {
        DirBuilder::new().mode(0o700).create(&runs)?;
    }
    trusted_user_directory(&runs)?;
    Ok(runs)
}

pub fn runtime_parent() -> Result<PathBuf> {
    let base = PathBuf::from(env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is required")?);
    if !base.is_absolute() {
        return Err("XDG_RUNTIME_DIR must be absolute".into());
    }
    trusted_user_directory(&base)?;
    let parent = base.join("automantle");
    if !parent.exists() {
        DirBuilder::new().mode(0o700).create(&parent)?;
    }
    trusted_user_directory(&parent)?;
    Ok(parent)
}

pub fn run_path(id: &str) -> Result<PathBuf> {
    if !crate::linux::valid_run_id(id) {
        return Err("invalid run ID".into());
    }
    Ok(runtime_parent()?.join(id))
}

pub fn disk_path(id: &str) -> Result<PathBuf> {
    if !crate::linux::valid_run_id(id) {
        return Err("invalid run ID".into());
    }
    Ok(data_parent()?.join(id))
}

pub fn create_run(id: &str) -> Result<(PathBuf, PathBuf)> {
    let directory = run_path(id)?;
    let disks = disk_path(id)?;
    DirBuilder::new().mode(0o700).create(&directory)?;
    trusted_user_directory(&directory)?;
    if let Err(error) = DirBuilder::new().mode(0o700).create(&disks) {
        let _ = fs::remove_dir(&directory);
        return Err(error.into());
    }
    trusted_user_directory(&disks)?;
    Ok((directory, disks))
}

pub fn connect_vmm(id: &str, kind: &str) -> Result<UnixStream> {
    let directory = run_path(id)?;
    trusted_user_directory(&directory)?;
    let leaf = match kind {
        "api" => "api.sock",
        "serial" => "serial.sock",
        _ => return Err("unknown VM socket kind".into()),
    };
    let socket = directory.join(leaf);
    let metadata = fs::symlink_metadata(&socket)?;
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("untrusted VM socket".into());
    }
    Ok(UnixStream::connect(socket)?)
}

pub fn start_vmm(
    id: &str,
    request: &RunRequest,
    memory_mib: u64,
    vcpus: u64,
    lifetime: Duration,
) -> Result<()> {
    let directory = run_path(id)?;
    trusted_user_directory(&directory)?;
    let hypervisor = fs::canonicalize(&request.hypervisor)?;
    let disks = disk_path(id)?;
    trusted_user_directory(&disks)?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command.args(["--user", "--quiet", "--service-type=exec", "--unit", id]);
    let properties = [
        "NoNewPrivileges=yes".to_owned(),
        "ProtectHome=tmpfs".to_owned(),
        format!("BindPaths={}", disks.display()),
        format!("BindPaths={}", directory.display()),
        format!("BindReadOnlyPaths={}", hypervisor.display()),
        "UMask=0077".to_owned(),
        "MemorySwapMax=0".to_owned(),
        "KillMode=control-group".to_owned(),
        "LimitCORE=0".to_owned(),
        format!("MemoryMax={}M", memory_mib + 256),
        format!("CPUQuota={}%", vcpus * 100),
        format!("TasksMax={}", vcpus * 2 + 64),
        format!(
            "RuntimeMaxSec={}",
            if request.timeout.is_zero() {
                "infinity".to_owned()
            } else {
                lifetime.as_secs().max(1).to_string()
            }
        ),
    ];
    for property in properties {
        command.arg("--property").arg(property);
    }
    command
        .arg("--")
        .arg(hypervisor)
        .arg("--api-socket")
        .arg(directory.join("api.sock"))
        .args(["--seccomp", "true"]);
    checked(&mut command)?;
    Ok(())
}

pub fn stop_vmm(id: &str) -> Result<()> {
    let _ = run_path(id)?;
    let output = command(Command::new("/usr/bin/systemctl").args(["--user", "stop", id]))?;
    if !output.status.success() {
        let state = checked(Command::new("/usr/bin/systemctl").args([
            "--user",
            "show",
            id,
            "--property=LoadState",
            "--value",
        ]))?;
        if String::from_utf8(state.stdout)?.trim() != "not-found" {
            return Err("could not stop VMM user service".into());
        }
    }
    let _ = command(Command::new("/usr/bin/systemctl").args(["--user", "reset-failed", id]));
    Ok(())
}

pub fn state(id: &str) -> Result<String> {
    let _ = run_path(id)?;
    let output = checked(Command::new("/usr/bin/systemctl").args([
        "--user",
        "show",
        id,
        "--property=SubState",
        "--value",
    ]))?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn destroy_run(id: &str) -> Result<()> {
    for directory in [run_path(id)?, disk_path(id)?] {
        if !directory.exists() {
            continue;
        }
        trusted_user_directory(&directory)?;
        if fs::canonicalize(&directory)? != directory {
            return Err("refusing cleanup through a linked run directory".into());
        }
        fs::remove_dir_all(directory)?;
    }
    Ok(())
}
