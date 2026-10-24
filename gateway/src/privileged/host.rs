use crate::{
    linux::{
        self,
        host_command::{checked, command},
    },
    sandbox::Result,
};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

const STATE: &str = "/run/automantle-helper/state";

fn run_path(id: &str) -> Result<PathBuf> {
    if !linux::valid_run_id(id) {
        return Err("invalid run ID".into());
    }
    Ok(Path::new("/run").join(id))
}

fn marker(id: &str) -> Result<PathBuf> {
    run_path(id)?;
    Ok(Path::new(STATE).join(id))
}

pub(super) fn active(id: &str) -> Result<PathBuf> {
    let path = marker(id)?;
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err("untrusted VM helper marker".into());
    }
    let directory = run_path(id)?;
    if !fs::symlink_metadata(&directory)?.is_dir() {
        return Err("invalid VM run directory".into());
    }
    Ok(directory)
}

fn user(id: &str) -> Result<String> {
    let suffix = linux::run_suffix(id)?;
    Ok(format!("amv{}", &suffix[..10]))
}

fn uid_of(name: &str) -> Result<(u32, u32)> {
    let name = CString::new(name)?;
    let record = unsafe { libc::getpwnam(name.as_ptr()) };
    if record.is_null() {
        return Err("VM service user is missing".into());
    }
    Ok(unsafe { ((*record).pw_uid, (*record).pw_gid) })
}

fn gid_of(name: &str) -> Result<u32> {
    let name = CString::new(name)?;
    let record = unsafe { libc::getgrnam(name.as_ptr()) };
    if record.is_null() {
        return Err("automantle service group is missing".into());
    }
    Ok(unsafe { (*record).gr_gid })
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn create_run(id: &str) -> Result<()> {
    let directory = run_path(id)?;
    let marker = marker(id)?;
    let name = user(id)?;
    let (gateway_uid, _) = uid_of("automantle")?;
    let gateway_gid = gid_of("automantle")?;
    if !Path::new(STATE).exists() {
        fs::create_dir(STATE)?;
        fs::set_permissions(STATE, fs::Permissions::from_mode(0o700))?;
    }
    let state = fs::symlink_metadata(STATE)?;
    if !state.is_dir() || state.uid() != 0 || state.mode() & 0o077 != 0 {
        return Err("untrusted helper state directory".into());
    }
    checked(Command::new("/usr/sbin/useradd").args([
        "--system",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        "/usr/sbin/nologin",
        "--user-group",
        "--groups",
        "kvm",
        &name,
    ]))?;
    let result = (|| -> Result<()> {
        fs::create_dir(&directory)?;
        chown(&directory, gateway_uid, gateway_gid)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&marker);
        let _ = fs::remove_dir(&directory);
        let _ = command(Command::new("/usr/sbin/userdel").arg(&name));
    }
    result
}

fn regular_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("VM run file must be regular".into());
    }
    Ok(file)
}

pub(super) fn prepare_run(id: &str, saved: Option<File>, initramfs: bool) -> Result<()> {
    let directory = active(id)?;
    let name = user(id)?;
    let (vmm_uid, vmm_gid) = uid_of(&name)?;
    if let Some(source) = saved.as_ref() {
        let meta = source.metadata()?;
        let (gateway_uid, _) = uid_of("automantle")?;
        if !meta.is_file()
            || meta.uid() != gateway_uid
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
            || meta.len() == 0
            || meta.len() > 64 * 1024 * 1024 * 1024
        {
            return Err("saved root must be a private gateway-owned regular file".into());
        }
        let target = directory.join("rootfs");
        let target_file = regular_file(&target)?;
        if target_file.metadata()?.len() != 0 {
            return Err("saved root mount target must be empty".into());
        }
        let source_path = CString::new(format!("/proc/self/fd/{}", source.as_raw_fd()))?;
        let target_path = CString::new(target.as_os_str().as_bytes())?;
        if unsafe {
            libc::mount(
                source_path.as_ptr(),
                target_path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(format!(
                "bind mounting saved root: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
    }
    for leaf in ["kernel", "rootfs", "scratch", "vm.json"] {
        let path = directory.join(leaf);
        let file = regular_file(&path)?;
        if unsafe { libc::fchown(file.as_raw_fd(), vmm_uid, vmm_gid) } != 0 {
            return Err(format!(
                "setting VM file owner for {leaf}: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
    }
    if initramfs {
        let file = regular_file(&directory.join("initramfs"))?;
        if unsafe { libc::fchown(file.as_raw_fd(), vmm_uid, vmm_gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

pub(super) fn release_saved(id: &str, file: File) -> Result<()> {
    let directory = active(id)?;
    let target = directory.join("rootfs");
    let mounted = regular_file(&target)?;
    let source_meta = file.metadata()?;
    let target_meta = mounted.metadata()?;
    if source_meta.dev() != target_meta.dev() || source_meta.ino() != target_meta.ino() {
        return Err("saved root mount identity changed".into());
    }
    drop(mounted);
    file.sync_all()?;
    let (gateway_uid, _) = uid_of("automantle")?;
    let gateway_gid = gid_of("automantle")?;
    if unsafe { libc::fchown(file.as_raw_fd(), gateway_uid, gateway_gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let target_path = CString::new(target.as_os_str().as_bytes())?;
    if unsafe { libc::umount2(target_path.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn start_vmm(id: &str, settings: &serde_json::Value) -> Result<()> {
    let directory = active(id)?;
    let name = user(id)?;
    let memory = settings["memoryMib"].as_u64().ok_or("invalid memory")?;
    let cpus = settings["vcpus"].as_u64().ok_or("invalid CPU count")?;
    let lifetime = settings["lifetimeSeconds"]
        .as_u64()
        .ok_or("invalid lifetime")?;
    let networking = settings["network"]
        .as_bool()
        .ok_or("invalid network mode")?;
    let saved = settings["saved"].as_bool().ok_or("invalid storage mode")?;
    let preparation = settings["preparation"]
        .as_bool()
        .ok_or("invalid preparation mode")?;
    let initramfs = settings["initramfs"]
        .as_bool()
        .ok_or("invalid initramfs mode")?;
    let hypervisor = settings["hypervisor"]
        .as_str()
        .ok_or("hypervisor path is required")?;
    if !(128..=65536).contains(&memory)
        || !(1..=64).contains(&cpus)
        || lifetime > 86400
        || (lifetime == 0 && !preparation)
        || (preparation && !saved)
    {
        return Err("invalid VM resource limits".into());
    }
    if settings.as_object().is_none_or(|v| v.len() != 8) {
        return Err("invalid VMM request fields".into());
    }
    if networking {
        let suffix = linux::run_suffix(id)?;
        let table = format!("am_{}", &suffix[..16]);
        let tap = format!("amt{}", &suffix[..10]);
        checked(Command::new("/usr/sbin/nft").args(["list", "table", "inet", &table]))?;
        checked(Command::new("/usr/sbin/ip").args(["link", "show", "dev", &tap]))?;
    }
    linux::preflight::check(Path::new(hypervisor))?;
    let root_len = regular_file(&directory.join("rootfs"))?.metadata()?.len();
    let mut cmd = Command::new("/usr/bin/systemd-run");
    cmd.args(["--quiet", "--service-type=exec", "--unit", id]);
    let properties = [
        format!("User={name}"),
        format!("Group={name}"),
        "SupplementaryGroups=kvm".into(),
        format!("RuntimeDirectory={id}"),
        "RuntimeDirectoryMode=0700".into(),
        "RuntimeDirectoryPreserve=yes".into(),
        "UMask=0077".into(),
        "RemainAfterExit=yes".into(),
        format!("PrivateNetwork={}", if networking { "no" } else { "yes" }),
        format!(
            "RestrictAddressFamilies={}",
            if networking {
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
        format!("LimitFSIZE={}", root_len.max(1024 * 1024 * 1024)),
        "KillMode=control-group".into(),
        "TimeoutStopSec=3s".into(),
        format!(
            "RuntimeMaxSec={}",
            if lifetime == 0 {
                "infinity".into()
            } else {
                format!("{lifetime}s")
            }
        ),
        format!("MemoryMax={}M", memory + 256),
        "MemorySwapMax=0".into(),
        format!("CPUQuota={}%", cpus * 100),
        format!("TasksMax={}", cpus * 2 + 64),
        format!(
            "ReadOnlyPaths={}/kernel {}/vm.json{}",
            directory.display(),
            directory.display(),
            if saved {
                String::new()
            } else {
                format!(" {}/rootfs", directory.display())
            }
        ),
        "StandardOutput=null".into(),
        "StandardError=journal".into(),
    ];
    for property in properties {
        cmd.arg("--property").arg(property);
    }
    if networking {
        cmd.arg("--property").arg("DeviceAllow=/dev/net/tun rw");
    }
    if initramfs {
        cmd.arg("--property")
            .arg(format!("ReadOnlyPaths={}/initramfs", directory.display()));
    }
    cmd.arg("--")
        .arg(fs::canonicalize(hypervisor)?)
        .arg("--api-socket")
        .arg(directory.join("api.sock"))
        .args(["--seccomp", "true"]);
    checked(&mut cmd)?;
    Ok(())
}

pub(super) fn stop_vmm(id: &str) -> Result<()> {
    active(id)?;
    let stop = command(Command::new("/usr/bin/systemctl").args(["stop", id]))?;
    if !stop.status.success() {
        let output = checked(Command::new("/usr/bin/systemctl").args([
            "show",
            id,
            "--property=LoadState",
            "--value",
        ]))?;
        let state = String::from_utf8(output.stdout)?;
        if state.trim() != "not-found" {
            return Err("could not stop VMM service".into());
        }
    }
    let _ = command(Command::new("/usr/bin/systemctl").args(["reset-failed", id]));
    Ok(())
}

pub(super) fn ensure_vmm_stopped(id: &str) -> Result<()> {
    active(id)?;
    let output = checked(Command::new("/usr/bin/systemctl").args([
        "show",
        id,
        "--property=ActiveState",
        "--value",
    ]))?;
    let state = String::from_utf8(output.stdout)?;
    if !matches!(state.trim(), "inactive" | "failed") {
        return Err("VM service must be stopped before removing host isolation".into());
    }
    Ok(())
}

pub(super) fn connect_socket(id: &str, kind: &str) -> Result<File> {
    let directory = active(id)?;
    let leaf = match kind {
        "api" => "api.sock",
        "serial" => "serial.sock",
        _ => return Err("unknown VM socket kind".into()),
    };
    let path = directory.join(leaf);
    let metadata = fs::symlink_metadata(&path)?;
    let (vmm_uid, _) = uid_of(&user(id)?)?;
    if !metadata.file_type().is_socket() || metadata.uid() != vmm_uid {
        return Err("untrusted VM socket".into());
    }
    let stream = UnixStream::connect(path)?;
    Ok(unsafe { File::from_raw_fd(stream.into_raw_fd()) })
}

pub(super) fn destroy_run(id: &str) -> Result<()> {
    let directory = active(id)?;
    let name = user(id)?;
    ensure_vmm_stopped(id)?;
    linux::network::HostNetwork::remove_by_id(id)?;
    linux::remove_run_directory(&directory, id)?;
    checked(Command::new("/usr/sbin/userdel").arg(name))?;
    fs::remove_file(marker(id)?)?;
    Ok(())
}
