use super::checked;
use crate::sandbox::Result;
use std::{
    fs::{self, OpenOptions},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    process::Command,
};

pub fn doctor(binary: &Path) -> Result<()> {
    check(binary)?;
    println!("OK: Cloud Hypervisor v53.0, KVM API 12, systemd, cgroup v2, and Landlock.");
    println!("The gateway runs unprivileged; its root helper sets up isolated VM services.");
    Ok(())
}

pub(crate) fn check(binary: &Path) -> Result<()> {
    let meta =
        fs::metadata(binary).map_err(|e| format!("Cloud Hypervisor {}: {e}", binary.display()))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.mode() & 0o111 == 0 {
        return Err(
            "Cloud Hypervisor must be a root-owned executable, not group/world writable".into(),
        );
    }
    for parent in fs::canonicalize(binary)?.ancestors().skip(1) {
        let meta = fs::metadata(parent)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("untrusted Cloud Hypervisor parent directory".into());
        }
    }
    let version = checked(Command::new(binary).arg("--version"))?;
    if String::from_utf8_lossy(&version.stdout).lines().next() != Some("cloud-hypervisor v53.0") {
        return Err("this gateway currently supports Cloud Hypervisor v53.0; validate other versions before upgrading".into());
    }
    let kvm = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("cannot open /dev/kvm: {e}"))?;
    let api_version = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xAE00, 0 as libc::c_ulong) };
    if api_version != 12 {
        return Err(format!(
            "KVM API check returned {api_version}: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0,
            1,
        )
    } < 1
    {
        return Err("Landlock is required by this sandbox profile but is unavailable".into());
    }
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("systemd must be running on Linux".into());
    }
    let controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?;
    for required in ["cpu", "memory", "pids"] {
        if !controllers.split_whitespace().any(|s| s == required) {
            return Err(format!("missing cgroup v2 controller: {required}").into());
        }
    }
    checked(Command::new("/usr/bin/systemd-run").arg("--version"))?;
    Ok(())
}
