use crate::{
    backend::Backend,
    credentials::Credentials,
    linux::{EventSink, RunEvent},
    machines::Machine,
    proxy::{Proxy, ProxyConfig},
    rootless,
    sandbox::Result,
    tls::Tls,
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const PROXY_ADDRESS: &str = "10.0.2.100:3128";

fn qmp_ready(path: &Path) -> Result<()> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    read_qmp_greeting(stream)
}

fn read_qmp_greeting(stream: UnixStream) -> Result<()> {
    let mut greeting = String::new();
    BufReader::new(stream)
        .take(65536)
        .read_line(&mut greeting)?;
    let value: serde_json::Value = serde_json::from_str(&greeting)?;
    if !value.get("QMP").is_some_and(serde_json::Value::is_object) {
        return Err("QEMU did not send a QMP greeting".into());
    }
    Ok(())
}

pub fn run(
    machine: Machine,
    disk: PathBuf,
    install: bool,
    backend: Backend,
    credentials_path: PathBuf,
    tls_path: PathBuf,
    id: String,
    cancelled: Arc<AtomicBool>,
    event: EventSink,
) -> Result<()> {
    backend.validate_profile(&machine.settings.agent_profile_id)?;
    let iso = machine.iso_path.as_ref().ok_or("VM has no installer ISO")?;
    if install && !Path::new(iso).is_file() {
        return Err("The selected ISO file is no longer available on this machine".into());
    }
    let qemu = env::var_os("AUTOMANTLE_QEMU_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let bundled = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("automantle-qemu")));
            bundled
                .filter(|p| p.is_file())
                .unwrap_or_else(|| PathBuf::from("/usr/bin/qemu-system-x86_64"))
        });
    if !qemu.is_absolute() || !qemu.is_file() {
        return Err(
            "QEMU is required to install and run an OS from an ISO (qemu-system-x86_64)".into(),
        );
    }
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err("A desktop display is needed to show the OS installer and VM window".into());
    }
    let (runtime, _temporary_disks) = rootless::create_run(&id)?;
    let result = (|| -> Result<()> {
        event(RunEvent::State("preparing"));
        let gateway = env::current_exe()?;
        let helper = gateway
            .parent()
            .ok_or("invalid gateway path")?
            .join("automantle-proxy-stdio");
        if !helper.is_file() {
            return Err("AutoMantle proxy helper is missing".into());
        }
        let local_helper = runtime.join("proxy-stdio");
        fs::copy(helper, &local_helper)?;
        fs::set_permissions(&local_helper, fs::Permissions::from_mode(0o700))?;
        let proxy_socket = runtime.join("proxy.sock");
        let tls = if tls_path.is_file() {
            Some(Tls::load(
                &tls_path,
                Instant::now() + Duration::from_secs(100 * 365 * 24 * 60 * 60),
            )?)
        } else {
            None
        };
        let proxy = Proxy::start_unix(
            ProxyConfig {
                backend,
                profile: machine.settings.agent_profile_id.clone(),
                tls,
                credentials: Credentials::default().with_managed(credentials_path),
                cancelled: Arc::clone(&cancelled),
                deadline: Instant::now() + Duration::from_secs(100 * 365 * 24 * 60 * 60),
                setup_mode: machine.settings.setup,
            },
            &proxy_socket,
        )?;
        let qmp = runtime.join("qmp.sock");
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args([
                "--user",
                "--wait",
                "--collect",
                "--pipe",
                "--service-type=exec",
                "--expand-environment=no",
                "--unit",
                &id,
            ])
            .arg("--working-directory")
            .arg(disk.parent().ok_or("invalid VM disk path")?)
            .args([
                "--property=NoNewPrivileges=yes",
                "--property=UMask=0077",
                "--property=KillMode=control-group",
            ])
            .arg(format!(
                "--property=MemoryMax={}M",
                machine.settings.memory_mib + 512
            ))
            .arg(format!(
                "--property=CPUQuota={}%",
                machine.settings.vcpu_count * 100
            ))
            .arg("--property=TasksMax=256")
            .arg(format!(
                "--setenv=AUTOMANTLE_PROXY_SOCKET={}",
                proxy_socket.display()
            ));
        for key in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
        ] {
            if let Ok(value) = env::var(key) {
                command.arg(format!("--setenv={key}={value}"));
            }
        }
        command.arg("--").arg(qemu);
        command.current_dir(disk.parent().ok_or("invalid VM disk path")?);
        command
            .args(["-enable-kvm", "-machine", "q35", "-cpu", "host", "-m"])
            .arg(machine.settings.memory_mib.to_string())
            .arg("-smp")
            .arg(machine.settings.vcpu_count.to_string())
            .args(["-drive", "file=rootfs,format=raw,if=virtio"])
            .arg("-nic")
            .arg(format!(
                "user,restrict=on,guestfwd=tcp:{PROXY_ADDRESS}-cmd:{}",
                format!(
                    "'{}'",
                    local_helper.to_string_lossy().replace('\'', "'\\''")
                )
                .replace(',', ",,")
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server=on,wait=off", qmp.display()))
            .args(["-display", "gtk", "-vga", "std", "-monitor", "none"])
            .env("AUTOMANTLE_PROXY_SOCKET", &proxy_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if install {
            command
                .arg("-cdrom")
                .arg(iso)
                .args(["-boot", "order=d", "-no-reboot"]);
        } else {
            command.args(["-boot", "order=c"]);
        }
        // Keep startup diagnostics with the saved VM, outside the disposable runtime directory.
        let error_log = disk
            .parent()
            .ok_or("invalid VM disk path")?
            .join("qemu.log");
        let log = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&error_log)?;
        command.stdout(log.try_clone()?).stderr(log);
        let mut child = command.spawn()?;
        let startup_deadline = Instant::now() + Duration::from_secs(30);
        let mut ready = false;
        let result = loop {
            if cancelled.load(Ordering::Relaxed) {
                let _ = rootless::stop_vmm(&id);
                let _ = child.kill();
                let _ = child.wait();
                break Err("run interrupted".into());
            }
            if let Err(error) = proxy.check() {
                break Err(error);
            }
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => break Err(error.into()),
            };
            if let Some(status) = status {
                if status.success() && ready {
                    break Ok(());
                }
                let detail = fs::read_to_string(&error_log).unwrap_or_default();
                break Err(format!(
                    "QEMU exited ({status}): {}. Log: {}",
                    detail.trim(),
                    error_log.display()
                )
                .into());
            }
            if !ready {
                match qmp_ready(&qmp) {
                    Ok(()) => {
                        ready = true;
                        event(RunEvent::State("running"));
                    }
                    Err(error) if Instant::now() >= startup_deadline => {
                        let detail = fs::read_to_string(&error_log).unwrap_or_default();
                        break Err(format!(
                            "QEMU did not become ready within 30 seconds: {error}; {}. Log: {}",
                            detail.trim(),
                            error_log.display()
                        )
                        .into());
                    }
                    Err(_) => (),
                }
            }
            thread::sleep(Duration::from_millis(100));
        };
        if result.is_err() {
            let _ = rootless::stop_vmm(&id);
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    })();
    if let Err(error) = &result {
        eprintln!("run={id} QEMU launch/run failed: {error}");
    }
    if let Err(error) = rootless::destroy_run(&id) {
        eprintln!("run={id} cleanup failed: {error}");
    }
    result
}

pub fn request_shutdown(id: &str) -> Result<()> {
    let socket = rootless::run_path(id)?.join("qmp.sock");
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut greeting = [0u8; 4096];
    let _ = stream.read(&mut greeting)?;
    stream.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    let _ = stream.read(&mut greeting)?;
    stream.write_all(b"{\"execute\":\"system_powerdown\"}\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_a_qmp_greeting() {
        for (greeting, expected) in [
            ("{\"QMP\":{\"version\":{},\"capabilities\":[]}}\r\n", true),
            ("{\"return\":{}}\n", false),
            ("{\"QMP\":null}\n", false),
            ("not JSON\n", false),
            ("", false),
        ] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(greeting.as_bytes()).unwrap();
            drop(writer);
            assert_eq!(read_qmp_greeting(reader).is_ok(), expected, "{greeting}");
        }
    }

    #[test]
    fn readiness_accepts_a_fragmented_greeting() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = thread::spawn(move || {
            writer.write_all(b"{\"QMP\":").unwrap();
            thread::sleep(Duration::from_millis(10));
            writer.write_all(b"{}}\r\n").unwrap();
        });
        read_qmp_greeting(reader).unwrap();
        sender.join().unwrap();
    }
}
