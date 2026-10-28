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
    fs::{self, File},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
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
        let error_log = runtime.join("qemu-stderr.log");
        command.stderr(File::create(&error_log)?);
        let mut child = command.spawn()?;
        event(RunEvent::State("running"));
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
                if status.success() {
                    break Ok(());
                }
                let detail = fs::read_to_string(&error_log).unwrap_or_default();
                break Err(format!("QEMU exited ({status}): {}", detail.trim()).into());
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
