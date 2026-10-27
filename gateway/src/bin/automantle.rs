#[cfg(target_os = "linux")]
mod linux {
    use automantle_gateway::{linux, rootless, sandbox::Result};
    use serde_json::json;
    use std::{
        env,
        fs::{self, OpenOptions},
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    const API_UNIT: &str = "automantle-api.service";
    const GATEWAY_UNIT: &str = "automantle-gateway.service";
    const WAIT: Duration = Duration::from_secs(45);

    fn output(command: &mut Command) -> Result<String> {
        let result = command.output()?;
        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            return Err(format!(
                "{} ({}): {}",
                command.get_program().to_string_lossy(),
                result.status,
                detail
            )
            .into());
        }
        Ok(String::from_utf8(result.stdout)?)
    }
    fn systemctl(args: &[&str]) -> Result<String> {
        output(Command::new("/usr/bin/systemctl").arg("--user").args(args))
    }
    fn active(unit: &str) -> Result<bool> {
        Ok(systemctl(&["show", unit, "--property=ActiveState", "--value"])?.trim() == "active")
    }
    fn wait_for(mut ready: impl FnMut() -> bool, unit: &str) -> Result<()> {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if ready() {
                return Ok(());
            }
            if !active(unit)? {
                return Err(format!(
                    "{unit} exited during startup; inspect journalctl --user -u {unit}"
                )
                .into());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(format!(
            "{unit} did not become ready within {} seconds",
            WAIT.as_secs()
        )
        .into())
    }
    fn api_ready(port: u16) -> bool {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let Ok(mut socket) = TcpStream::connect_timeout(&address, Duration::from_millis(300))
        else {
            return false;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(300)));
        let _ = socket.set_write_timeout(Some(Duration::from_millis(300)));
        if socket
            .write_all(
                b"GET /gateway/health HTTP/1.1\r\nHost: localhost\r\nX-Automantle-Gateway: local\r\nConnection: close\r\n\r\n",
            )
            .is_err()
        {
            return false;
        }
        let mut prefix = [0u8; 12];
        socket.read_exact(&mut prefix).is_ok() && &prefix == b"HTTP/1.1 200"
    }
    fn gateway_ready(socket: &Path) -> bool {
        std::os::unix::net::UnixStream::connect(socket)
            .and_then(|mut stream| {
                stream.set_read_timeout(Some(Duration::from_millis(300)))?;
                stream.set_write_timeout(Some(Duration::from_millis(300)))?;
                stream.write_all(b"{\"command\":\"list\"}\n")?;
                let mut buffer = [0u8; 32];
                stream
                    .read_exact(&mut buffer[..10])
                    .map(|_| &buffer[..10] == b"{\"result\":")
            })
            .unwrap_or(false)
    }
    fn start_unit(
        name: &str,
        command: &Path,
        arguments: &[String],
        environment: &[(String, String)],
    ) -> Result<bool> {
        if active(name)? {
            return Ok(false);
        }
        let _ = systemctl(&["reset-failed", name]);
        let mut run = Command::new("/usr/bin/systemd-run");
        run.args(["--user", "--quiet", "--service-type=exec", "--unit", name]);
        for property in [
            "NoNewPrivileges=yes",
            "UMask=0077",
            "KillMode=control-group",
            "TimeoutStopSec=60s",
            "LimitCORE=0",
        ] {
            run.arg("--property").arg(property);
        }
        for (key, value) in environment {
            run.arg(format!("--setenv={key}={}", value));
        }
        run.arg("--").arg(command).args(arguments);
        output(&mut run)?;
        Ok(true)
    }
    fn release_file(base: &Path, relative: &str) -> Result<PathBuf> {
        let path = base.join(relative);
        if !path.is_file() {
            return Err(format!("release is missing {}", path.display()).into());
        }
        Ok(path)
    }
    fn release_root() -> Result<PathBuf> {
        let executable = fs::canonicalize(env::current_exe()?)?;
        Ok(executable
            .parent()
            .and_then(Path::parent)
            .ok_or("invalid release layout")?
            .to_path_buf())
    }
    fn config_file(port: u16) -> Result<PathBuf> {
        let runs = rootless::data_parent()?;
        let data = runs.parent().ok_or("invalid data directory")?;
        let path = data.join("gateway.json");
        let desired = json!({"backendUrl":format!("http://127.0.0.1:{port}")});
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(
                        "gateway config must be a private regular file owned by the current user"
                            .into(),
                    );
                }
                if serde_json::from_slice::<serde_json::Value>(&fs::read(&path)?)? == desired {
                    return Ok(path);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let temporary = data.join(format!("gateway.{}.stage", linux::new_run_id()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| -> Result<()> {
            serde_json::to_writer(&mut file, &desired)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            fs::File::open(data)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(path)
    }
    fn port() -> Result<u16> {
        let value = env::var("AUTOMANTLE_PORT").unwrap_or_else(|_| "8082".into());
        let port: u16 = value.parse()?;
        if port < 1024 {
            return Err("AUTOMANTLE_PORT must be between 1024 and 65535".into());
        }
        Ok(port)
    }
    fn up() -> Result<()> {
        let port = port()?;
        let base = release_root()?;
        let gateway = release_file(&base, "bin/automantle-gateway")?;
        let hypervisor = release_file(&base, "bin/cloud-hypervisor")?;
        let java = release_file(&base, "runtime/bin/java")?;
        let jar = release_file(&base, "app/api.jar")?;
        let kernel = release_file(&base, "share/guest/kernel")?;
        let rootfs = release_file(&base, "share/guest/linux.ext4")?;
        rootless::runtime_parent()?;
        output(
            Command::new(&gateway)
                .args(["doctor", "--cloud-hypervisor"])
                .arg(&hypervisor),
        )?;
        let socket = rootless::runtime_parent()?.join("control.sock");
        let config = config_file(port)?;
        let data = rootless::data_parent()?;
        let application_data = data.parent().ok_or("invalid data directory")?;
        let data_home = application_data.parent().ok_or("invalid data directory")?;
        let api_started = start_unit(
            API_UNIT,
            &java,
            &["-jar".into(), jar.to_string_lossy().into_owned()],
            &[
                (
                    "AUTOMANTLE_GATEWAY_SOCKET".into(),
                    socket.to_string_lossy().into_owned(),
                ),
                (
                    "AUTOMANTLE_GATEWAY_BINARY".into(),
                    gateway.to_string_lossy().into_owned(),
                ),
                (
                    "AUTOMANTLE_DATA_DIR".into(),
                    application_data.to_string_lossy().into_owned(),
                ),
                ("PORT".into(), port.to_string()),
            ],
        )?;
        let result = (|| -> Result<()> {
            wait_for(|| api_ready(port), API_UNIT)?;
            let gateway_started = start_unit(
                GATEWAY_UNIT,
                &gateway,
                &[
                    "start".into(),
                    "--gateway-config".into(),
                    config.to_string_lossy().into_owned(),
                    "--cloud-hypervisor".into(),
                    hypervisor.to_string_lossy().into_owned(),
                    "--default-kernel".into(),
                    kernel.to_string_lossy().into_owned(),
                    "--default-rootfs".into(),
                    rootfs.to_string_lossy().into_owned(),
                ],
                &[(
                    "XDG_DATA_HOME".into(),
                    data_home.to_string_lossy().into_owned(),
                )],
            )?;
            if let Err(error) = wait_for(|| gateway_ready(&socket), GATEWAY_UNIT) {
                if gateway_started {
                    let _ = systemctl(&["stop", GATEWAY_UNIT]);
                }
                return Err(error);
            }
            Ok(())
        })();
        if result.is_err() && api_started {
            let _ = systemctl(&["stop", API_UNIT]);
        }
        result?;
        println!("AutoMantle is ready at http://127.0.0.1:{port}");
        Ok(())
    }
    fn stop_vm_units(errors: &mut Vec<String>) {
        let listed = systemctl(&[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "automantle-vm-*.service",
        ]);
        match listed {
            Ok(units) => {
                for line in units.lines() {
                    let Some(unit) = line.split_whitespace().next() else {
                        continue;
                    };
                    let Some(id) = unit.strip_suffix(".service") else {
                        continue;
                    };
                    if !automantle_gateway::linux::valid_run_id(id) {
                        continue;
                    }
                    match active(unit) {
                        Ok(true) => {
                            if let Err(error) = systemctl(&["stop", unit]) {
                                errors.push(format!("{unit}: {error}"));
                            }
                        }
                        Ok(false) => (),
                        Err(error) => errors.push(format!("{unit}: {error}")),
                    }
                }
            }
            Err(error) => errors.push(format!("cannot list VM units: {error}")),
        }
    }
    fn down() -> Result<()> {
        rootless::runtime_parent()?;
        let mut errors = Vec::new();
        for unit in [GATEWAY_UNIT, API_UNIT] {
            if active(unit).unwrap_or(false) {
                if let Err(error) = systemctl(&["stop", unit]) {
                    errors.push(format!("{unit}: {error}"));
                }
            }
        }
        stop_vm_units(&mut errors);
        for unit in [GATEWAY_UNIT, API_UNIT] {
            match active(unit) {
                Ok(true) => errors.push(format!("{unit} is still active")),
                Err(error) => errors.push(format!("cannot verify {unit}: {error}")),
                _ => (),
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("; ").into());
        }
        println!("AutoMantle is stopped");
        Ok(())
    }
    pub fn main() -> Result<()> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("run automantle as an ordinary user, without sudo".into());
        }
        match env::args().skip(1).collect::<Vec<_>>().as_slice() {
            [command] if command == "up" => up(),
            [command] if command == "down" => down(),
            _ => Err("usage: automantle up|down".into()),
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    let result = linux::main();
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), &str> = Err("AutoMantle supports Linux only");
    if let Err(error) = result {
        eprintln!("automantle: {error}");
        std::process::exit(1);
    }
}
