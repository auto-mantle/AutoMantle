#![cfg(target_os = "linux")]
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Cleanup {
    child: Option<Child>,
    directory: std::path::PathBuf,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            let _ = child.wait();
        }
        let _ = fs::remove_file(self.directory.join("gateway.json"));
        let _ = fs::remove_file(self.directory.join("source"));
        let _ = fs::remove_file(self.directory.join("disks/harness/rootfs"));
        let _ = fs::remove_dir(self.directory.join("disks/harness"));
        let _ = fs::remove_dir(self.directory.join("disks"));
        let _ = fs::remove_dir(&self.directory);
    }
}

#[test]
fn persistent_cli_requires_profile_and_does_not_replace_running_manager() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("run this lifecycle test as root to check the protected socket");
        return;
    }
    let directory = std::path::PathBuf::from(format!(
        "/run/automantle-manager-test-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut cleanup = Cleanup {
        child: None,
        directory: directory.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = directory.join("gateway.json");
    fs::write(
        &config,
        format!(
            "{{\"backendUrl\":\"http://{}\"}}",
            listener.local_addr().unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let server = thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut data = Vec::new();
                let mut byte = [0];
                while !data.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    data.push(byte[0]);
                }
                let health = data.starts_with(b"GET /gateway/health ");
                let body = if health {
                    "{\"status\":\"ready\"}"
                } else {
                    "{}"
                };
                let code = if health { 200 } else { 404 };
                write!(stream, "HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    let socket = directory.join("control.sock");
    let disks = directory.join("disks");
    let source = directory.join("source");
    fs::write(&source, b"saved harness installation").unwrap();
    let binary = env!("CARGO_BIN_EXE_automantle-gateway");
    let command = |args: &[&str]| {
        Command::new(binary)
            .args(args)
            .arg("--socket")
            .arg(&socket)
            .output()
            .unwrap()
    };
    cleanup.child = Some(
        Command::new(binary)
            .args(["start", "--gateway-config"])
            .arg(&config)
            .arg("--disk-directory")
            .arg(&disks)
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if command(&["list"]).status.success() {
            break;
        }
        assert!(Instant::now() < deadline, "manager did not become ready");
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !command(&["start", "--gateway-config", config.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        command(&[
            "create-disk",
            "--name",
            "harness",
            "--rootfs",
            source.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(
        !command(&[
            "create-disk",
            "--name",
            "harness",
            "--rootfs",
            source.to_str().unwrap()
        ])
        .status
        .success()
    );
    let saved = command(&["list-disks"]);
    assert!(saved.status.success());
    let saved: serde_json::Value = serde_json::from_slice(&saved.stdout).unwrap();
    assert_eq!(saved[0]["name"], "harness");
    assert!(
        !command(&["launch", "--kernel", "/missing", "--rootfs", "/missing"])
            .status
            .success()
    );
    assert!(
        !command(&[
            "launch",
            "--kernel",
            "/missing",
            "--rootfs",
            "/missing",
            "--agent-profile-id",
            "10000000-0000-0000-0000-000000000001"
        ])
        .status
        .success()
    );
    let list = command(&["list"]);
    assert!(list.status.success());
    assert_eq!(String::from_utf8(list.stdout).unwrap().trim(), "[]");
    assert!(command(&["stop"]).status.success());
    assert!(cleanup.child.as_mut().unwrap().wait().unwrap().success());
    cleanup.child = None;
    assert!(!socket.exists());
    assert_eq!(
        fs::read(disks.join("harness/rootfs")).unwrap(),
        fs::read(&source).unwrap()
    );
    done.store(true, Ordering::Relaxed);
    server.join().unwrap();
}
