use super::*;
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    time::Duration,
};
const PROFILE: &str = "10000000-0000-0000-0000-000000000001";
fn args() -> Vec<String> {
    [
        "--kernel",
        "/kernel",
        "--rootfs",
        "/rootfs",
        "--agent-profile-id",
        PROFILE,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
fn manager(backend: Backend, runner: Runner) -> Manager {
    Manager {
        backend,
        config: "/config".into(),
        hypervisor: "/hypervisor".into(),
        storage: crate::storage::Store {
            directory: "/var/lib/automantle/vms".into(),
        },
        defaults: Defaults::default(),
        machine_runs: BTreeMap::new(),
        tasks: BTreeMap::new(),
        imports: Vec::new(),
        runner,
    }
}
fn live_runner() -> Runner {
    Arc::new(|_, _, _, cancel, event| {
        event(RunEvent::State("running"));
        event(RunEvent::Console(vec![b'x'; CONSOLE_LIMIT + 50]));
        while !cancel.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(5));
        }
        Err("run interrupted".into())
    })
}
fn await_finished(task: &Task) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !task.worker.is_finished() {
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn import_workers_do_not_block_controls_and_shutdown_cancels_them() {
    let (backend, server) = crate::backend::tests::server(vec![]);
    let mut manager = manager(backend, live_runner());
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    manager.imports.push(Import {
        cancel,
        worker: thread::spawn(move || {
            while !worker_cancel.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(5));
            }
        }),
    });
    assert_eq!(
        manager.command(&json!({"command":"list"})).unwrap(),
        json!([])
    );
    manager.shutdown();
    assert!(manager.imports.is_empty());
    server.join().unwrap();
}

#[test]
fn disk_import_worker_returns_the_completed_disk_to_its_caller() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = crate::storage::tests::Fixture::new();
    let (backend, server) = crate::backend::tests::server(vec![]);
    let mut manager = manager(backend, live_runner());
    manager.storage = fixture.store.clone();
    let (mut client, stream) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    manager.import_disk(json!({"command":"create-disk", "args":["--name", "background", "--rootfs", fixture.source]}), stream);
    assert_eq!(
        manager.command(&json!({"command":"list"})).unwrap(),
        json!([])
    );
    let mut reply = String::new();
    BufReader::new(&mut client).read_line(&mut reply).unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["result"]["name"], "background");
    manager.shutdown();
    assert_eq!(
        fs::read(fixture.store.directory.join("background/rootfs")).unwrap(),
        fs::read(&fixture.source).unwrap()
    );
    server.join().unwrap();
}

#[test]
fn two_runs_share_manager_and_stop_independently() {
    let second_profile = "10000000-0000-0000-0000-000000000002";
    let (backend, server) = crate::backend::tests::server(vec![
        (200, json!({"id":PROFILE})),
        (200, json!({"id":second_profile})),
    ]);
    let mut manager = manager(backend, live_runner());
    let first = manager.launch(&args()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut second_args = args();
    *second_args.last_mut().unwrap() = second_profile.into();
    let second = manager.launch(&second_args).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(first, second);
    manager
        .command(&json!({"command":"stop-vm","id":first}))
        .unwrap();
    await_finished(&manager.tasks[&first]);
    assert_eq!(
        manager.tasks[&first].record.lock().unwrap().state,
        "stopped"
    );
    assert!(!manager.tasks[&second].worker.is_finished());
    assert_eq!(
        manager
            .command(&json!({"command":"list"}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    manager.shutdown();
    assert!(manager.tasks.is_empty());
    let requests = server.join().unwrap();
    assert!(
        requests
            .iter()
            .all(|(header, _)| header.contains("/gateway/agent-profiles/"))
    );
}
#[test]
fn missing_deleted_or_mismatched_profile_never_starts_runner() {
    let (backend, server) =
        crate::backend::tests::server(vec![(404, json!({})), (200, json!({"id":"other"}))]);
    let mut manager = manager(backend, Arc::new(|_, _, _, _, _| panic!("must not start")));
    assert!(
        manager
            .launch(&[
                "--kernel".into(),
                "/k".into(),
                "--rootfs".into(),
                "/r".into()
            ])
            .is_err()
    );
    assert!(manager.launch(&args()).is_err());
    assert!(manager.launch(&args()).is_err());
    assert!(manager.tasks.is_empty());
    assert_eq!(server.join().unwrap().len(), 2);
}
#[test]
fn worker_failure_does_not_stop_manager_and_console_is_bounded() {
    let (backend, server) = crate::backend::tests::server(vec![
        (200, json!({"id":PROFILE})),
        (200, json!({"id":PROFILE})),
    ]);
    let mut manager = manager(
        backend,
        Arc::new(|_, _, _, _, event| {
            event(RunEvent::Console(vec![b'x'; CONSOLE_LIMIT + 50]));
            Err("boot failed".into())
        }),
    );
    let first = manager.launch(&args()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    await_finished(&manager.tasks[&first]);
    let logs = manager
        .command(&json!({"command":"logs","id":first}))
        .unwrap();
    assert_eq!(logs["state"], "failed");
    assert_eq!(logs["error"], "boot failed");
    assert_eq!(logs["console"].as_str().unwrap().len(), CONSOLE_LIMIT);
    assert!(manager.launch(&args()).is_ok());
    assert!(
        manager
            .command(&json!({"command":"stop-vm","id":"missing"}))
            .is_err()
    );
    manager.shutdown();
    server.join().unwrap();
}
#[test]
fn control_protocol_rejects_oversize_and_incomplete_requests() {
    for bytes in [vec![b'x'; REQUEST_LIMIT + 1], b"{}".to_vec()] {
        let (read, mut write) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            let _ = write.write_all(&bytes);
        });
        assert!(read_request(&read).is_err());
        drop(read);
        sender.join().unwrap();
    }
    let (read, mut write) = UnixStream::pair().unwrap();
    write.write_all(b"{\"command\":\"list\"}\n").unwrap();
    assert_eq!(read_request(&read).unwrap(), json!({"command":"list"}));
}

#[test]
fn saved_disk_locks_cover_queued_runs_and_profiles_are_selected_per_run() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let other = "10000000-0000-0000-0000-000000000002";
    let (backend, server) = crate::backend::tests::server(
        [PROFILE, PROFILE, other, PROFILE, PROFILE, other]
            .into_iter()
            .map(|id| (200, json!({"id":id})))
            .collect(),
    );
    let fixture = crate::storage::tests::Fixture::new();
    fixture.store.create("harness", &fixture.source).unwrap();
    let mut manager = manager(backend, live_runner());
    manager.storage.directory = fixture.store.directory.clone();
    let saved_args = |profile: &str, mode: &str| {
        [
            "--kernel",
            "/kernel",
            "--saved-disk",
            "harness",
            "--agent-profile-id",
            profile,
            "--storage-mode",
            mode,
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    };
    let first = manager.launch(&saved_args(PROFILE, "prepare")).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(manager.launch(&saved_args(PROFILE, "runtime")).is_err());
    manager
        .command(&json!({"command":"stop-vm","id":first}))
        .unwrap();
    await_finished(&manager.tasks[&first]);
    let second = manager.launch(&saved_args(other, "runtime")).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let third = manager.launch(&saved_args(PROFILE, "runtime")).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let listing = manager.command(&json!({"command":"list"})).unwrap();
    let record = listing
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == second)
        .unwrap();
    assert_eq!(record["agentProfileId"], other);
    assert_eq!(record["savedDisk"], "harness");
    assert_eq!(record["storageMode"], "runtime");
    assert!(manager.launch(&saved_args(PROFILE, "prepare")).is_err());
    for id in [&second, &third] {
        manager
            .command(&json!({"command":"stop-vm","id":id}))
            .unwrap();
        await_finished(&manager.tasks[id]);
    }
    assert!(manager.launch(&saved_args(other, "prepare")).is_ok());
    manager.shutdown();
    assert_eq!(server.join().unwrap().len(), 6);
    assert_eq!(
        fs::read(fixture.store.directory.join("harness/rootfs")).unwrap(),
        fs::read(&fixture.source).unwrap()
    );
}

#[test]
fn terminal_preserves_bytes_cursors_and_rejects_input_after_stop() {
    let (backend, server) = crate::backend::tests::server(vec![(200, json!({"id":PROFILE}))]);
    let (mut guest, host) = UnixStream::pair().unwrap();
    let host = Arc::new(Mutex::new(Some(host)));
    let mut manager = manager(
        backend,
        Arc::new(move |_, _, _, cancel, event| {
            event(RunEvent::Terminal(host.lock().unwrap().take().unwrap()));
            event(RunEvent::Console(vec![b'A'; CONSOLE_LIMIT + 9]));
            event(RunEvent::State("running"));
            while !cancel.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        }),
    );
    let id = manager.launch(&args()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..100 {
        if manager.tasks[&id].record.lock().unwrap().state == "running" {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let reply = manager
        .command(&json!({"command":"terminal-read","id":id,"offset":0}))
        .unwrap();
    assert_eq!(reply["start"], 9);
    assert_eq!(reply["next"], 9 + 64 * 1024);
    assert_eq!(reply["gap"], true);
    assert!(
        manager
            .command(&json!({"command":"terminal-read","id":id,"offset":CONSOLE_LIMIT + 10}))
            .is_err()
    );
    let bytes = vec![3u8, 27, 195, 169, 13];
    let written = manager
        .command(&json!({"command":"terminal-write","id":id,"data":bytes}))
        .unwrap();
    assert_eq!(written["written"], bytes.len());
    let mut received = vec![0; bytes.len()];
    guest.read_exact(&mut received).unwrap();
    assert_eq!(received, bytes);
    for invalid in [
        json!([]),
        json!([256]),
        json!([-1]),
        json!([null]),
        json!(vec![0; 4097]),
    ] {
        assert!(
            manager
                .command(&json!({"command":"terminal-write","id":id,"data":invalid}))
                .is_err()
        );
    }
    manager
        .command(&json!({"command":"stop-vm","id":id}))
        .unwrap();
    await_finished(&manager.tasks[&id]);
    assert!(
        manager
            .command(&json!({"command":"terminal-write","id":id,"data":[1]}))
            .is_err()
    );
    assert_eq!(
        manager
            .command(&json!({"command":"terminal-read","id":id,"offset":0}))
            .unwrap()["ready"],
        false
    );
    server.join().unwrap();
}
