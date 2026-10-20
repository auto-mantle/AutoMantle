use super::*;
#[test]
#[ignore = "requires root, tc/mirred, TAP, nftables and a kvm group"]
fn ethernet_gate_catches_unknown_ipv6_vlan_and_direct_ip_before_firewall() {
    let mut vm = Run::create(new_run_id().unwrap()).unwrap();
    let (backend, api) = crate::backend::tests::server(vec![(204, serde_json::Value::Null)]);
    let mut network = HostNetwork::create(&vm.id, &vm.service_user).unwrap();
    network
        .start_policy(
            backend,
            "10000000-0000-0000-0000-000000000001".into(),
            vm.id.clone(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let config = network.config.clone();
    let mut guest = crate::packet_gate::open_tap(&config.tap).unwrap();
    vm.network = Some(network);
    let mac = |value: &str| {
        value
            .split(':')
            .map(|v| u8::from_str_radix(v, 16).unwrap())
            .collect::<Vec<_>>()
    };
    let frame = |ether: u16| {
        let mut bytes = Vec::new();
        bytes.extend(mac(&config.host_mac));
        bytes.extend(mac(&config.guest_mac));
        bytes.extend(ether.to_be_bytes());
        bytes
    };
    let guest_ip = config
        .guest_ip
        .parse::<std::net::Ipv4Addr>()
        .unwrap()
        .octets();
    let host_ip = config
        .host_ip
        .parse::<std::net::Ipv4Addr>()
        .unwrap()
        .octets();
    let mut arp = frame(0x0806);
    let mut payload = vec![0; 28];
    payload[1] = 1;
    payload[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    payload[4] = 6;
    payload[5] = 4;
    payload[7] = 1;
    payload[8..14].copy_from_slice(&mac(&config.guest_mac));
    payload[14..18].copy_from_slice(&guest_ip);
    payload[24..28].copy_from_slice(&host_ip);
    arp.extend(payload);
    guest.write_all(&arp).unwrap();
    let mut response = [0; 2048];
    let response_deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match guest.read(&mut response) {
            Ok(n) => {
                assert!(n >= 42);
                assert_eq!(u16::from_be_bytes([response[20], response[21]]), 2);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < response_deadline,
                    "ARP reply did not cross the policy relay"
                );
                thread::sleep(Duration::from_millis(2));
            }
            other => panic!("unexpected TAP result: {other:?}"),
        }
    }
    let unknown = frame(0x88b5);
    for _ in 0..100 {
        guest.write_all(&unknown).unwrap();
    }
    let mut vlan = frame(0x8100);
    vlan.extend([0, 1, 0x88, 0xb5]);
    vlan.extend([0u8; 46]);
    guest.write_all(&vlan).unwrap();
    let mut ipv6 = frame(0x86dd);
    let mut payload = vec![0; 40];
    payload[0] = 0x60;
    payload[6] = 17;
    payload[24..40].copy_from_slice(
        &"2606:4700:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    ipv6.extend(payload);
    guest.write_all(&ipv6).unwrap();
    for protocol in [6, 17] {
        let mut packet = frame(0x0800);
        let mut payload = vec![0; if protocol == 6 { 40 } else { 28 }];
        let length = payload.len() as u16;
        payload[0] = 0x45;
        payload[2..4].copy_from_slice(&length.to_be_bytes());
        payload[9] = protocol;
        payload[12..16].copy_from_slice(&guest_ip);
        payload[16..20].copy_from_slice(&[1, 1, 1, 1]);
        payload[20..22].copy_from_slice(&50000u16.to_be_bytes());
        payload[22..24].copy_from_slice(&443u16.to_be_bytes());
        if protocol == 6 {
            payload[32] = 0x50;
        }
        packet.extend(payload);
        guest.write_all(&packet).unwrap();
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    while vm
        .network
        .as_ref()
        .unwrap()
        .gate
        .as_ref()
        .unwrap()
        .received()
        < 105
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    vm.network.as_mut().unwrap().gate = None;
    let calls = api.join().unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].0.starts_with("POST /gateway/network-history "));
    let events = calls[0].1.as_array().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|e| e["packetCount"].as_u64().unwrap())
            .sum::<u64>(),
        105
    );
    for protocol in ["UNKNOWN", "TCP", "UDP", "IPV6", "VLAN"] {
        assert!(
            events
                .iter()
                .any(|e| e["protocol"] == protocol && e["reason"] == "UNSUPPORTED_NETWORK"),
            "missing {protocol}: {events:?}"
        );
    }
    assert!(events.iter().any(|e| e["reason"] == "LINK_CONTROL"));
    vm.cleanup().unwrap();
}

#[test]
fn continuous_console_reader_captures_bursts_without_byte_loss() {
    let (stream, mut guest) = UnixStream::pair().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = Arc::clone(&captured);
    let pump = ConsolePump::start(
        stream,
        Arc::new(move |event| {
            if let RunEvent::Console(bytes) = event {
                output.lock().unwrap().extend(bytes);
            }
        }),
    )
    .unwrap();
    let bytes = (0..128 * 1024).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    guest.write_all(&bytes).unwrap();
    drop(guest);
    pump.finish().unwrap();
    assert_eq!(*captured.lock().unwrap(), bytes);
}
#[test]
#[ignore = "requires root, a kvm group, useradd, and permission to bind-mount"]
fn saved_disk_mount_and_cleanup_preserve_preparation_but_discard_runtime() {
    let fixture = crate::storage::tests::Fixture::new();
    fixture.store.create("harness", &fixture.source).unwrap();
    for mode in ["prepare", "runtime"] {
        let lease = fixture.store.acquire("harness", mode == "prepare").unwrap();
        let args = [
            "--kernel",
            fixture.source.to_str().unwrap(),
            "--saved-disk",
            "harness",
            "--storage-mode",
            mode,
            "--gateway-config",
            "/config",
            "--agent-profile-id",
            "10000000-0000-0000-0000-000000000001",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let mut request = RunRequest::parse(&args).unwrap();
        request.rootfs = lease.path.clone();
        let mut run = Run::create(new_run_id().unwrap()).unwrap();
        run.prepare(
            &request,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        fs::write(
            run.directory.join("rootfs"),
            if mode == "prepare" {
                b"saved harness"
            } else {
                b"task changes!"
            },
        )
        .unwrap();
        let runtime_path = run.runtime_root.clone();
        run.cleanup().unwrap();
        assert!(!run.directory.exists());
        assert_eq!(fs::read(&lease.path).unwrap(), b"saved harness");
        assert_eq!(fs::metadata(&lease.path).unwrap().uid(), 0);
        if let Some(path) = runtime_path {
            assert!(!path.exists());
        }
    }
    assert_eq!(
        fs::read(&fixture.source).unwrap(),
        b"installed harness and login state"
    );
}

#[test]
fn cleanup_rejects_parent_sibling_and_malformed_paths() {
    let id = format!("{RUN_PREFIX}{}", "a".repeat(32));
    for path in ["/run", "/", "/run/other", "/tmp"] {
        assert!(remove_run_directory(Path::new(path), &id).is_err());
    }
    assert!(
        remove_run_directory(Path::new("/run/automantle-vm-../"), "automantle-vm-../").is_err()
    );
}

#[test]
fn failed_unmount_preserves_runtime_disk_and_directory() {
    let id = new_run_id().unwrap();
    let directory = std::env::temp_dir().join(&id);
    fs::create_dir(&directory).unwrap();
    let source = directory.join("source");
    let runtime = directory.join("runtime");
    fs::write(&source, b"saved data").unwrap();
    fs::write(&runtime, b"runtime data").unwrap();
    let mut run = Run {
        id,
        service_user: "no-such-vm-user".into(),
        directory: directory.clone(),
        service_started: false,
        console: None,
        network: None,
        proxy: None,
        persistent_root: Some(source.clone()),
        runtime_root: Some(runtime.clone()),
    };
    assert!(run.cleanup().is_err());
    assert!(source.exists());
    assert!(runtime.exists());
    assert!(directory.exists());
    drop(run);
    fs::remove_file(source).unwrap();
    fs::remove_file(runtime).unwrap();
    fs::remove_dir(directory).unwrap();
}
#[test]
fn signal_and_deadline_are_enforced() {
    assert!(
        check_deadline(
            &AtomicBool::new(true),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(check_deadline(&AtomicBool::new(false), Instant::now()).is_err());
}
