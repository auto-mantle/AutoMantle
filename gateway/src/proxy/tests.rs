use super::destination::{parse_target, public_address};
use super::request::connect_host;
use super::*;
const PROFILE: &str = "10000000-0000-0000-0000-000000000001";

#[test]
fn raw_protected_values_in_destinations_never_enter_policy_metadata() {
    for target in [
        "/synthetic-secret-123456789",
        "/?key=synthetic-secret-123456789",
    ] {
        let (backend, api) = crate::backend::tests::server(vec![(204, serde_json::Value::Null)]);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: test_credentials("api.example.com"),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, &context).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        write!(
            client,
            "GET http://api.example.com{target} HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        )
        .unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 403"));
        worker.join().unwrap();
        let records = api.join().unwrap();
        assert_eq!(records.len(), 1);
        assert!(
            !serde_json::to_string(&records)
                .unwrap()
                .contains("synthetic-secret-123456789")
        );
    }
}

#[test]
fn revoked_managed_alias_never_writes_an_upstream_header() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = crate::storage::tests::Fixture::new();
    fixture
        .store
        .save_credential(
            crate::credentials::SaveCredential {
                name: "GITHUB_TOKEN".into(),
                secret: Some("synthetic-host-secret-12345".into()),
                scopes: None,
            },
            true,
        )
        .unwrap();
    let snapshot = Credentials::default()
        .with_managed(fixture.store.credential_path())
        .snapshot()
        .unwrap();
    let (backend, api) = crate::backend::tests::server(vec![]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials: snapshot,
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    fixture.store.delete_credential("GITHUB_TOKEN").unwrap();
    let request = parse_request(
        b"GET /api HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer GITHUB_TOKEN\r\n\r\n",
        Some("api.example.com"),
    )
    .unwrap();
    let mut upstream = std::io::Cursor::new(Vec::<u8>::new());
    let mut client = Vec::new();
    forward(&mut client, &mut upstream, &request, &context).unwrap();
    assert!(upstream.get_ref().is_empty());
    assert!(
        String::from_utf8(client)
            .unwrap()
            .starts_with("HTTP/1.1 403")
    );
    assert!(api.join().unwrap().is_empty());
}

#[test]
fn query_and_encoded_paths_preserve_wire_bytes_but_hide_values_from_review() {
    let raw = b"POST /api/users/%C3%A9?alt=sse&code=synthetic-query HTTP/1.1\r\nHost: api.example.com\r\nX-Goog-Api-Client: synthetic-header\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n";
    let mut request = parse_request(raw, Some("api.example.com")).unwrap();
    request.body = b"{}".to_vec();
    assert_eq!(request.path, "/api/users/%C3%A9");
    assert_eq!(
        request.target,
        "/api/users/%C3%A9?alt=sse&code=synthetic-query"
    );
    let action = request.action();
    assert!(!action.to_string().contains("synthetic-query"));
    assert!(!action.to_string().contains("synthetic-header"));
    request.target.push_str("x");
    assert_ne!(action["request_sha256"], request.action()["request_sha256"]);
    request.headers.push(("x-extra".into(), "different".into()));
    let changed = request.action();
    request.headers.pop();
    assert_ne!(
        changed["request_sha256"],
        request.action()["request_sha256"]
    );
    assert_eq!(
        parse_target("http://example.com?alt=sse"),
        Some(("example.com".into(), "/".into()))
    );
    let invalid = parse_request(
        b"GET /api/%75sers HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        Some("api.example.com"),
    )
    .unwrap();
    assert_eq!(invalid.path, "/api/%75sers");
}
#[test]
fn chunked_uploads_are_bounded_and_reframed_without_ambiguous_lengths() {
    let mut body = Vec::new();
    let mut reader = std::io::Cursor::new(b"3;upload=yes\r\na\0b\r\n2\r\ncd\r\n0\r\n\r\nunread");
    read_chunked_request(&mut reader, &mut body).unwrap();
    assert_eq!(body, b"a\0bcd");
    assert!(reader.position() < reader.get_ref().len() as u64);
    for bytes in [
        b"800001\r\n".as_slice(),
        b"+3\r\nabc\r\n0\r\n\r\n",
        b"3\r\nabcxx",
        b"0\r\nAuthorization: hidden\r\n\r\n",
    ] {
        assert!(read_chunked_request(&mut std::io::Cursor::new(bytes), &mut Vec::new()).is_err());
    }
    let request = parse_request(b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nContent-Type: multipart/form-data; boundary=synthetic\r\n\r\n", Some("api.example.com")).unwrap();
    assert!(request.chunked);
    assert_eq!(
        request.content_type,
        "multipart/form-data; boundary=synthetic"
    );
}
#[test]
fn vm_oauth_sse_flushes_first_event_before_reading_next_event() {
    use std::sync::Mutex;
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl RequestMonitor for Output {
        fn end_reason(&mut self) -> Option<EndReason> {
            None
        }
    }
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct Upstream {
        response: std::io::Cursor<Vec<u8>>,
        boundary: u64,
        output: Arc<Mutex<Vec<u8>>>,
        written: Vec<u8>,
    }
    impl Read for Upstream {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.response.position() == self.boundary {
                assert!(
                    String::from_utf8_lossy(&self.output.lock().unwrap())
                        .contains("data: hello\n\n"),
                    "first SSE event was buffered"
                );
            }
            self.response.read(bytes)
        }
    }
    impl Write for Upstream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (backend, api) = crate::backend::tests::server(vec![]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials: test_guest_credentials("api.example.com"),
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let mut request = parse_request(b"POST /api?alt=sse HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer synthetic-vm-login-token\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n", Some("api.example.com")).unwrap();
    request.body = b"{}".to_vec();
    assert!(context.credentials.validate(
        &request.headers,
        PROFILE,
        &request.host,
        &request.method,
        &request.path,
        true
    ));
    let first = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: hello\n\n\r\n";
    let mut response = first.to_vec();
    response.extend_from_slice(b"D\r\ndata: world\n\n\r\n0\r\n\r\n");
    let output = Arc::new(Mutex::new(Vec::new()));
    let mut upstream = Upstream {
        response: std::io::Cursor::new(response.clone()),
        boundary: first.len() as u64,
        output: Arc::clone(&output),
        written: Vec::new(),
    };
    forward(
        &mut Output(Arc::clone(&output)),
        &mut upstream,
        &request,
        &context,
    )
    .unwrap();
    assert_eq!(*output.lock().unwrap(), response);
    assert!(
        String::from_utf8(upstream.written)
            .unwrap()
            .starts_with("POST /api?alt=sse HTTP/1.1\r\n")
    );
    assert!(api.join().unwrap().is_empty());
}
#[test]
fn rejected_proxy_requests_report_destinations_without_sensitive_payloads() {
    for (raw, reason, host, port) in [
        (
            "CONNECT brain.example.com:443 HTTP/1.1\r\nHost: brain.example.com\r\n\r\n",
            "HTTPS_DISABLED",
            "brain.example.com",
            443,
        ),
        (
            "GET http://brain.example.com/models?key=private-query HTTP/1.1\r\nHost: brain.example.com\r\nAuthorization: Bearer private-header\r\n\r\n",
            "CREDENTIAL_BINDING_DENIED",
            "brain.example.com",
            80,
        ),
    ] {
        let (backend, api) = crate::backend::tests::server(if reason == "HTTPS_DISABLED" {
            vec![(204, serde_json::Value::Null)]
        } else {
            vec![
                (200, serde_json::json!({"decision":"ALLOW"})),
                (204, serde_json::Value::Null),
            ]
        });
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: test_credentials("brain.example.com"),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(raw.as_bytes()).unwrap();
        handle(server, &context).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 4"));
        let requests = api.join().unwrap();
        assert_eq!(
            requests.len(),
            if reason == "HTTPS_DISABLED" { 1 } else { 2 }
        );
        let event = &requests.last().unwrap().1;
        assert_eq!(event["reason"], reason);
        assert_eq!(event["host"], host);
        assert_eq!(event["port"], port);
        assert!(event["path"].is_null());
        assert_eq!(event["requestId"].as_str().unwrap().len(), 36);
        let wire = event.to_string();
        assert!(!wire.contains("private-query"));
        assert!(!wire.contains("private-header"));
    }
}

#[test]
fn custom_and_read_methods_forward_exact_bodies_and_repeated_headers() {
    struct Upstream {
        response: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Upstream {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(bytes)
        }
    }
    impl Write for Upstream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for method in ["GET", "OPTIONS", "PROPFIND"] {
        let (backend, api) = crate::backend::tests::server(vec![]);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: Credentials::default(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let raw = format!(
            "{method} /api HTTP/1.1\r\nHost: brain.example.com\r\nContent-Type: application/json\r\nContent-Length: 7\r\nAccept: application/json\r\nAccept: text/plain\r\n\r\n"
        );
        let mut request = parse_request(raw.as_bytes(), Some("brain.example.com")).unwrap();
        request.body = b"{broken".to_vec();
        let mut upstream = Upstream {
            response: std::io::Cursor::new(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
            written: Vec::new(),
        };
        forward(&mut Vec::new(), &mut upstream, &request, &context).unwrap();
        let sent = String::from_utf8(upstream.written).unwrap();
        assert!(sent.starts_with(&format!("{method} /api HTTP/1.1\r\n")));
        assert!(sent.contains("Content-Length: 7\r\n"));
        assert!(sent.contains("accept: application/json\r\naccept: text/plain\r\n"));
        assert!(sent.ends_with("\r\n\r\n{broken"));
        assert!(api.join().unwrap().is_empty());
    }
}

#[test]
fn valid_methods_and_unsupported_protocols_reach_policy_first() {
    for (method, headers, decision, expected) in [
        ("OPTIONS", "", "DENY", 403),
        ("PROPFIND", "", "DENY", 403),
        (
            "GET",
            "Upgrade: websocket\r\nConnection: Upgrade\r\n",
            "DENY",
            403,
        ),
        (
            "GET",
            "Upgrade: websocket\r\nConnection: Upgrade\r\n",
            "ALLOW",
            501,
        ),
        (
            "POST",
            "Expect: fancy-extension\r\nContent-Length: 7\r\n",
            "ALLOW",
            501,
        ),
        ("POST", "Content-Length: 8388609\r\n", "DENY", 403),
        ("POST", "Content-Length: 8388609\r\n", "ALLOW", 413),
        (
            "POST",
            "Content-Length: 7\r\nContent-Type: invalid\r\n",
            "DENY",
            403,
        ),
    ] {
        let (backend, api) = crate::backend::tests::server(vec![
            (200, serde_json::json!({"decision":decision})),
            (204, serde_json::Value::Null),
        ]);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: test_credentials("brain.example.com"),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        write!(client, "{method} http://brain.example.com/models HTTP/1.1\r\nHost: brain.example.com\r\n{headers}\r\n").unwrap();
        if headers.contains("Content-Type: invalid") {
            client.write_all(b"{broken").unwrap();
        }
        handle(server, &context).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "{response}"
        );
        let calls = api.join().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1["action"]["method"], method.to_ascii_lowercase());
        assert_eq!(
            calls[1].1["reason"],
            if decision == "ALLOW" {
                "FORWARDING_UNSUPPORTED"
            } else {
                "COMPLETED"
            }
        );
    }
    let options = parse_request(
        b"OPTIONS * HTTP/1.1\r\nHost: brain.example.com\r\n\r\n",
        Some("brain.example.com"),
    )
    .unwrap();
    assert_eq!(options.target, "*");
    assert_eq!(options.path, "/");
    assert!(parse_request(b"GET /api HTTP/1.1\r\nHost: brain.example.com\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n", Some("brain.example.com")).is_ok());
}

#[test]
fn denied_decision_and_gateway_metadata_share_one_request_id() {
    let (backend, api) = crate::backend::tests::server(vec![
        (200, serde_json::json!({"decision":"DENY"})),
        (204, serde_json::Value::Null),
    ]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials: test_credentials("brain.example.com"),
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client
        .write_all(
            b"GET http://brain.example.com/models HTTP/1.1\r\nHost: brain.example.com\r\n\r\n",
        )
        .unwrap();
    handle(server, &context).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    let requests = api.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].1["requestId"], requests[1].1["requestId"]);
    assert_eq!(requests[1].1["reason"], "COMPLETED");
    assert_eq!(requests[1].1["port"], 80);
}

#[test]
fn history_omits_configured_secrets_in_destination_metadata() {
    let (backend, api) = crate::backend::tests::server(vec![(204, serde_json::Value::Null)]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials: test_credentials("brain.example.com"),
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let mut observation = Observation::new(&context).unwrap();
    observation.capture(
        b"GET http://brain.example.com/synthetic-secret-123456789 HTTP/1.1\r\n\r\n",
        None,
    );
    observation.report("INVALID_REQUEST");
    let requests = api.join().unwrap();
    assert!(requests[0].1["path"].is_null());
    assert!(!requests[0].1.to_string().contains("synthetic-secret"));
}
fn test_credentials(host: &str) -> Credentials {
    Credentials::parse(
            &serde_json::json!({"credentials":[{
                "placeholder":"AUTOMANTLE_TEST_TOKEN", "secret":"synthetic-secret-123456789",
                "scopes":[
                    {"agentProfileId":PROFILE,"host":host,"paths":["/api"],"location":"header","selector":"authorization"},
                    {"agentProfileId":PROFILE,"host":host,"paths":["/api"],"location":"json","selector":"/auth/token"},
                    {"agentProfileId":PROFILE,"host":host,"paths":["/api"],"location":"query","selector":"api_key"}
                ]
            }]})
            .to_string(),
        )
        .unwrap()
}
fn test_guest_credentials(host: &str) -> Credentials {
    Credentials::parse(&serde_json::json!({"credentials":[{
            "placeholder":"AUTOMANTLE_TEST_TOKEN", "secret":"synthetic-secret-123456789",
            "scopes":[{"agentProfileId":PROFILE,"host":host,"paths":["/api"],"location":"header","selector":"authorization"}]
        }],"guestBearer":[{"agentProfileId":PROFILE,"host":host,"methods":["GET","POST"],"paths":["/api"]}]}).to_string()).unwrap()
}

#[test]
fn credential_failures_evaluate_policy_but_never_forward() {
    for (value, secure) in [
        ("Bearer AUTOMANTLE_TEST_TOKEN", false),
        ("Bearer REAL_TOKEN", true),
        ("Bearer AUTOMANTLE_UNKNOWN", true),
    ] {
        let (backend, api) = crate::backend::tests::server(vec![
            (200, serde_json::json!({"decision":"ALLOW"})),
            (204, serde_json::Value::Null),
        ]);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: test_credentials("destination.invalid"),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let raw = format!(
            "GET /api HTTP/1.1\r\nHost: destination.invalid\r\nAuthorization: {value}\r\n\r\n"
        );
        let request = parse_request(raw.as_bytes(), Some("destination.invalid")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut stream = Client::Plain(context.socket(server).unwrap());
        let mut observation = Observation::new(&context).unwrap();
        serve(&mut stream, &request, secure, &context, &mut observation).unwrap();
        drop(stream);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403"));
        let calls = api.join().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1["reason"], "CREDENTIAL_BINDING_DENIED");
        assert!(!calls[0].1.to_string().contains("REAL_TOKEN"));
    }
}

#[test]
fn network_allow_cannot_release_credentials_outside_their_scope() {
    for (profile, host, target, header) in [
        (PROFILE, "other.invalid", "/api", "Authorization"),
        (PROFILE, "api.example.com", "/other", "Authorization"),
        (PROFILE, "api.example.com", "/api", "X-Other"),
        (
            PROFILE,
            "api.example.com",
            "/api?other=AUTOMANTLE_TEST_TOKEN",
            "Authorization",
        ),
        (
            "20000000-0000-0000-0000-000000000002",
            "api.example.com",
            "/api",
            "Authorization",
        ),
    ] {
        let (backend, api) = crate::backend::tests::server(vec![
            (200, serde_json::json!({"decision":"ALLOW"})),
            (204, serde_json::Value::Null),
        ]);
        let context = Context {
            setup_session: None,
            backend,
            profile: profile.into(),
            tls: None,
            credentials: test_credentials("api.example.com"),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let raw = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\n{header}: Bearer AUTOMANTLE_TEST_TOKEN\r\n\r\n"
        );
        let request = parse_request(raw.as_bytes(), Some(host)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut stream = Client::Plain(context.socket(server).unwrap());
        let mut observation = Observation::new(&context).unwrap();
        serve(&mut stream, &request, true, &context, &mut observation).unwrap();
        drop(stream);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403"));
        let calls = api.join().unwrap();
        assert_eq!(calls[1].1["reason"], "CREDENTIAL_BINDING_DENIED");
        assert!(
            !serde_json::to_string(&calls)
                .unwrap()
                .contains("synthetic-secret")
        );
    }
}
#[test]
fn credential_requests_wait_for_matching_approval_and_never_upload_secrets() {
    use serde_json::json;
    for (status, guest) in [
        ("APPROVED", false),
        ("REJECTED", false),
        ("EXPIRED", false),
        ("APPROVED", true),
        ("REJECTED", true),
        ("EXPIRED", true),
    ] {
        let credentials = if guest {
            test_guest_credentials("destination.invalid")
        } else {
            test_credentials("destination.invalid")
        };
        let token = if guest {
            "synthetic-vm-login-token"
        } else {
            "AUTOMANTLE_TEST_TOKEN"
        };
        let raw = format!(
            "GET /api HTTP/1.1\r\nHost: destination.invalid\r\nAuthorization: Bearer {token}\r\n\r\n"
        );
        let request = parse_request(raw.as_bytes(), Some("destination.invalid")).unwrap();
        let id = "20000000-0000-0000-0000-000000000001";
        let mut responses = vec![
            (
                200,
                json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":id}),
            ),
            (
                200,
                json!({"id":id,"agentProfileId":PROFILE,"status":status,"actionMetadata":{"action":request.reviewed_action(&credentials)}}),
            ),
        ];
        if status == "APPROVED" {
            responses.push((204, serde_json::Value::Null));
        }
        let (backend, api) = crate::backend::tests::server(responses);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials,
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut stream = Client::Plain(context.socket(server).unwrap());
        let mut observation = Observation::new(&context).unwrap();
        serve(&mut stream, &request, true, &context, &mut observation).unwrap();
        drop(stream);
        drop(observation);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with(if status == "APPROVED" {
            "HTTP/1.1 502"
        } else {
            "HTTP/1.1 403"
        }));
        let requests = api.join().unwrap();
        assert_eq!(requests.len(), if status == "APPROVED" { 3 } else { 2 });
        let wire = serde_json::to_string(&requests).unwrap();
        assert!(!wire.contains("synthetic-secret"));
        assert!(wire.contains(if guest {
            "AUTOMANTLE_VM_BEARER_"
        } else {
            "AUTOMANTLE_TEST_TOKEN"
        }));
        assert!(!wire.contains("synthetic-vm-login-token"));
        assert_eq!(
            requests[0].1["action"]["credentials"][0][if guest { "header" } else { "selector" }],
            "authorization"
        );
        assert!(!response.contains("synthetic-secret"));
    }
}

#[test]
fn inserts_only_at_planned_locations_and_blocks_response_echo_for_every_location() {
    struct Upstream {
        response: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Upstream {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(b)
        }
    }
    impl Write for Upstream {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for (echo, guest_token, location) in [
        (false, false, "header"),
        (true, false, "header"),
        (false, true, "header"),
        (false, false, "json"),
        (true, false, "json"),
        (false, false, "query"),
        (true, false, "query"),
    ] {
        let (backend, api) = crate::backend::tests::server(vec![]);
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls: None,
            credentials: if guest_token {
                test_guest_credentials("api.example.com")
            } else {
                test_credentials("api.example.com")
            },
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let mut request=parse_request(b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer AUTOMANTLE_TEST_TOKEN\r\nAccept-Encoding: gzip\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n",Some("api.example.com")).unwrap();
        request.body = br#"{"x":1}"#.to_vec();
        if location != "header" {
            request.headers.retain(|(name, _)| name != "authorization");
        }
        if location == "json" {
            request.body = br#"{"auth":{"token":"AUTOMANTLE_TEST_TOKEN"},"x":1}"#.to_vec();
        }
        if location == "query" {
            request.target = "/api?api_key=AUTOMANTLE_TEST_TOKEN&ordinary=unchanged".into();
        }
        request.body_metadata =
            Some(body::opaque_metadata(&request.body, "application/json").unwrap());
        let review = request.reviewed_action(&context.credentials);
        assert_eq!(review["credentials"][0]["location"], location);
        assert!(!review.to_string().contains("synthetic-secret"));
        if guest_token {
            request
                .headers
                .iter_mut()
                .find(|(name, _)| name == "authorization")
                .unwrap()
                .1 = "Bearer synthetic-vm-login-token".into();
            request.body_metadata =
                Some(body::opaque_metadata(&request.body, "application/json").unwrap());
            let review = request.reviewed_action(&context.credentials);
            assert_eq!(
                review["body"]["preview"],
                serde_json::json!({"omitted":true})
            );
            assert!(!review.to_string().contains("synthetic-vm-login-token"));
        }
        assert!(context.credentials.validate_guest_headers(
            &request.headers,
            PROFILE,
            &request.host,
            &request.method,
            &request.path,
            true
        ));
        let response = if echo {
            let mut bytes = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            bytes.resize(8185, b' ');
            bytes.extend_from_slice(b"synthetic-secret-123456789");
            bytes
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec()
        };
        let mut upstream = Upstream {
            response: std::io::Cursor::new(response.clone()),
            written: Vec::new(),
        };
        let mut guest = Vec::new();
        forward(&mut guest, &mut upstream, &request, &context).unwrap();
        let wire = String::from_utf8(upstream.written).unwrap();
        if location == "header" {
            assert!(wire.contains(if guest_token {
                "authorization: Bearer synthetic-vm-login-token\r\n"
            } else {
                "authorization: Bearer synthetic-secret-123456789\r\n"
            }));
        } else if location == "query" {
            assert!(wire.starts_with(
                "POST /api?api_key=synthetic-secret-123456789&ordinary=unchanged HTTP/1.1\r\n"
            ));
        }
        assert_eq!(wire.contains("Accept-Encoding: identity\r\n"), !guest_token);
        assert_eq!(wire.contains("gzip"), guest_token);
        assert!(!wire.contains("AUTOMANTLE_TEST_TOKEN"));
        if location == "json" {
            let body = wire.split_once("\r\n\r\n").unwrap().1;
            let value: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(value["auth"]["token"], "synthetic-secret-123456789");
            assert_eq!(value["x"], 1);
            assert!(wire.contains(&format!("Content-Length: {}\r\n", body.len())));
            assert!(String::from_utf8_lossy(&request.body).contains("AUTOMANTLE_TEST_TOKEN"));
        } else {
            assert!(wire.ends_with("{\"x\":1}"));
        }
        assert!(!context.credentials.contains_secret(&guest));
        if echo {
            assert!(guest.starts_with(b"HTTP/1.1 502"));
        } else {
            assert_eq!(guest, response);
        }
        assert_eq!(api.join().unwrap().len(), 0);
    }
}
#[test]
fn credential_response_honors_http_framing_and_checks_dechunked_echoes() {
    struct AbruptEof(std::io::Cursor<Vec<u8>>);
    impl Read for AbruptEof {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let count = self.0.read(bytes)?;
            if count == 0 {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            } else {
                Ok(count)
            }
        }
    }
    for response in [
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec(),
    ] {
        let mut upstream = AbruptEof(std::io::Cursor::new(response.clone()));
        assert_eq!(
            credential_response(&mut upstream, "POST").unwrap().0,
            response
        );
    }
    let wire=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n11\r\ntest-secret-value\r\n6\r\n-12345\r\n0\r\n\r\n";
    let credentials = Credentials::parse(
        &serde_json::json!({"credentials":[{
            "placeholder":"AUTOMANTLE_TOKEN","secret":"test-secret-value-12345","scopes":[]}]})
        .to_string(),
    )
    .unwrap();
    let (raw, decoded) = credential_response(&mut std::io::Cursor::new(wire), "GET").unwrap();
    assert!(!credentials.contains_secret(&raw));
    assert!(credentials.contains_secret(&decoded));
    for wire in [
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nNO",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;hidden=yes\r\nOK\r\n0\r\n\r\n",
    ] {
        assert!(credential_response(&mut std::io::Cursor::new(wire), "GET").is_err());
    }
}
#[test]
fn installer_download_streams_past_eight_mib_and_stops_at_content_length() {
    struct Download {
        header: std::io::Cursor<Vec<u8>>,
        remaining: usize,
    }
    impl Read for Download {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            assert!(bytes.len() <= 8192);
            let count = self.header.read(bytes)?;
            if count > 0 {
                return Ok(count);
            }
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let count = bytes.len().min(self.remaining);
            bytes[..count].fill(0x5a);
            self.remaining -= count;
            Ok(count)
        }
    }
    let size = 12 * 1024 * 1024;
    let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").into_bytes();
    let mut upstream = Download {
        header: std::io::Cursor::new(header.clone()),
        remaining: size,
    };
    let mut output = Vec::new();
    stream_response(
        &mut output,
        &mut upstream,
        "GET",
        MAX_DOWNLOAD_RESPONSE,
        || true,
    )
    .unwrap();
    assert_eq!(&output[..header.len()], &header);
    assert_eq!(output.len(), header.len() + size);
    assert!(output[header.len()..].iter().all(|b| *b == 0x5a));
    assert_eq!(upstream.remaining, 0);
}
#[test]
fn oversized_download_is_rejected_before_forwarding_body() {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_DOWNLOAD_RESPONSE
    );
    let mut upstream = std::io::Cursor::new(header.as_bytes());
    let mut output = Vec::new();
    stream_response(
        &mut output,
        &mut upstream,
        "GET",
        MAX_DOWNLOAD_RESPONSE,
        || true,
    )
    .unwrap();
    assert!(output.starts_with(b"HTTP/1.1 502"));
    assert_eq!(upstream.position(), header.len() as u64);
    assert!(credential_response(&mut std::io::Cursor::new(header.as_bytes()), "GET").is_err());
}
#[test]
fn streamed_chunked_and_head_responses_finish_without_transport_eof() {
    for (wire, method, expected) in [
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\nX-Test: done\r\n\r\nunread",
            "GET",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\nX-Test: done\r\n\r\n",
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\nunread",
            "HEAD",
            "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n",
        ),
    ] {
        let mut output = Vec::new();
        stream_response(
            &mut output,
            &mut std::io::Cursor::new(wire),
            method,
            MAX_DOWNLOAD_RESPONSE,
            || true,
        )
        .unwrap();
        assert_eq!(output, expected.as_bytes());
    }
}
#[test]
fn streamed_responses_reject_ambiguous_truncated_and_over_limit_framing() {
    for wire in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nNO",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOKxx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n",
        "HTTP/1.1 200 OK\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ] {
        assert!(
            stream_response(
                &mut Vec::new(),
                &mut std::io::Cursor::new(wire),
                "GET",
                100,
                || true
            )
            .is_err()
        );
    }
}
#[test]
fn download_cancellation_interrupts_between_blocks() {
    let wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 16384\r\n\r\n{}",
        "x".repeat(16384)
    );
    let checks = std::cell::Cell::new(0);
    let mut output = Vec::new();
    assert!(
        stream_response(
            &mut output,
            &mut std::io::Cursor::new(wire),
            "GET",
            MAX_DOWNLOAD_RESPONSE,
            || {
                checks.set(checks.get() + 1);
                checks.get() <= 2
            }
        )
        .is_err()
    );
    assert!(output.len() < 16384);
}
#[test]
fn proxy_returns_deny_and_blocks_backend_failures() {
    use serde_json::json;
    for (code, decision, expected) in [
        (200, "DENY", "403"),
        (503, "ALLOW", "503"),
        (200, "UNKNOWN", "503"),
    ] {
        let (backend, api) =
            crate::backend::tests::server(vec![(code, json!({"decision":decision}))]);
        let context = Context {
            setup_session: None,
            credentials: Credentials::default(),
            backend,
            tls: None,
            profile: "10000000-0000-0000-0000-000000000001".into(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let worker = thread::spawn(move || {
            handle(server, &context).unwrap();
        });
        client
            .write_all(
                b"GET http://destination.invalid/api HTTP/1.1\r\nHost: destination.invalid\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "{response}"
        );
        worker.join().unwrap();
        assert_eq!(api.join().unwrap().len(), 1);
    }
}
#[test]
fn preserves_paths_for_backend_validation() {
    for path in ["/%2f", "/a/../b", "//api", "/a\\b"] {
        assert_eq!(
            parse_target(&format!("http://example.com{path}")),
            Some(("example.com".into(), path.into()))
        );
    }
    assert!(parse_target("https://example.com/").is_none());
    assert!(parse_target("http://").is_none());
    assert_eq!(
        parse_target("http://Example.com/api"),
        Some(("example.com".into(), "/api".into()))
    );
    assert_eq!(
        parse_target("http://example.com"),
        Some(("example.com".into(), "/".into()))
    );
}
#[test]
fn private_and_special_destinations_remain_blocked() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "224.0.0.1",
    ] {
        assert!(!public_address(ip.parse().unwrap()));
    }
    assert!(public_address("8.8.8.8".parse().unwrap()));
}

#[test]
fn dual_stack_hosts_use_validated_ipv4_without_enabling_ipv6() {
    let addresses = |values: &[&str]| values.iter().map(|v| v.parse().unwrap()).collect();
    assert_eq!(
        public_ipv4_destinations(addresses(&[
            "[2600:1900:4240:200::]:443",
            "34.143.72.2:443"
        ])),
        Some(addresses(&["34.143.72.2:443"]))
    );
    for values in [
        vec!["[2600:1900:4240:200::]:443"],
        vec!["[::1]:443"],
        vec!["34.143.72.2:443", "127.0.0.1:443"],
        vec!["34.143.72.2:443", "169.254.169.254:443"],
        vec![],
    ] {
        assert!(public_ipv4_destinations(addresses(&values)).is_none());
    }
}

#[test]
fn binds_https_host_and_rejects_ambiguous_requests() {
    let good = b"GET /api HTTP/1.1\r\nHost: Example.com:443\r\n\r\n";
    let request = parse_request(good, Some("example.com")).unwrap();
    assert_eq!(
        (&*request.method, &*request.host, &*request.path),
        ("GET", "example.com", "/api")
    );
    for raw in [
        "GET /api HTTP/1.1\r\nHost: other.com\r\n\r\n",
        "GET https://example.com/api HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /api HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
        "GET /api HTTP/1.1\r\nHost : example.com\r\n\r\n",
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ] {
        assert!(
            parse_request(raw.as_bytes(), Some("example.com")).is_err(),
            "{raw}"
        );
    }
    for target in [
        "127.0.0.1:443",
        "example.com:80",
        "example.com:0443",
        "user@example.com:443",
        "[::1]:443",
        "example.com:443/path",
    ] {
        assert!(connect_host(target).is_none(), "{target}");
    }
}
#[test]
fn inspected_https_uses_backend_and_denies_before_dns() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use serde_json::json;
    for (code, decision, expected) in [(200, "DENY", "403"), (503, "ALLOW", "503")] {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let certificate = params.self_signed(&key).unwrap();
        let tls = Tls::from_pem(
            &certificate.pem(),
            &key.serialize_pem(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        let (backend, api) =
            crate::backend::tests::server(vec![(code, json!({"decision":decision}))]);
        let context = Context {
            setup_session: None,
            credentials: test_credentials("destination.invalid"),
            backend,
            tls: Some(Arc::new(tls)),
            profile: "10000000-0000-0000-0000-000000000001".into(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let worker = thread::spawn(move || handle(server, &context).unwrap());
        client.write_all(b"CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid:443\r\n\r\n").unwrap();
        assert!(
            String::from_utf8(read_header(&mut client).unwrap())
                .unwrap()
                .contains("200")
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate.der().clone()).unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("destination.invalid").unwrap(),
        )
        .unwrap();
        let mut client = StreamOwned::new(connection, client);
        client
                .write_all(b"GET /api HTTP/1.1\r\nHost: destination.invalid\r\nAuthorization: Bearer AUTOMANTLE_TEST_TOKEN\r\n\r\n")
                .unwrap();
        client.flush().unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "{response}"
        );
        worker.join().unwrap();
        let requests = api.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1["action"]["host"], "destination.invalid");
        assert_eq!(requests[0].1["action"]["path"], "/api");
    }
}
#[test]
fn inspected_https_binds_body_without_uploading_raw_bytes() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use serde_json::json;
    for (code, decision, expected, content_type, body_bytes) in [
        (
            200,
            "DENY",
            "403",
            "application/json",
            br#"{"token":"sensitive-request-value"}"#.as_slice(),
        ),
        (
            503,
            "ALLOW",
            "503",
            "application/json",
            br#"{"token":"sensitive-request-value"}"#.as_slice(),
        ),
        (
            200,
            "DENY",
            "403",
            "application/x-www-form-urlencoded",
            b"code=sensitive-request-value&grant_type=authorization_code".as_slice(),
        ),
        (
            503,
            "ALLOW",
            "503",
            "application/x-www-form-urlencoded",
            b"code=sensitive-request-value&grant_type=authorization_code".as_slice(),
        ),
    ] {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let certificate = params.self_signed(&key).unwrap();
        let tls = Tls::from_pem(
            &certificate.pem(),
            &key.serialize_pem(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        let (backend, api) =
            crate::backend::tests::server(vec![(code, json!({"decision":decision}))]);
        let context = Context {
            setup_session: None,
            credentials: Credentials::default(),
            backend,
            tls: Some(Arc::new(tls)),
            profile: "10000000-0000-0000-0000-000000000001".into(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let worker = thread::spawn(move || handle(server, &context).unwrap());
        client.write_all(b"CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid:443\r\n\r\n").unwrap();
        assert!(
            String::from_utf8(read_header(&mut client).unwrap())
                .unwrap()
                .contains("200")
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificate.der().clone()).unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("destination.invalid").unwrap(),
        )
        .unwrap();
        let mut client = StreamOwned::new(connection, client);
        write!(client, "POST /api HTTP/1.1\r\nHost: destination.invalid\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n", body_bytes.len()).unwrap();
        client.write_all(body_bytes).unwrap();
        client.flush().unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected}")),
            "{response}"
        );
        worker.join().unwrap();
        let requests = api.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1["action"]["host"], "destination.invalid");
        assert_eq!(requests[0].1["action"]["path"], "/api");
        let mut expected = body::opaque_metadata(body_bytes, content_type).unwrap();
        expected["preview"] = if content_type == "application/x-www-form-urlencoded" {
            json!({"omitted": true})
        } else {
            Credentials::default().body_preview(body_bytes)
        };
        assert_eq!(requests[0].1["action"]["body"], expected);
        assert!(
            !requests[0]
                .1
                .to_string()
                .contains("sensitive-request-value")
        );
    }
}

#[test]
fn validates_body_framing_before_any_authorization() {
    for (headers, expected) in [
        (
            "Content-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n",
            400,
        ),
        (
            "Content-Length: 02\r\nContent-Type: application/json\r\n",
            400,
        ),
        (
            "Content-Length: +2\r\nContent-Type: application/json\r\n",
            400,
        ),
        (
            "Content-Length: 2\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n",
            400,
        ),
    ] {
        let raw = format!("POST /api HTTP/1.1\r\nHost: example.com\r\n{headers}\r\n");
        assert_eq!(
            parse_request(raw.as_bytes(), Some("example.com"))
                .unwrap_err()
                .0,
            expected
        );
    }
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let raw = format!(
            "{method} /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n"
        );
        assert_eq!(
            parse_request(raw.as_bytes(), Some("example.com"))
                .unwrap()
                .content_length,
            2
        );
    }
}
#[test]
fn invalid_json_reaches_policy_but_incomplete_framing_does_not() {
    for (payload, declared) in [(b"{\"x\":1,\"x\":2}".as_slice(), 13), (b"{".as_slice(), 2)] {
        let complete = payload.len() == declared;
        let (backend, api) = crate::backend::tests::server(if complete {
            vec![
                (200, serde_json::json!({"decision":"DENY"})),
                (204, serde_json::Value::Null),
            ]
        } else {
            vec![]
        });
        let context = Context {
            setup_session: None,
            credentials: Credentials::default(),
            backend,
            tls: None,
            profile: "10000000-0000-0000-0000-000000000001".into(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(3),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let worker = thread::spawn(move || handle(server, &context).unwrap());
        write!(client, "POST http://example.com/api HTTP/1.1\r\nHost: example.com\r\nContent-Length: {declared}\r\nContent-Type: application/json\r\n\r\n").unwrap();
        client.write_all(payload).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(if complete {
                "HTTP/1.1 403"
            } else {
                "HTTP/1.1 400"
            }),
            "{response}"
        );
        worker.join().unwrap();
        let calls = api.join().unwrap();
        assert_eq!(calls.len(), if complete { 2 } else { 0 });
        if complete {
            assert_eq!(
                calls[0].1["action"]["body"]["preview"],
                serde_json::json!({"omitted":true})
            );
        }
    }
}
#[test]
fn closed_tcp_or_tls_request_expires_pending_approval_without_upstream_contact() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use serde_json::json;
    for secure in [false, true] {
        let id = "20000000-0000-0000-0000-000000000001";
        let (signal, ready) = std::sync::mpsc::channel();
        let (backend, api) = crate::backend::tests::server_observed(
            vec![
                (
                    200,
                    json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":id}),
                ),
                (
                    200,
                    json!({"id":id,"agentProfileId":PROFILE,"status":"PENDING","actionMetadata":{"action":null}}),
                ),
                (204, serde_json::Value::Null),
                (204, serde_json::Value::Null),
            ],
            move |count| {
                if count == 2 {
                    signal.send(()).unwrap();
                }
            },
        );
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let certificate = parameters.self_signed(&key).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let tls = secure.then(|| {
            Arc::new(Tls::from_pem(&certificate.pem(), &key.serialize_pem(), deadline).unwrap())
        });
        let context = Context {
            setup_session: None,
            backend,
            profile: PROFILE.into(),
            tls,
            credentials: Credentials::default(),
            stopped: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let worker = thread::spawn(move || {
            let _ = handle(server, &context);
        });
        if secure {
            client.write_all(b"CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid:443\r\n\r\n").unwrap();
            assert!(
                String::from_utf8(read_header(&mut client).unwrap())
                    .unwrap()
                    .starts_with("HTTP/1.1 200")
            );
            let mut roots = RootCertStore::empty();
            roots.add(certificate.der().clone()).unwrap();
            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connection = ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("destination.invalid").unwrap(),
            )
            .unwrap();
            let mut client = StreamOwned::new(connection, client);
            client
                .write_all(b"GET /api HTTP/1.1\r\nHost: destination.invalid\r\n\r\n")
                .unwrap();
            client.flush().unwrap();
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            client.conn.send_close_notify();
            client.flush().unwrap();
            worker.join().unwrap();
        } else {
            client.write_all(b"GET http://destination.invalid/api HTTP/1.1\r\nHost: destination.invalid\r\n\r\n").unwrap();
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            client.shutdown(std::net::Shutdown::Both).unwrap();
            drop(client);
            worker.join().unwrap();
        }
        let calls = api.join().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(
            calls[2]
                .0
                .starts_with(&format!("POST /gateway/approval-requests/{id}/expire "))
        );
        assert_eq!(calls[2].1["reason"], "CLIENT_CLOSED");
        assert_eq!(calls[2].1["agentProfileId"], PROFILE);
        assert_eq!(calls[3].1["reason"], "COMPLETED");
        assert!(calls.iter().all(|call| call.1["reason"] != "DNS_FAILED"));
    }
}

#[test]
fn local_cancellation_is_recorded_without_an_approval() {
    let (backend, api) = crate::backend::tests::server(vec![(204, serde_json::Value::Null)]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials: Credentials::default(),
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(true)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let mut observation = Observation::new(&context).unwrap();
    assert!(!observation.request_active(&mut || None));
    assert!(observation.terminal);
    assert_eq!(api.join().unwrap()[0].1["reason"], "CANCELLED");
}

#[test]
fn approved_request_is_rechecked_before_first_upstream_byte() {
    use serde_json::json;
    let credentials = Credentials::default();
    let request = parse_request(
        b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
        Some("api.example.com"),
    )
    .unwrap();
    let action = request.reviewed_action(&credentials);
    let id = "20000000-0000-0000-0000-000000000001";
    let (backend, api) = crate::backend::tests::server(vec![
        (
            200,
            json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":id}),
        ),
        (
            200,
            json!({"id":id,"agentProfileId":PROFILE,"status":"APPROVED","actionMetadata":{"action":action}}),
        ),
        (204, serde_json::Value::Null),
        (204, serde_json::Value::Null),
    ]);
    let context = Context {
        setup_session: None,
        backend,
        profile: PROFILE.into(),
        tls: None,
        credentials,
        stopped: Arc::new(AtomicBool::new(false)),
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    };
    let lifecycle = RequestLifecycle::new(&context.stopped, &context.cancelled, context.deadline);
    let authorization = context
        .backend
        .authorize_action_recorded(PROFILE, &action, None, None, &lifecycle, &mut || None)
        .unwrap();
    assert!(authorization.is_allowed());
    let mut observation = Observation::new(&context).unwrap();
    observation.authorization = Some(authorization);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut client = Client::Plain(context.socket(server).unwrap());
    peer.shutdown(std::net::Shutdown::Both).unwrap();
    drop(peer);
    let mut upstream = std::io::Cursor::new(Vec::new());
    forward_observed(
        &mut client,
        &mut upstream,
        &request,
        &context,
        Some(&mut observation),
    )
    .unwrap();
    assert!(upstream.get_ref().is_empty());
    let calls = api.join().unwrap();
    assert_eq!(calls[2].1["reason"], "CLIENT_CLOSED");
}

#[test]
fn changed_body_fingerprint_cannot_use_pending_approval() {
    use serde_json::json;
    for field in [
        "sha256",
        "size_bytes",
        "content_type",
        "guest_token",
        "request_digest",
        "credential_placement",
    ] {
        let mut action = json!({"resource_type":"http","method":"post","host":"example.com","path":"/api",
                "body":body::opaque_metadata(b"{\"x\":1}", "application/json").unwrap()});
        if field == "guest_token" {
            action["credentials"] = test_guest_credentials("example.com").identities(&[(
                "authorization".into(),
                "Bearer synthetic-vm-login-token".into(),
            )]);
        }
        if field == "request_digest" {
            action["request_sha256"] = json!("a".repeat(64));
        }
        if field == "credential_placement" {
            action["credentials"] =
                json!([{"placeholder":"SERVICE_TOKEN","location":"json","selector":"/auth/token"}]);
        }
        let mut changed = action.clone();
        if field == "credential_placement" {
            changed["credentials"][0]["selector"] = json!("/description");
        } else if field == "request_digest" {
            changed["request_sha256"] = json!("b".repeat(64));
        } else if field == "guest_token" {
            changed["credentials"] = test_guest_credentials("example.com").identities(&[(
                "authorization".into(),
                "Bearer changed-vm-login-token".into(),
            )]);
        } else {
            changed["body"][field] = match field {
                "sha256" => json!("b".repeat(64)),
                "size_bytes" => json!(8),
                _ => json!("application/merge-patch+json"),
            };
        }
        let id = "20000000-0000-0000-0000-000000000001";
        let profile = "10000000-0000-0000-0000-000000000001";
        let (backend, api) = crate::backend::tests::server(vec![
            (
                200,
                json!({"decision":"REQUIRE_APPROVAL","approvalRequestId":id}),
            ),
            (
                200,
                json!({"id":id,"agentProfileId":profile,"status":"APPROVED","actionMetadata":{"action":changed}}),
            ),
            (204, serde_json::Value::Null),
        ]);
        assert!(
            backend
                .authorize_action(
                    profile,
                    &action,
                    &AtomicBool::new(false),
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(3)
                )
                .is_err()
        );
        let calls = api.join().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].1["reason"], "REQUEST_NOT_EXECUTED");
    }
}
