use crate::{
    backend::{Authorization, Backend},
    body,
    credentials::Credentials,
    request_lifecycle::{EndReason, RequestLifecycle, RequestMonitor},
    sandbox::Result,
    tls::Tls,
    transport::{Socket, Stream},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    os::unix::net::UnixListener,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
mod destination;
mod forward;
mod observation;
mod request;
mod response;

use destination::{public_ipv4_destinations, resolve};
use forward::forward_observed;
use observation::Observation;
use request::{Request, parse_request, writes_body};
pub(crate) use request::{valid_host, valid_method, valid_path};
use response::{credential_response, response_line, stream_response};

const MAX_HEADER: usize = 32 * 1024;
const MAX_RESPONSE: u64 = 8 * 1024 * 1024;
const MAX_DOWNLOAD_RESPONSE: u64 = 128 * 1024 * 1024;

pub struct Proxy {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    context: Arc<Context>,
}
pub(crate) struct ProxyConfig {
    pub backend: Backend,
    pub profile: String,
    pub tls: Option<Tls>,
    pub credentials: Credentials,
    pub cancelled: Arc<AtomicBool>,
    pub deadline: Instant,
    pub setup_mode: bool,
}
#[derive(Clone)]
struct Context {
    setup_session: Option<String>,
    backend: Backend,
    profile: String,
    tls: Option<Arc<Tls>>,
    credentials: Credentials,
    stopped: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl Context {
    fn active(&self) -> bool {
        !self.stopped.load(Ordering::Relaxed)
            && !self.cancelled.load(Ordering::Relaxed)
            && Instant::now() < self.deadline
    }
    fn socket(&self, stream: impl Into<Stream>) -> Result<Socket> {
        Ok(Socket::new(
            stream,
            Arc::clone(&self.stopped),
            Arc::clone(&self.cancelled),
            self.deadline,
            Duration::from_secs(10),
        )?)
    }
}
impl Proxy {
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }
    pub fn check(&self) -> Result<()> {
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err("HTTP inspection proxy stopped unexpectedly".into());
        }
        Ok(())
    }
    pub(crate) fn start_unix(config: ProxyConfig, path: &Path) -> Result<Self> {
        let listener = UnixListener::bind(path)?;
        let ProxyConfig {
            backend,
            profile,
            tls,
            credentials,
            cancelled,
            deadline,
            setup_mode,
        } = config;
        listener.set_nonblocking(true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let setup_session = if setup_mode {
            Some(backend.start_setup(&profile, deadline)?)
        } else {
            None
        };
        let context = Arc::new(Context {
            setup_session,
            backend,
            profile,
            tls: tls.map(Arc::new),
            credentials,
            stopped: Arc::clone(&stopped),
            cancelled,
            deadline,
        });
        let setup_context = Arc::clone(&context);
        let worker = thread::Builder::new()
            .name("vm-http-proxy".into())
            .spawn(move || {
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                while context.active() {
                    let mut i = 0;
                    while i < workers.len() {
                        if workers[i].is_finished() {
                            let _ = workers.swap_remove(i).join();
                        } else {
                            i += 1;
                        }
                    }
                    match listener.accept().map(|(stream, _)| Stream::from(stream)) {
                        Ok(mut client) => {
                            if workers.len() >= 16 {
                                let _ = client.set_write_timeout(Some(Duration::from_secs(1)));
                                let _ = reply(&mut client, 503, "proxy request limit reached");
                                continue;
                            }
                            let context = Arc::clone(&context);
                            match thread::Builder::new().spawn(move || {
                                let _ = handle(client, &context);
                            }) {
                                Ok(worker) => workers.push(worker),
                                Err(error) => {
                                    eprintln!("HTTP proxy worker could not start: {error}");
                                    break;
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20))
                        }
                        Err(error) => {
                            eprintln!("HTTP proxy accept failed: {error}");
                            break;
                        }
                    }
                }
                context.stopped.store(true, Ordering::Relaxed);
                for worker in workers {
                    let _ = worker.join();
                }
            });
        let thread = match worker {
            Ok(thread) => thread,
            Err(error) => {
                if let Some(id) = &setup_context.setup_session {
                    setup_context
                        .backend
                        .finish_setup(&setup_context.profile, id);
                }
                return Err(error.into());
            }
        };
        Ok(Self {
            stopped,
            thread: Some(thread),
            context: setup_context,
        })
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(id) = &self.context.setup_session {
            self.context.backend.finish_setup(&self.context.profile, id);
        }
    }
}

enum Client {
    Plain(Socket),
    Tls(Box<crate::tls::Downstream>),
}
impl Client {
    fn socket(&mut self) -> &mut Socket {
        match self {
            Self::Plain(s) => s,
            Self::Tls(s) => &mut s.sock,
        }
    }
}
impl RequestMonitor for Client {
    fn end_reason(&mut self) -> Option<EndReason> {
        if let Some(reason) = self.socket().peer_end_reason() {
            return Some(reason);
        }
        if let Self::Tls(stream) = self {
            match stream.conn.process_new_packets() {
                Ok(state) if state.peer_has_closed() => return Some(EndReason::ClientClosed),
                Err(_) => return Some(EndReason::TransportError),
                _ => {}
            }
            struct Available<'a>(&'a Socket);
            impl Read for Available<'_> {
                fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                    self.0.read_available(bytes)
                }
            }
            match stream.conn.read_tls(&mut Available(&stream.sock)) {
                Ok(0) => return Some(EndReason::ClientClosed),
                Ok(_) => match stream.conn.process_new_packets() {
                    Ok(state) if state.peer_has_closed() => return Some(EndReason::ClientClosed),
                    Err(_) => return Some(EndReason::TransportError),
                    _ => {}
                },
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                    return Some(EndReason::ConnectionReset);
                }
                Err(_) => return Some(EndReason::TransportError),
            }
        }
        None
    }
}

impl Read for Client {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(b),
            Self::Tls(s) => s.read(b),
        }
    }
}
impl Write for Client {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(b),
            Self::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}
fn read_header(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(1024);
    let mut byte = [0; 1];
    while header.len() < MAX_HEADER {
        reader.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err("request header too large".into())
}
fn handle(mut stream: Stream, shared: &Context) -> Result<()> {
    let credentials = match shared.credentials.snapshot() {
        Ok(credentials) => credentials,
        Err(_) => {
            let mut event = Observation::new(shared)?;
            event.report("CREDENTIAL_BINDING_DENIED");
            stream.set_write_timeout(Some(Duration::from_secs(1)))?;
            return reply(&mut stream, 503, "credential store unavailable");
        }
    };
    let snapshot = Context {
        credentials,
        ..shared.clone()
    };
    let context = &snapshot;
    let mut observation = Observation::new(context)?;
    let result = handle_observed(stream, context, &mut observation);
    if result.is_err() && !observation.terminal {
        observation.report(if context.active() {
            "IO_FAILED"
        } else {
            "CANCELLED"
        });
    }
    result
}
fn handle_observed(stream: Stream, context: &Context, observation: &mut Observation) -> Result<()> {
    let mut socket = context.socket(stream)?;
    let raw = read_header(&mut socket)?;
    observation.capture(&raw, None);
    let outer = match parse_request(&raw, None) {
        Ok(request) => request,
        Err((status, message)) => {
            observation.report("INVALID_REQUEST");
            let result = reply(&mut socket, status, message);
            socket.finish();
            return result;
        }
    };
    let (mut client, parsed, secure) = if outer.method == "CONNECT" {
        let Some(tls) = context.tls.as_ref() else {
            observation.report("HTTPS_DISABLED");
            return reply(&mut socket, 403, "HTTPS inspection is not enabled");
        };
        socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        socket.flush()?;
        let mut stream = match tls.accept(socket, &outer.host) {
            Ok(stream) => stream,
            Err(error) => {
                observation.report("DOWNSTREAM_TLS_FAILED");
                return Err(error);
            }
        };
        let raw = read_header(&mut stream)?;
        observation.capture(&raw, Some(&outer.host));
        let parsed = parse_request(&raw, Some(&outer.host));
        (Client::Tls(Box::new(stream)), parsed, true)
    } else {
        (Client::Plain(socket), Ok(outer), false)
    };
    let result = (|| -> Result<()> {
        let mut request = match parsed {
            Ok(request) => request,
            Err((status, message)) => {
                observation.report("INVALID_REQUEST");
                return reply(&mut client, status, message);
            }
        };
        client.socket().phase(Duration::from_secs(10));
        if request.unsupported_forwarding() {
            client.socket().waiting_for_policy();
            return serve(&mut client, &request, secure, context, observation);
        }
        if request.headers.iter().any(|(name, _)| name == "expect") {
            client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            client.flush()?;
        }
        let body_result = if request.chunked {
            read_chunked_request(&mut client, &mut request.body)
        } else {
            request.body.resize(request.content_length, 0);
            client
                .read_exact(&mut request.body)
                .map_err(|_| "incomplete request body".into())
        };
        if body_result.is_err() {
            observation.report("INVALID_BODY");
            return reply(&mut client, 400, "incomplete request body");
        }
        if writes_body(&request.method) {
            request.body_metadata =
                Some(body::opaque_metadata(&request.body, &request.content_type)?);
        }
        client.socket().waiting_for_policy();
        serve(&mut client, &request, secure, context, observation)
    })();
    if let Client::Tls(stream) = &mut client {
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
    client.socket().finish();
    result
}
fn serve(
    client: &mut Client,
    request: &Request,
    secure: bool,
    context: &Context,
    observation: &mut Observation,
) -> Result<()> {
    if [
        &request.host,
        &request.path,
        &request.target,
        &request.method,
    ]
    .iter()
    .any(|value| context.credentials.contains_secret(value.as_bytes()))
        || context.credentials.contains_secret(&request.body)
        || request
            .headers
            .iter()
            .any(|(_, value)| context.credentials.contains_secret(value.as_bytes()))
    {
        observation.report("CREDENTIAL_BINDING_DENIED");
        return reply(
            client,
            403,
            "raw protected credentials are not allowed in requests",
        );
    }
    let credential_plan = request.credential_plan(&context.credentials);
    let action = request.reviewed_action(&context.credentials, credential_plan.as_deref().ok());
    let lifecycle = RequestLifecycle::new(&context.stopped, &context.cancelled, context.deadline);
    match context.backend.authorize_action_recorded(
        &context.profile,
        &action,
        Some(&observation.id),
        context.setup_session.as_deref(),
        &lifecycle,
        client,
    ) {
        Ok(authorization) => {
            let allowed = authorization.is_allowed();
            observation.authorization = Some(authorization);
            if !allowed {
                observation.report(if context.active() {
                    "COMPLETED"
                } else {
                    "CANCELLED"
                });
                return reply(client, 403, "request denied or no longer active");
            }
        }
        Err(_) => {
            observation.report("POLICY_UNAVAILABLE");
            return reply(client, 503, "policy evaluation unavailable");
        }
    }
    if !observation.request_active(client) {
        return Ok(());
    }
    if request.unsupported_forwarding() {
        observation.report("FORWARDING_UNSUPPORTED");
        let (status, message) = request.forwarding_error.unwrap_or((
            501,
            "policy allowed request; protocol forwarding is not implemented",
        ));
        return reply(client, status, message);
    }
    let credential_plan = match credential_plan {
        Ok(plan) => plan,
        Err(_) => {
            observation.report("CREDENTIAL_BINDING_DENIED");
            return reply(client, 403, "invalid or ambiguous credential placement");
        }
    };
    if !context.credentials.is_current()
        || !context.credentials.permits(
            &credential_plan,
            &context.profile,
            &request.host,
            &request.method,
            &request.path,
            secure,
        )
        || !context.credentials.validate_guest_headers(
            &request.headers,
            &context.profile,
            &request.host,
            &request.method,
            &request.path,
            secure,
        )
    {
        observation.report("CREDENTIAL_BINDING_DENIED");
        return reply(client, 403, "credential binding denied");
    }
    if !context.active() {
        observation.report("CANCELLED");
        return Ok(());
    }
    let addresses = match resolve(&request.host, if secure { 443 } else { 80 }, context) {
        Ok(addresses) => addresses,
        Err(_) => {
            observation.report("DNS_FAILED");
            return reply(client, 502, "destination resolution failed or cancelled");
        }
    };
    let addresses = match public_ipv4_destinations(addresses) {
        Some(addresses) => addresses,
        None => {
            observation.report("PRIVATE_DESTINATION");
            return reply(
                client,
                403,
                "private, special-use, and IPv6-only destinations are blocked",
            );
        }
    };
    if !context.active() {
        observation.report("CANCELLED");
        return Ok(());
    }
    let timeout = context
        .deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(5));
    if timeout.is_zero() {
        observation.report("CANCELLED");
        return Ok(());
    }
    let upstream = match TcpStream::connect_timeout(&addresses[0], timeout) {
        Ok(stream) => stream,
        Err(_) => {
            observation.report("CONNECT_FAILED");
            return reply(client, 502, "upstream connection failed");
        }
    };
    if !observation.request_active(client) {
        return Ok(());
    }
    let mut upstream = context.socket(upstream)?;
    let transfer_time = Duration::from_secs(300);
    client.socket().phase(transfer_time);
    let result = if secure {
        let Some(tls) = context.tls.as_ref() else {
            observation.report("HTTPS_DISABLED");
            return reply(client, 503, "HTTPS inspection is not enabled");
        };
        match tls.connect(upstream, &request.host) {
            Ok(mut upstream) => {
                upstream.sock.phase(transfer_time);
                if !observation.request_active(client) {
                    return Ok(());
                }
                forward_observed(
                    client,
                    &mut upstream,
                    request,
                    context,
                    secure,
                    Some(observation),
                )
            }
            Err(_) => {
                observation.report("UPSTREAM_TLS_FAILED");
                reply(client, 502, "upstream TLS verification or handshake failed")
            }
        }
    } else {
        upstream.phase(transfer_time);
        forward_observed(
            client,
            &mut upstream,
            request,
            context,
            secure,
            Some(observation),
        )
    };
    if !observation.terminal {
        observation.report(if !context.active() {
            "CANCELLED"
        } else if result.is_err() {
            "IO_FAILED"
        } else {
            "COMPLETED"
        });
    }
    result
}
fn read_chunked_request(reader: &mut impl Read, body: &mut Vec<u8>) -> Result<()> {
    let mut framing = 0usize;
    loop {
        let line = response_line(reader)?;
        framing += line.len();
        if framing > 64 * 1024 {
            return Err("request chunk framing too large".into());
        }
        let text =
            std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| "invalid request chunk")?;
        let size_text = text.split(';').next().unwrap();
        if size_text.is_empty()
            || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
            || !text.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err("invalid request chunk".into());
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| "invalid request chunk")?;
        if size == 0 {
            if response_line(reader)? != b"\r\n" {
                return Err("request trailers are unsupported".into());
            }
            return Ok(());
        }
        if size > body::MAX_BODY.saturating_sub(body.len()) {
            return Err("request body too large".into());
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..])?;
        let mut crlf = [0; 2];
        reader.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err("invalid request chunk ending".into());
        }
    }
}

fn reply(client: &mut impl Write, status: u16, message: &str) -> Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    write!(
        client,
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{message}",
        message.len()
    )?;
    client.flush()?;
    Ok(())
}
