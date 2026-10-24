//! Narrow, local IPC boundary for host operations that require root.
//!
//! The helper receives its listener from a root-owned systemd socket unit.
//! Only the dedicated gateway UID may submit requests.

use crate::sandbox::Result;
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

const SOCKET: &str = "/run/automantle-helper/control.sock";
const REQUEST_LIMIT: u64 = 64 * 1024;

mod host;

struct Reply {
    value: Value,
    file: Option<File>,
}

fn send_header(stream: &UnixStream, file: Option<&File>) -> Result<()> {
    let mut byte = if file.is_some() { b'F' } else { b'N' };
    let mut iov = libc::iovec {
        iov_base: &mut byte as *mut _ as *mut libc::c_void,
        iov_len: 1,
    };
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    let mut control = [0usize; 8];
    if let Some(file) = file {
        header.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        header.msg_controllen =
            unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as usize };
        let message = unsafe { libc::CMSG_FIRSTHDR(&header) };
        if message.is_null() {
            return Err("cannot prepare helper descriptor".into());
        }
        unsafe {
            (*message).cmsg_level = libc::SOL_SOCKET;
            (*message).cmsg_type = libc::SCM_RIGHTS;
            (*message).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize;
            *(libc::CMSG_DATA(message) as *mut libc::c_int) = file.as_raw_fd();
        }
    }
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &header, libc::MSG_NOSIGNAL) } != 1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn receive_header(stream: &UnixStream) -> Result<Option<File>> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut byte as *mut _ as *mut libc::c_void,
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    header.msg_controllen = mem::size_of_val(&control);
    if unsafe { libc::recvmsg(stream.as_raw_fd(), &mut header, libc::MSG_CMSG_CLOEXEC) } != 1
        || header.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err("invalid helper descriptor header".into());
    }
    let message = unsafe { libc::CMSG_FIRSTHDR(&header) };
    match byte {
        b'N' if message.is_null() => Ok(None),
        b'F' if !message.is_null() => {
            if unsafe {
                (*message).cmsg_level != libc::SOL_SOCKET
                    || (*message).cmsg_type != libc::SCM_RIGHTS
                    || (*message).cmsg_len
                        != libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize
                    || !libc::CMSG_NXTHDR(&header, message).is_null()
            } {
                return Err("invalid helper descriptor".into());
            }
            let fd = unsafe { *(libc::CMSG_DATA(message) as *const libc::c_int) };
            if fd < 0 {
                return Err("invalid helper descriptor".into());
            }
            Ok(Some(unsafe { File::from_raw_fd(fd) }))
        }
        _ => Err("invalid helper descriptor header".into()),
    }
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != mem::size_of::<libc::ucred>()
    {
        return Err("cannot authenticate helper peer".into());
    }
    Ok(credentials.uid)
}

fn gateway_uid() -> Result<u32> {
    let name = CString::new("automantle")?;
    let user = unsafe { libc::getpwnam(name.as_ptr()) };
    if user.is_null() {
        return Err("automantle service user is missing".into());
    }
    Ok(unsafe { (*user).pw_uid })
}

fn listener_from_systemd() -> Result<UnixListener> {
    let pid = std::env::var("LISTEN_PID")?.parse::<u32>()?;
    let count = std::env::var("LISTEN_FDS")?.parse::<u32>()?;
    if pid != std::process::id() || count != 1 {
        return Err("helper requires one systemd socket".into());
    }
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    if !listener
        .local_addr()?
        .as_pathname()
        .is_some_and(|p| p == Path::new(SOCKET))
    {
        return Err("unexpected helper socket".into());
    }
    Ok(listener)
}

fn dispatch(request: &Value, file: Option<File>) -> Result<Reply> {
    let fields = request
        .as_object()
        .ok_or("helper request must be an object")?;
    match request["command"].as_str() {
        Some("ping") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command"])?;
            Ok(Reply {
                value: json!({"status":"ready"}),
                file: None,
            })
        }
        Some("create-network") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id"])?;
            let id = run_id(request)?;
            host::active(id)?;
            let user = service_user(id)?;
            let network = crate::linux::network::HostNetwork::create(id, &user, "automantle")?;
            let socket = crate::packet_gate::guest_sender(&network.config().tap)?;
            let config = network.detach();
            Ok(Reply {
                value: serde_json::to_value(config)?,
                file: Some(socket),
            })
        }
        Some("remove-network") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id"])?;
            host::ensure_vmm_stopped(run_id(request)?)?;
            crate::linux::network::HostNetwork::remove_by_id(run_id(request)?)?;
            Ok(Reply {
                value: json!({"removed":true}),
                file: None,
            })
        }
        Some("create-run") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id"])?;
            host::create_run(run_id(request)?)?;
            Ok(Reply {
                value: json!({"created":true}),
                file: None,
            })
        }
        Some("prepare-run") => {
            exact_fields(fields, &["command", "id", "saved", "initramfs"])?;
            let saved = request["saved"]
                .as_bool()
                .ok_or("saved must be a boolean")?;
            let initramfs = request["initramfs"]
                .as_bool()
                .ok_or("initramfs must be a boolean")?;
            if saved != file.is_some() {
                return Err("saved root descriptor mismatch".into());
            }
            host::prepare_run(run_id(request)?, file, initramfs)?;
            Ok(Reply {
                value: json!({"prepared":true}),
                file: None,
            })
        }
        Some("release-saved") => {
            exact_fields(fields, &["command", "id"])?;
            host::release_saved(
                run_id(request)?,
                file.ok_or("saved root descriptor required")?,
            )?;
            Ok(Reply {
                value: json!({"released":true}),
                file: None,
            })
        }
        Some("start-vmm") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id", "settings"])?;
            host::start_vmm(run_id(request)?, &request["settings"])?;
            Ok(Reply {
                value: json!({"started":true}),
                file: None,
            })
        }
        Some("stop-vmm") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id"])?;
            host::stop_vmm(run_id(request)?)?;
            Ok(Reply {
                value: json!({"stopped":true}),
                file: None,
            })
        }
        Some("connect-vmm") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id", "kind"])?;
            let kind = request["kind"]
                .as_str()
                .ok_or("VM socket kind is required")?;
            let socket = host::connect_socket(run_id(request)?, kind)?;
            Ok(Reply {
                value: json!({"connected":true}),
                file: Some(socket),
            })
        }
        Some("destroy-run") => {
            if file.is_some() {
                return Err("unexpected helper descriptor".into());
            }
            exact_fields(fields, &["command", "id"])?;
            host::destroy_run(run_id(request)?)?;
            Ok(Reply {
                value: json!({"destroyed":true}),
                file: None,
            })
        }
        _ => Err("unknown helper operation".into()),
    }
}

fn exact_fields(fields: &serde_json::Map<String, Value>, expected: &[&str]) -> Result<()> {
    if fields.len() != expected.len() || fields.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err("invalid helper request fields".into());
    }
    Ok(())
}

fn run_id(request: &Value) -> Result<&str> {
    let id = request["id"].as_str().ok_or("run ID is required")?;
    if !crate::linux::valid_run_id(id) {
        return Err("invalid run ID".into());
    }
    Ok(id)
}

fn service_user(id: &str) -> Result<String> {
    let suffix = id.strip_prefix("automantle-vm-").ok_or("invalid run ID")?;
    Ok(format!("amv{}", &suffix[..10]))
}

fn handle(mut stream: UnixStream, uid: u32) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if peer_uid(&stream)? != uid {
        return Err("unauthorized helper peer".into());
    }
    let file = receive_header(&stream)?;
    let mut bytes = Vec::new();
    BufReader::new((&stream).take(REQUEST_LIMIT + 1)).read_until(b'\n', &mut bytes)?;
    let response = if bytes.len() as u64 > REQUEST_LIMIT || bytes.last() != Some(&b'\n') {
        Err("invalid helper request size".into())
    } else {
        serde_json::from_slice(&bytes)
            .map_err(Into::into)
            .and_then(|v| dispatch(&v, file))
    };
    let (response, file) = match response {
        Ok(reply) => (json!({"result":reply.value}), reply.file),
        Err(error) => (json!({"error":error.to_string()}), None),
    };
    send_header(&stream, file.as_ref())?;
    writeln!(stream, "{response}")?;
    Ok(())
}

pub fn serve() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("helper requires root".into());
    }
    let listener = listener_from_systemd()?;
    let uid = gateway_uid()?;
    listener.set_nonblocking(true)?;
    let mut last_request = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                last_request = Instant::now();
                if let Err(error) = handle(stream, uid) {
                    eprintln!("helper request rejected: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if last_request.elapsed() >= Duration::from_secs(60) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn request(value: Value) -> Result<(Value, Option<File>)> {
    request_with_file(value, None)
}

pub fn request_with_file(value: Value, file: Option<&File>) -> Result<(Value, Option<File>)> {
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if peer_uid(&stream)? != 0 {
        return Err("helper server is not root-owned".into());
    }
    send_header(&stream, file)?;
    writeln!(stream, "{value}")?;
    let file = receive_header(&stream)?;
    let mut bytes = Vec::new();
    BufReader::new((&stream).take(REQUEST_LIMIT + 1)).read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > REQUEST_LIMIT || bytes.last() != Some(&b'\n') {
        return Err("invalid helper response".into());
    }
    let response: Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = response["error"].as_str() {
        return Err(error.to_owned().into());
    }
    let result = response
        .get("result")
        .cloned()
        .ok_or("missing helper result")?;
    Ok((result, file))
}

pub fn connect_vmm(id: &str, kind: &str) -> Result<UnixStream> {
    let (_, socket) = request(json!({"command":"connect-vmm","id":id,"kind":kind}))?;
    let file = socket.ok_or("helper did not return VM socket")?;
    Ok(unsafe { UnixStream::from_raw_fd(file.into_raw_fd()) })
}

#[cfg(test)]
mod tests {
    use super::{dispatch, receive_header, send_header};
    use serde_json::json;
    use std::{fs::File, os::unix::net::UnixStream};

    #[test]
    fn descriptor_transfer() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        send_header(&sender, Some(&file)).unwrap();
        assert!(receive_header(&receiver).unwrap().is_some());
        send_header(&sender, None).unwrap();
        assert!(receive_header(&receiver).unwrap().is_none());
    }

    #[test]
    fn helper_rejects_unexpected_requests() {
        assert!(dispatch(&json!({"command":"ping","extra":true}), None).is_err());
        assert!(dispatch(&json!({"command":"create-run","id":"../../tmp"}), None).is_err());
        assert!(
            dispatch(
                &json!({"command":"prepare-run","id":"x","saved":true,"initramfs":false}),
                None
            )
            .is_err()
        );
    }
}
