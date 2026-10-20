use crate::sandbox::Result;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub(super) fn client_request(socket: &Path, request: &Value) -> Result<Value> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot reach running gateway at {}: {e}; start it first",
            socket.display()
        )
    })?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    writeln!(stream, "{request}")?;
    let mut bytes = Vec::new();
    BufReader::new(stream.take(2 * 1024 * 1024 + 1)).read_until(b'\n', &mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 || bytes.last() != Some(&b'\n') {
        return Err("invalid gateway response".into());
    }
    let response: Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = response["error"].as_str() {
        return Err(error.to_string().into());
    }
    Ok(response["result"].clone())
}

pub(super) fn terminal_cli(socket: &Path, id: &str) -> Result<()> {
    let mut offset = 0u64;
    let info = client_request(
        socket,
        &json!({"command":"terminal-read","id":id,"offset":0}),
    )?;
    if !info["ready"].as_bool().unwrap_or(false) {
        return Err("VM terminal is not ready".into());
    }
    struct Restore(Option<libc::termios>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(original) = &self.0 {
                unsafe {
                    libc::tcsetattr(0, libc::TCSANOW, original);
                }
            }
        }
    }
    let mut restore = Restore(None);
    if unsafe { libc::isatty(0) } == 1 {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(0, original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        restore.0 = Some(original);
    }
    let name = client_request(socket, &json!({"command":"list-machines"}))
        .ok()
        .and_then(|machines| {
            machines.as_array().and_then(|items| {
                items
                    .iter()
                    .find(|vm| vm["runId"] == id)
                    .and_then(|vm| vm["name"].as_str())
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "VM".into());
    eprintln!("Terminal inside VM: {name}; Ctrl+] detaches without stopping the VM");
    let mut input = std::io::stdin();
    let mut output = std::io::stdout();
    loop {
        let reply = client_request(
            socket,
            &json!({"command":"terminal-read","id":id,"offset":offset}),
        )?;
        if reply["gap"] == true {
            output.write_all(b"\r\n[Older console output expired]\r\n")?;
        }
        let bytes = reply["data"]
            .as_array()
            .ok_or("invalid terminal output")?
            .iter()
            .map(|b| {
                b.as_u64()
                    .filter(|b| *b <= 255)
                    .map(|b| b as u8)
                    .ok_or("invalid terminal byte")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        output.write_all(&bytes)?;
        output.flush()?;
        offset = reply["next"].as_u64().ok_or("invalid terminal offset")?;
        if matches!(reply["state"].as_str(), Some("stopped" | "failed")) {
            return Ok(());
        }
        let mut poll = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 50) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if ready > 0 {
            let mut bytes = [0u8; 1024];
            let count = input.read(&mut bytes)?;
            if count == 0 || bytes[..count].contains(&29) {
                return Ok(());
            }
            let mut sent = 0;
            while sent < count {
                let reply = client_request(
                    socket,
                    &json!({"command":"terminal-write","id":id,"data":bytes[sent..count]}),
                )?;
                let written = reply["written"]
                    .as_u64()
                    .ok_or("invalid terminal input reply")? as usize;
                if written == 0 || written > count - sent {
                    return Err("terminal could not accept input".into());
                }
                sent += written;
            }
        }
    }
}
