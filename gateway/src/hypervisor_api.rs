use crate::sandbox::Result;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

const MAX_RESPONSE: usize = 256 * 1024;

pub fn request(
    mut stream: UnixStream,
    method: &str,
    endpoint: &str,
    body: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or("API deadline exceeded")?
        .min(Duration::from_secs(2));
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "{method} /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    read_response(&mut stream, deadline)
}

fn read_response(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut framing = None;
    loop {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or("API deadline exceeded")?
            .min(Duration::from_secs(2));
        stream.set_read_timeout(Some(timeout))?;
        let mut buffer = [0; 4096];
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Err("truncated API response".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_RESPONSE {
            return Err("API response is too large".into());
        }
        if framing.is_none()
            && let Some(index) = bytes.windows(4).position(|s| s == b"\r\n\r\n")
        {
            let header = std::str::from_utf8(&bytes[..index])?;
            let status = header
                .lines()
                .next()
                .and_then(|s| s.split_whitespace().nth(1))
                .ok_or("missing HTTP status")?
                .parse::<u16>()?;
            let mut length = None;
            for line in header.lines().skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err("unsupported API transfer encoding".into());
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        if length.is_some() {
                            return Err("duplicate API content length".into());
                        }
                        length = Some(value.trim().parse::<usize>()?);
                    }
                }
            }
            let length = if status == 204 {
                0
            } else {
                length.ok_or("missing API content length")?
            };
            if length > MAX_RESPONSE {
                return Err("API body is too large".into());
            }
            framing = Some((index + 4, length, status));
        }
        if let Some((start, length, status)) = framing
            && bytes.len() >= start + length
        {
            let body = bytes[start..start + length].to_vec();
            if !(200..300).contains(&status) {
                return Err(format!(
                    "Cloud Hypervisor HTTP {status}: {}",
                    String::from_utf8_lossy(&body)
                )
                .into());
            }
            return Ok(body);
        }
    }
}
