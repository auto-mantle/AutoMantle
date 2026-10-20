use crate::sandbox::Result;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

const MAX_RESPONSE: usize = 256 * 1024;

pub fn request(
    socket: &Path,
    method: &str,
    endpoint: &str,
    body: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
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
        if framing.is_none() {
            if let Some(index) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
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
        }
        if let Some((start, length, status)) = framing {
            if bytes.len() >= start + length {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn does_not_wait_for_connection_close() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .unwrap();
        assert!(
            read_response(&mut client, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn preserves_error_body_and_rejects_incomplete_body() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad")
            .unwrap();
        assert!(
            read_response(&mut client, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .to_string()
                .contains("bad")
        );
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
            .unwrap();
        drop(server);
        assert!(read_response(&mut client, Instant::now() + Duration::from_secs(1)).is_err());
    }
    #[test]
    fn stalled_api_has_a_deadline() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(read_response(&mut client, start + Duration::from_millis(50)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
