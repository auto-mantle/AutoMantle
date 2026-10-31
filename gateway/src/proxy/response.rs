use super::{MAX_HEADER, Result, read_header};
use crate::body::{Payload, Spool, copy_exact};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

pub(super) fn stream_response(
    client: &mut impl Write,
    upstream: &mut impl Read,
    method: &str,
    active: impl Fn() -> bool,
) -> Result<()> {
    transfer_response(client, &mut io::sink(), upstream, method, false, &active)
}

pub(super) fn credential_response(
    upstream: &mut impl Read,
    method: &str,
    active: &impl Fn() -> bool,
) -> Result<(Payload, Payload)> {
    let mut response = Spool::default();
    let mut decoded = Spool::default();
    transfer_response(&mut response, &mut decoded, upstream, method, true, active)?;
    Ok((response.finish()?, decoded.finish()?))
}

// Keep the original HTTP framing and the decoded body separately. Credential
// checks examine both before sending any bytes to the guest, including secrets
// split across chunks or read buffers.
struct BodyWriter<'a, W, D> {
    raw: &'a mut W,
    decoded: &'a mut D,
}
impl<W: Write, D: Write> Write for BodyWriter<'_, W, D> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.raw.write_all(bytes)?;
        self.decoded.write_all(bytes)?;
        self.raw.flush()?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.raw.flush()
    }
}

fn transfer_response(
    raw: &mut impl Write,
    decoded: &mut impl Write,
    upstream: &mut impl Read,
    method: &str,
    protected: bool,
    active: &impl Fn() -> bool,
) -> Result<()> {
    let header = read_header(upstream)?;
    let (code, length, chunked) = response_framing(&header, protected)?;
    if !active() {
        return Err("request cancelled".into());
    }
    raw.write_all(&header)?;
    raw.flush()?;
    if method == "HEAD" || matches!(code, 204 | 304) {
        return Ok(());
    }
    if let Some(length) = length {
        return copy_exact(
            upstream,
            &mut BodyWriter { raw, decoded },
            length as u64,
            active,
        );
    }
    if chunked {
        loop {
            if !active() {
                return Err("request cancelled".into());
            }
            let line = response_line(upstream)?;
            let text = std::str::from_utf8(&line[..line.len() - 2])?;
            if text.is_empty() || text.len() > 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid response chunk".into());
            }
            let size = u64::from_str_radix(text, 16)?;
            raw.write_all(&line)?;
            if size == 0 {
                let mut trailers = 0;
                loop {
                    let line = response_line(upstream)?;
                    trailers += line.len();
                    if trailers > MAX_HEADER {
                        return Err("response trailers too large".into());
                    }
                    raw.write_all(&line)?;
                    if line == b"\r\n" {
                        raw.flush()?;
                        return Ok(());
                    }
                }
            }
            copy_exact(upstream, &mut BodyWriter { raw, decoded }, size, active)?;
            let mut end = [0; 2];
            upstream.read_exact(&mut end)?;
            if end != *b"\r\n" {
                return Err("invalid response chunk terminator".into());
            }
            raw.write_all(&end)?;
            raw.flush()?;
        }
    }
    let mut buffer = [0; 64 * 1024];
    loop {
        if !active() {
            return Err("request cancelled".into());
        }
        let count = upstream.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        BodyWriter { raw, decoded }.write_all(&buffer[..count])?;
    }
}

fn response_framing(header: &[u8], protected: bool) -> Result<(u16, Option<usize>, bool)> {
    let text = std::str::from_utf8(header)?;
    let mut lines = text.split("\r\n");
    let mut status = lines
        .next()
        .ok_or("missing response status")?
        .split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err("invalid response protocol".into());
    }
    let code: u16 = status.next().ok_or("missing status")?.parse()?;
    if !(200..=599).contains(&code) {
        return Err("unsupported response status".into());
    }
    let mut length = None;
    let mut chunked = false;
    let mut framing = BTreeSet::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("invalid response header")?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "content-encoding"
        ) && !framing.insert(name.clone())
        {
            return Err("duplicate response framing".into());
        }
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid response length".into());
                }
                length = Some(value.parse::<usize>()?);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err("unsupported response coding".into());
                }
                chunked = true;
            }
            "content-encoding" if protected && !value.eq_ignore_ascii_case("identity") => {
                return Err("compressed credential response denied".into());
            }
            _ => {}
        }
    }
    if chunked && length.is_some() {
        return Err("ambiguous response framing".into());
    }
    Ok((code, length, chunked))
}
pub(super) fn response_line(upstream: &mut impl Read) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() < 1024 {
        let mut byte = [0];
        upstream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err("response line too long".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u64);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn downloads_above_previous_cap_stream_with_and_without_content_length() {
        let size = 129 * 1024 * 1024;
        for length in [format!("Content-Length: {size}\r\n"), String::new()] {
            let header = format!("HTTP/1.1 200 OK\r\n{length}\r\n");
            let mut upstream = header.as_bytes().chain(io::repeat(b'x').take(size));
            let mut output = Counter(0);
            stream_response(&mut output, &mut upstream, "GET", || true).unwrap();
            assert_eq!(output.0, header.len() as u64 + size);
        }
    }
    #[test]
    fn credential_responses_above_previous_cap_preserve_every_byte() {
        let size = 9 * 1024 * 1024;
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
        let mut upstream = header.as_bytes().chain(io::repeat(b'x').take(size));
        let (raw, decoded) = credential_response(&mut upstream, "GET", &|| true).unwrap();
        assert_eq!(raw.len(), header.len() + size as usize);
        assert_eq!(decoded.len(), size as usize);
        assert!(decoded.iter().all(|b| *b == b'x'));
    }
    #[test]
    fn chunked_inspection_reassembles_secrets_split_between_chunks() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nabcdefghij\r\na\r\nklmnopqrst\r\n0\r\n\r\n";
        let (raw, decoded) = credential_response(&mut &response[..], "GET", &|| true).unwrap();
        assert_eq!(&*raw, response);
        assert_eq!(&*decoded, b"abcdefghijklmnopqrst");
        let credentials = crate::credentials::Credentials::parse(&serde_json::json!({
            "credentials": [{"placeholder":"API_KEY", "secret":"abcdefghijklmnopqrst",
                "scopes":[{"agentProfileId":"12345678-1234-1234-1234-123456789abc", "host":"example.com", "paths":["/*"], "location":"header", "selector":"x-api-key"}]}]
        }).to_string()).unwrap();
        assert!(!credentials.contains_secret(&raw));
        assert!(credentials.contains_secret(&decoded));
    }
    #[test]
    fn transfers_still_reject_truncation_and_support_cancellation() {
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        assert!(stream_response(&mut io::sink(), &mut &short[..], "GET", || true).is_err());
        assert!(credential_response(&mut &short[..], "GET", &|| true).is_err());
        let mut output = Vec::new();
        assert!(stream_response(&mut output, &mut &short[..], "GET", || false).is_err());
        assert!(output.is_empty());
    }
    #[test]
    fn ambiguous_upstream_framing_is_rejected() {
        assert!(
            response_framing(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                false,
            )
            .is_err()
        );
        assert!(
            response_framing(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_responses_reject_compression() {
        let header = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n";
        assert!(response_framing(header, true).is_err());
        assert!(response_framing(header, false).is_ok());
    }
}
