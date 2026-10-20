use super::{MAX_HEADER, MAX_RESPONSE, Result, read_header, reply};
use std::collections::BTreeSet;
use std::io::{Read, Write};

pub(super) fn stream_response(
    client: &mut impl Write,
    upstream: &mut impl Read,
    method: &str,
    limit: u64,
    active: impl Fn() -> bool,
) -> Result<()> {
    let header = read_header(upstream)?;
    let (code, length, chunked) = response_framing(&header, false)?;
    let mut remaining = limit
        .checked_sub(header.len() as u64)
        .ok_or("response too large")?;
    let no_body = method == "HEAD" || matches!(code, 204 | 304);
    if !no_body && length.is_some_and(|size| size as u64 > remaining) {
        return reply(client, 502, "upstream response too large");
    }
    if !active() {
        return Err("request cancelled".into());
    }
    client.write_all(&header)?;
    client.flush()?;
    if no_body {
        return Ok(());
    }
    if let Some(length) = length {
        return stream_exact(client, upstream, length as u64, &active);
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
            remaining = remaining
                .checked_sub(line.len() as u64)
                .ok_or("response too large")?;
            client.write_all(&line)?;
            if size == 0 {
                let mut trailers = 0;
                loop {
                    let line = response_line(upstream)?;
                    trailers += line.len();
                    if trailers > MAX_HEADER {
                        return Err("response trailers too large".into());
                    }
                    remaining = remaining
                        .checked_sub(line.len() as u64)
                        .ok_or("response too large")?;
                    client.write_all(&line)?;
                    if line == b"\r\n" {
                        client.flush()?;
                        return Ok(());
                    }
                }
            }
            remaining = remaining
                .checked_sub(size)
                .and_then(|r| r.checked_sub(2))
                .ok_or("response too large")?;
            stream_exact(client, upstream, size, &active)?;
            let mut end = [0; 2];
            upstream.read_exact(&mut end)?;
            if end != *b"\r\n" {
                return Err("invalid response chunk terminator".into());
            }
            client.write_all(&end)?;
            client.flush()?;
        }
    }
    let mut block = [0; 8192];
    loop {
        if !active() {
            return Err("request cancelled".into());
        }
        let count = upstream.read(&mut block)?;
        if count == 0 {
            return Ok(());
        }
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or("response too large")?;
        client.write_all(&block[..count])?;
        client.flush()?;
    }
}

fn stream_exact(
    client: &mut impl Write,
    upstream: &mut impl Read,
    mut size: u64,
    active: &impl Fn() -> bool,
) -> Result<()> {
    let mut block = [0; 8192];
    while size > 0 {
        if !active() {
            return Err("request cancelled".into());
        }
        let count = block.len().min(size as usize);
        upstream.read_exact(&mut block[..count])?;
        client.write_all(&block[..count])?;
        client.flush()?;
        size -= count as u64;
    }
    Ok(())
}

pub(super) fn credential_response(
    upstream: &mut impl Read,
    method: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let response = read_header(upstream)?;
    let (code, length, chunked) = response_framing(&response, true)?;
    if method == "HEAD" || matches!(code, 204 | 304) {
        return Ok((response, Vec::new()));
    }
    credential_body(upstream, response, length, chunked)
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
fn credential_body(
    upstream: &mut impl Read,
    mut response: Vec<u8>,
    length: Option<usize>,
    chunked: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut decoded = Vec::new();
    if let Some(length) = length {
        if length > MAX_RESPONSE as usize - response.len() {
            return Err("response too large".into());
        }
        let start = response.len();
        response.resize(start + length, 0);
        upstream.read_exact(&mut response[start..])?;
    } else if chunked {
        loop {
            let line = response_line(upstream)?;
            let size = std::str::from_utf8(&line[..line.len() - 2])?;
            if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid response chunk".into());
            }
            let size = usize::from_str_radix(size, 16)?;
            if size > MAX_RESPONSE as usize
                || response.len() + line.len() + size + 2 > MAX_RESPONSE as usize
            {
                return Err("response too large".into());
            }
            response.extend_from_slice(&line);
            if size == 0 {
                let mut trailers = 0;
                loop {
                    let line = response_line(upstream)?;
                    trailers += line.len();
                    if trailers > MAX_HEADER || response.len() + line.len() > MAX_RESPONSE as usize
                    {
                        return Err("response trailers too large".into());
                    }
                    response.extend_from_slice(&line);
                    if line == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let start = response.len();
            response.resize(start + size + 2, 0);
            upstream.read_exact(&mut response[start..])?;
            if &response[start + size..] != b"\r\n" {
                return Err("invalid response chunk terminator".into());
            }
            decoded.extend_from_slice(&response[start..start + size]);
        }
    } else {
        let mut buffer = [0; 8192];
        loop {
            let count = upstream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if response.len() + count > MAX_RESPONSE as usize {
                return Err("response too large".into());
            }
            response.extend_from_slice(&buffer[..count]);
        }
    }
    Ok((response, decoded))
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
