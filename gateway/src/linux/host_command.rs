use crate::sandbox::Result;
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT: usize = 1024 * 1024;

pub(crate) fn command(command: &mut Command) -> Result<Output> {
    run_with_timeout(command, COMMAND_TIMEOUT)
}

pub(crate) fn checked(command: &mut Command) -> Result<Output> {
    let output = self::command(command)?;
    if !output.status.success() {
        return Err(format!(
            "host command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(output)
}

fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = collect_output(&mut child, Instant::now() + timeout);
    if result.is_err() {
        let _ = child.kill();
        thread::spawn(move || {
            let _ = child.wait();
        });
    }
    result
}

fn collect_output(child: &mut Child, deadline: Instant) -> Result<Output> {
    let mut stdout = child.stdout.take().ok_or("missing host command stdout")?;
    let mut stderr = child.stderr.take().ok_or("missing host command stderr")?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_closed = false;
    let mut err_closed = false;
    loop {
        drain(&mut stdout, &mut out, &mut out_closed)?;
        drain(&mut stderr, &mut err, &mut err_closed)?;
        if let Some(status) = child.try_wait()? {
            if out_closed && err_closed {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("host command timed out".into());
        }
        let mut fds = [
            libc::pollfd {
                fd: if out_closed { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if err_closed { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait_ms = remaining.as_millis().min(25) as i32;
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, wait_ms) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

fn set_nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, closed: &mut bool) -> Result<()> {
    if *closed {
        return Ok(());
    }
    let mut bytes = [0u8; 8192];
    loop {
        match pipe.read(&mut bytes) {
            Ok(0) => {
                *closed = true;
                return Ok(());
            }
            Ok(count) => {
                if output.len() + count > MAX_OUTPUT {
                    return Err("host command output exceeded 1 MiB".into());
                }
                output.extend_from_slice(&bytes[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
