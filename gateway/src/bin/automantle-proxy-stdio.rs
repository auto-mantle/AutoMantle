#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::{
        io::{self, Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
        thread,
    };

    let socket = std::env::var_os("AUTOMANTLE_PROXY_SOCKET")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing proxy socket"))?;
    let mut stream = UnixStream::connect(socket)?;
    let mut upstream = stream.try_clone()?;
    let sender = thread::spawn(move || -> io::Result<()> {
        io::copy(&mut io::stdin(), &mut upstream)?;
        upstream.shutdown(Shutdown::Write)
    });
    let mut output = io::stdout().lock();
    let mut buffer = [0u8; 8192];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        output.flush()?;
    }
    sender
        .join()
        .map_err(|_| io::Error::other("proxy sender failed"))??;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("AutoMantle supports Linux only");
    std::process::exit(1);
}
