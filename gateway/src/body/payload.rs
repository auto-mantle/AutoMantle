//! Disk-backed bodies keep transfer size independent of heap allocation.
use crate::sandbox::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    ops::Deref,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::Arc,
};

#[derive(Clone, Default)]
pub struct Payload(Option<Arc<Mapping>>);

struct Mapping {
    address: *mut libc::c_void,
    length: usize,
}
// The mapping is read-only. Its unlinked backing file is never exposed or modified
// after mapping, and remains alive through the mapping until the final Arc drops.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address, self.length) };
    }
}
impl Deref for Payload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            None => &[],
            Some(mapping) => unsafe {
                std::slice::from_raw_parts(mapping.address.cast(), mapping.length)
            },
        }
    }
}
impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("bytes", &self.len())
            .finish()
    }
}

#[derive(Default)]
pub struct Spool {
    file: Option<File>,
    length: usize,
}
impl Spool {
    pub fn finish(self) -> Result<Payload> {
        if self.length == 0 {
            return Ok(Payload::default());
        }
        let file = self.file.ok_or("missing transfer spool")?;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Payload(Some(Arc::new(Mapping {
            address,
            length: self.length,
        }))))
    }
}
impl Write for Spool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // A Rust slice must fit the process address space; this is not a transfer quota.
        self.length
            .checked_add(bytes.len())
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or_else(|| io::Error::other("transfer exceeds process address space"))?;
        if self.file.is_none() {
            let create = || -> Result<File> {
                let path = crate::rootless::data_parent()?
                    .join(format!("transfer-{}", crate::linux::new_uuid()?));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                // Unlink immediately: cancellation, errors, and process exit leave no payload file.
                fs::remove_file(path)?;
                Ok(file)
            };
            self.file = Some(create().map_err(|e| io::Error::other(e.to_string()))?);
        }
        let written = self.file.as_mut().unwrap().write(bytes)?;
        self.length += written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn copy_exact(
    reader: &mut impl Read,
    writer: &mut impl Write,
    mut size: u64,
    active: &impl Fn() -> bool,
) -> Result<()> {
    let mut buffer = [0; 64 * 1024];
    while size > 0 {
        if !active() {
            return Err("request cancelled".into());
        }
        let count = size.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        writer.write_all(&buffer[..count])?;
        size -= count as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spool_survives_cloning_and_removes_its_backing_name() {
        let mut spool = Spool::default();
        spool.write_all(b"first").unwrap();
        spool.write_all(b" second").unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(spool.file.as_ref().unwrap().metadata().unwrap().nlink(), 0);
        let payload = spool.finish().unwrap();
        let cloned = payload.clone();
        drop(payload);
        assert_eq!(&*cloned, b"first second");
    }
}
