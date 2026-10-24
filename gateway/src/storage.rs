use crate::{
    linux,
    sandbox::{Result, valid_disk_name},
};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Store {
    pub directory: PathBuf,
}
pub struct Lease {
    pub path: PathBuf,
    _file: File,
}

impl Store {
    pub(crate) fn ensure(&self) -> Result<()> {
        if !self.directory.is_absolute() {
            return Err("disk directory must be absolute".into());
        }
        let mut path = PathBuf::from("/");
        for part in self.directory.components().skip(1) {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err("invalid disk directory".into());
            }
            path.push(part);
            if !path.try_exists()? {
                DirBuilder::new().mode(0o700).create(&path)?;
            }
            trusted_parent_directory(&path)?;
        }
        let meta = fs::metadata(&self.directory)?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("disk directory must be gateway-owned with mode 0700".into());
        }
        Ok(())
    }

    pub(crate) fn disk(&self, name: &str) -> Result<PathBuf> {
        if !valid_disk_name(name) {
            return Err("invalid saved disk name".into());
        }
        self.ensure()?;
        Ok(self.directory.join(name))
    }

    pub fn create(&self, name: &str, source: &Path) -> Result<Value> {
        self.create_cancellable(name, source, &AtomicBool::new(false))
    }

    pub fn create_cancellable(
        &self,
        name: &str,
        source: &Path,
        cancel: &AtomicBool,
    ) -> Result<Value> {
        let directory = self.disk(name)?;
        DirBuilder::new().mode(0o700).create(&directory)?;
        let temporary = directory.join("importing");
        let result = (|| -> Result<Value> {
            linux::copy_image(
                source,
                &temporary,
                false,
                cancel,
                Instant::now() + Duration::from_secs(110),
            )?;
            File::open(&temporary)?.sync_all()?;
            fs::rename(&temporary, directory.join("rootfs"))?;
            File::open(&directory)?.sync_all()?;
            File::open(&self.directory)?.sync_all()?;
            Ok(json!({"name":name,"bytes":fs::metadata(directory.join("rootfs"))?.len()}))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            let _ = fs::remove_file(directory.join("rootfs"));
            let _ = fs::remove_dir(&directory);
        }
        result
    }

    pub fn list(&self) -> Result<Value> {
        self.ensure()?;
        let mut disks = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !valid_disk_name(&name) {
                continue;
            }
            trusted_directory(&entry.path())?;
            let path = entry.path().join("rootfs");
            let meta = match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                result => result?,
            };
            if !meta.is_file() {
                return Err("saved disk is not a regular file".into());
            }
            disks.push(json!({"name":name,"bytes":meta.len()}));
        }
        disks.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(json!(disks))
    }

    pub fn acquire(&self, name: &str, preparation: bool) -> Result<Lease> {
        let directory = self.disk(name)?;
        trusted_directory(&directory)?;
        let path = directory.join("rootfs");
        let file = OpenOptions::new()
            .read(true)
            .write(preparation)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.len() == 0
            || meta.len() > 64 * 1024 * 1024 * 1024
            || meta.nlink() != 1
        {
            return Err("invalid saved disk".into());
        }
        let operation = if preparation {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "saved disk {name} is busy; stop its other runs before preparation"
            )
            .into());
        }
        let meta = file.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("saved disk must be private and owned by the gateway user".into());
        }
        Ok(Lease { path, _file: file })
    }
}

pub(crate) fn trusted_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err(format!("untrusted disk directory: {}", path.display()).into());
    }
    Ok(())
}

fn trusted_parent_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || ![0, unsafe { libc::geteuid() }].contains(&meta.uid())
        || meta.mode() & 0o022 != 0
    {
        return Err(format!("untrusted disk parent: {}", path.display()).into());
    }
    Ok(())
}
