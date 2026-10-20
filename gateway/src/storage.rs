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
            trusted_directory(&path)?;
        }
        if fs::metadata(&self.directory)?.mode() & 0o077 != 0 {
            return Err("disk directory must have mode 0700".into());
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    pub struct Fixture {
        pub store: Store,
        pub directory: PathBuf,
        pub source: PathBuf,
    }
    impl Fixture {
        pub fn new() -> Self {
            let directory =
                Path::new("/run").join(format!("{}-storage-test", linux::new_run_id().unwrap()));
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let source = directory.join("source");
            fs::write(&source, b"installed harness and login state").unwrap();
            Self {
                store: Store {
                    directory: directory.join("disks"),
                },
                directory,
                source,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn cancelled_import_does_not_publish_or_keep_its_reserved_name() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        assert!(
            fixture
                .store
                .create_cancellable("cancelled", &fixture.source, &AtomicBool::new(true))
                .is_err()
        );
        assert!(!fixture.store.directory.join("cancelled").exists());
        assert!(fixture.store.create("cancelled", &fixture.source).is_ok());
    }

    #[test]
    fn persistent_import_exclusive_preparation_and_private_runtime_copy() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        let store = &fixture.store;
        store.create("harness", &fixture.source).unwrap();
        assert!(store.create("harness", &fixture.source).is_err());
        let first = store.acquire("harness", false).unwrap();
        let second = store.acquire("harness", false).unwrap();
        assert!(store.acquire("harness", true).is_err());
        let runtime = fixture.directory.join("runtime");
        linux::copy_image(
            &first.path,
            &runtime,
            false,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        fs::write(&runtime, b"task changes").unwrap();
        assert_eq!(
            fs::read(&first.path).unwrap(),
            fs::read(&fixture.source).unwrap()
        );
        drop((first, second));
        let preparation = store.acquire("harness", true).unwrap();
        assert!(store.acquire("harness", true).is_err());
        assert!(store.acquire("harness", false).is_err());
        fs::write(&preparation.path, b"saved installation").unwrap();
        drop(preparation);
        let reopened = Store {
            directory: store.directory.clone(),
        };
        let later = reopened.acquire("harness", false).unwrap();
        assert_eq!(fs::read(later.path).unwrap(), b"saved installation");
        assert_eq!(reopened.list().unwrap()[0]["name"], "harness");
        assert_eq!(
            fs::read(&fixture.source).unwrap(),
            b"installed harness and login state"
        );
        fs::remove_file(runtime).unwrap();
        assert!(store.acquire("harness", false).is_ok());
    }

    #[test]
    fn rejects_symlinks_traversal_and_cleans_failed_imports() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        let store = &fixture.store;
        assert!(store.create("../escape", &fixture.source).is_err());
        assert!(
            store
                .create("missing", &fixture.directory.join("absent"))
                .is_err()
        );
        assert!(!store.directory.join("missing").exists());
        store.create("harness", &fixture.source).unwrap();
        let disk = store.directory.join("harness/rootfs");
        fs::remove_file(&disk).unwrap();
        symlink(&fixture.source, &disk).unwrap();
        assert!(store.acquire("harness", true).is_err());
        assert!(store.list().is_err());
        fs::remove_file(&disk).unwrap();
        fs::write(&disk, b"disk").unwrap();
        fs::set_permissions(&disk, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(store.acquire("harness", false).is_err());
        let alias = fixture.directory.join("alias");
        symlink(&store.directory, &alias).unwrap();
        assert!(Store { directory: alias }.list().is_err());
    }

    #[test]
    fn sparse_copy_preserves_trailing_zeroes_and_logical_size() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let fixture = Fixture::new();
        let file = OpenOptions::new()
            .write(true)
            .open(&fixture.source)
            .unwrap();
        file.set_len(3 * 1024 * 1024).unwrap();
        drop(file);
        fixture.store.create("sparse", &fixture.source).unwrap();
        let lease = fixture.store.acquire("sparse", false).unwrap();
        assert_eq!(
            fs::read(&lease.path).unwrap(),
            fs::read(&fixture.source).unwrap()
        );
        assert_eq!(fs::metadata(&lease.path).unwrap().len(), 3 * 1024 * 1024);
        assert!(fs::metadata(&lease.path).unwrap().blocks() * 512 < 3 * 1024 * 1024);
    }
}
