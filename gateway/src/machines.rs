use crate::{
    linux,
    sandbox::{Result, valid_disk_name, valid_uuid},
    storage::Store,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub name: String,
    pub agent_profile_id: String,
    pub memory_mib: u64,
    pub vcpu_count: u64,
    #[serde(default)]
    pub setup: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn iso_creation_keeps_source_and_persists_boot_choice() {
        let base = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".automantle-iso-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let source = base.join("installer.iso");
        let mut bytes = vec![0u8; 0x9000];
        bytes[0x8001..0x8006].copy_from_slice(b"CD001");
        fs::write(&source, &bytes).unwrap();
        let store = Store {
            directory: base.join("vms"),
        };
        let settings = Settings {
            name: "Test".into(),
            agent_profile_id: "12345678-1234-4234-8234-123456789abc".into(),
            memory_mib: 2048,
            vcpu_count: 2,
            setup: false,
        };
        assert!(
            store
                .create_iso_machine(settings.clone(), Path::new("relative.iso"))
                .is_err()
        );
        let vm = store.create_iso_machine(settings.clone(), &source).unwrap();
        assert!(!vm.install_complete);
        assert_eq!(
            fs::metadata(store.disk(&vm.id).unwrap().join("rootfs"))
                .unwrap()
                .len(),
            32 * 1024 * 1024 * 1024
        );
        assert_eq!(fs::read(&source).unwrap(), bytes);
        store.mark_install_complete(&vm.id).unwrap();
        let updated = store.update_machine(&vm.id, settings).unwrap();
        assert!(updated.install_complete);
        assert_eq!(updated.iso_path, vm.iso_path);
        fs::write(
            store.disk(&vm.id).unwrap().join("qemu.log"),
            b"startup error",
        )
        .unwrap();
        store.delete_machine(&vm.id).unwrap();
        fs::remove_dir(base.join("vms")).unwrap();
        fs::remove_file(source).unwrap();
        fs::remove_dir(base).unwrap();
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.chars().count() > 80
            || self.name.chars().any(char::is_control)
        {
            return Err("VM name must contain 1-80 characters without control characters".into());
        }
        if !valid_uuid(&self.agent_profile_id) {
            return Err("Choose an existing Agent Profile".into());
        }
        if !(128..=65536).contains(&self.memory_mib) || !(1..=64).contains(&self.vcpu_count) {
            return Err("Memory must be 128-65536 MiB and CPUs must be 1-64".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Machine {
    pub id: String,
    #[serde(flatten)]
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_path: Option<String>,
    #[serde(default)]
    pub install_complete: bool,
}
impl Store {
    pub fn machine(&self, id: &str) -> Result<Machine> {
        let directory = self.disk(id)?;
        super::storage::trusted_directory(&directory)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("machine.json"))?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.len() > 16384
            || meta.nlink() != 1
        {
            return Err("Invalid private VM definition".into());
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(16385)
            .read_to_end(&mut bytes)?;
        let machine: Machine = serde_json::from_slice(&bytes)?;
        if machine.id != id {
            return Err("VM identity does not match its environment".into());
        }
        machine.settings.validate()?;
        Ok(machine)
    }
    pub fn machines(&self) -> Result<Vec<Machine>> {
        self.ensure()?;
        let mut machines = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if !valid_disk_name(&id) {
                continue;
            }
            super::storage::trusted_directory(&entry.path())?;
            if entry.path().join("machine.json").try_exists()? {
                machines.push(self.machine(&id)?);
            }
        }
        machines.sort_by(|a, b| a.settings.name.cmp(&b.settings.name).then(a.id.cmp(&b.id)));
        Ok(machines)
    }
    pub fn save_machine(&self, machine: &Machine) -> Result<()> {
        machine.settings.validate()?;
        let directory = self.disk(&machine.id)?;
        super::storage::trusted_directory(&directory)?;
        let temporary = directory.join(format!(".{}.json", linux::new_run_id()?));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec_pretty(machine)?)?;
            file.sync_all()?;
            fs::rename(&temporary, directory.join("machine.json"))?;
            File::open(&directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn create_machine(
        &self,
        settings: Settings,
        base: &Path,
        cancel: &AtomicBool,
    ) -> Result<Machine> {
        settings.validate()?;
        let id = linux::new_run_id()?.replacen("automantle-vm-", "vm-", 1);
        self.create_cancellable(&id, base, cancel)?;
        let machine = Machine {
            id,
            settings,
            iso_path: None,
            install_complete: true,
        };
        if let Err(error) = self.save_machine(&machine) {
            let _ = fs::remove_file(self.disk(&machine.id)?.join("rootfs"));
            let _ = fs::remove_dir(self.disk(&machine.id)?);
            return Err(error);
        }
        Ok(machine)
    }
    pub fn create_iso_machine(&self, settings: Settings, iso: &Path) -> Result<Machine> {
        settings.validate()?;
        if !iso.is_absolute()
            || iso
                .extension()
                .and_then(|ext| ext.to_str())
                .is_none_or(|ext| !ext.eq_ignore_ascii_case("iso"))
        {
            return Err("Choose an absolute path to an ISO file on this machine".into());
        }
        let iso = fs::canonicalize(iso)?;
        let mut file = File::open(&iso)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() < 0x8006
            || metadata.len() > 64 * 1024 * 1024 * 1024
        {
            return Err("ISO must be a regular file between 32 KiB and 64 GiB".into());
        }
        file.seek(SeekFrom::Start(0x8001))?;
        let mut signature = [0u8; 5];
        file.read_exact(&mut signature)?;
        if &signature != b"CD001" {
            return Err("Selected file is not an ISO image".into());
        }
        let id = linux::new_run_id()?.replacen("automantle-vm-", "vm-", 1);
        let directory = self.disk(&id)?;
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let result = (|| -> Result<Machine> {
            let disk = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join("rootfs"))?;
            disk.set_len(32 * 1024 * 1024 * 1024)?;
            disk.sync_all()?;
            let machine = Machine {
                id,
                settings,
                iso_path: Some(iso.to_string_lossy().into_owned()),
                install_complete: false,
            };
            self.save_machine(&machine)?;
            Ok(machine)
        })();
        if result.is_err() {
            let _ = fs::remove_file(directory.join("machine.json"));
            let _ = fs::remove_file(directory.join("rootfs"));
            let _ = fs::remove_dir(&directory);
        }
        result
    }
    pub fn copy_machine(&self, id: &str, name: String, cancel: &AtomicBool) -> Result<Machine> {
        let source = self.machine(id)?;
        let mut settings = source.settings;
        settings.name = name;
        settings.validate()?;
        let lease = self.acquire(id, true)?;
        let mut copy = self.create_machine(settings, &lease.path, cancel)?;
        copy.iso_path = source.iso_path;
        copy.install_complete = source.install_complete;
        self.save_machine(&copy)?;
        Ok(copy)
    }
    pub fn update_machine(&self, id: &str, settings: Settings) -> Result<Machine> {
        let previous = self.machine(id)?;
        settings.validate()?;
        let _lease = self.acquire(id, true)?;
        let machine = Machine {
            id: id.to_owned(),
            settings,
            iso_path: previous.iso_path,
            install_complete: previous.install_complete,
        };
        self.save_machine(&machine)?;
        Ok(machine)
    }
    pub fn mark_install_complete(&self, id: &str) -> Result<()> {
        let mut machine = self.machine(id)?;
        if machine.iso_path.is_none() {
            return Err("VM has no installer ISO".into());
        }
        machine.install_complete = true;
        self.save_machine(&machine)
    }
    pub fn delete_machine(&self, id: &str) -> Result<()> {
        self.machine(id)?;
        let _lease = self.acquire(id, true)?;
        let directory = self.disk(id)?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if !matches!(
                entry.file_name().to_str(),
                Some("rootfs" | "machine.json" | "qemu.log")
            ) {
                return Err("VM environment has unfinished host artifacts; inspect gateway logs before deleting".into());
            }
        }
        let deleted = self.directory.join(format!(".deleted-{id}"));
        fs::rename(&directory, &deleted)?;
        File::open(&self.directory)?.sync_all()?;
        fs::remove_file(deleted.join("rootfs"))?;
        fs::remove_file(deleted.join("machine.json"))?;
        match fs::remove_file(deleted.join("qemu.log")) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        fs::remove_dir(&deleted)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
