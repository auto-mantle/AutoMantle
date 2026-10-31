use crate::{
    linux,
    sandbox::{Result, valid_disk_name, valid_uuid},
    storage::Store,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
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
    #[serde(default)]
    pub managed_image: Option<String>,
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
        // Read old definitions without enabling the removed installer flow.
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(fields) = value.as_object_mut() {
            fields.remove("isoPath");
            fields.remove("installComplete");
        }
        let machine: Machine = serde_json::from_value(value)?;
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
        if settings.memory_mib < 1024 {
            return Err("Managed environments require at least 1024 MiB of memory".into());
        }
        let id = linux::new_run_id()?.replacen("automantle-vm-", "vm-", 1);
        self.create_cancellable(&id, base, cancel)?;
        let machine = Machine {
            id,
            settings,
            managed_image: Some(crate::managed::IMAGE_VERSION.into()),
        };
        let result = (|| -> Result<()> {
            let disk = OpenOptions::new()
                .write(true)
                .open(self.disk(&machine.id)?.join("rootfs"))?;
            if disk.metadata()?.len() < 32 * 1024 * 1024 * 1024 {
                disk.set_len(32 * 1024 * 1024 * 1024)?;
            }
            disk.sync_all()?;
            self.save_machine(&machine)
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(self.disk(&machine.id)?.join("rootfs"));
            let _ = fs::remove_dir(self.disk(&machine.id)?);
            return Err(error);
        }
        Ok(machine)
    }
    pub fn copy_machine(&self, id: &str, name: String, cancel: &AtomicBool) -> Result<Machine> {
        let source = self.machine(id)?;
        if source.managed_image.is_none() {
            return Err(
                "Legacy environments cannot be copied; create a managed environment".into(),
            );
        }
        let mut settings = source.settings;
        settings.name = name;
        settings.validate()?;
        let lease = self.acquire(id, true)?;
        let mut copy = self.create_machine(settings, &lease.path, cancel)?;
        copy.managed_image = source.managed_image;
        self.save_machine(&copy)?;
        Ok(copy)
    }
    pub fn update_machine(&self, id: &str, settings: Settings) -> Result<Machine> {
        let previous = self.machine(id)?;
        settings.validate()?;
        if previous.managed_image.is_some() && settings.memory_mib < 1024 {
            return Err("Managed environments require at least 1024 MiB of memory".into());
        }
        let _lease = self.acquire(id, true)?;
        let machine = Machine {
            id: id.to_owned(),
            settings,
            managed_image: previous.managed_image,
        };
        self.save_machine(&machine)?;
        Ok(machine)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn managed_creation_and_legacy_reading_preserve_disks() {
        let base = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".automantle-managed-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let source = base.join("base.raw");
        fs::write(&source, b"base image bytes").unwrap();
        let store = Store {
            directory: base.join("vms"),
        };
        let settings = Settings {
            name: "Managed".into(),
            agent_profile_id: "12345678-1234-4234-8234-123456789abc".into(),
            memory_mib: 2048,
            vcpu_count: 2,
            setup: false,
        };
        let vm = store
            .create_machine(settings.clone(), &source, &AtomicBool::new(false))
            .unwrap();
        let directory = store.disk(&vm.id).unwrap();
        assert_eq!(
            fs::metadata(directory.join("rootfs")).unwrap().len(),
            32 * 1024 * 1024 * 1024
        );
        assert_eq!(fs::read(&source).unwrap(), b"base image bytes");
        assert_eq!(
            store
                .update_machine(&vm.id, settings)
                .unwrap()
                .managed_image
                .as_deref(),
            Some(crate::managed::IMAGE_VERSION)
        );
        let mut metadata = serde_json::to_value(&vm).unwrap();
        metadata.as_object_mut().unwrap().remove("managedImage");
        metadata["isoPath"] = serde_json::json!("/old/installer.iso");
        metadata["installComplete"] = serde_json::json!(true);
        fs::write(
            directory.join("machine.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(store.machine(&vm.id).unwrap().managed_image.is_none());
        assert_eq!(store.machines().unwrap().len(), 1);
        assert!(
            store
                .copy_machine(&vm.id, "Copy".into(), &AtomicBool::new(false))
                .is_err()
        );
        let mut disk = File::open(directory.join("rootfs")).unwrap();
        let mut prefix = [0; 16];
        disk.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"base image bytes");
        fs::write(directory.join("qemu.log"), b"diagnostics").unwrap();
        store.delete_machine(&vm.id).unwrap();
        fs::remove_dir_all(base).unwrap();
    }
}
