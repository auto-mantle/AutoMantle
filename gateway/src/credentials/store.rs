use super::{Config, Credentials, Entry, GUEST_ID_PREFIX, Scope, valid_name};
use crate::sandbox::Result;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SaveCredential {
    pub name: String,
    pub secret: Option<String>,
    pub scopes: Option<Vec<Scope>>,
}
fn public_entry(entry: &Entry) -> serde_json::Value {
    serde_json::json!({"name":entry.placeholder,"scopes":entry.scopes})
}
impl crate::storage::Store {
    pub fn credential_path(&self) -> std::path::PathBuf {
        self.directory.join(".credentials.json")
    }
    fn credential_config(&self) -> Result<Config> {
        self.ensure()?;
        let raw = Credentials::managed_raw(&self.credential_path())?;
        if raw.is_empty() {
            return Ok(Config {
                credentials: Vec::new(),
                guest_bearer: Vec::new(),
            });
        }
        Credentials::parse(&raw)?;
        serde_json::from_str(&raw).map_err(|_| "credential store unavailable".into())
    }
    pub fn list_credentials(&self) -> Result<serde_json::Value> {
        let config = self.credential_config()?;
        Ok(serde_json::Value::Array(
            config.credentials.iter().map(public_entry).collect(),
        ))
    }
    fn write_credentials(&self, config: &Config) -> Result<()> {
        use std::{
            fs::{File, OpenOptions},
            io::Write,
            os::unix::fs::OpenOptionsExt,
        };
        let raw = serde_json::to_string(config).map_err(|_| "credential store unavailable")?;
        if raw.len() > 32 * 1024 {
            return Err("Credential store size limit reached".into());
        }
        Credentials::parse(&raw)?;
        let temporary = self
            .directory
            .join(format!(".{}.credentials", crate::linux::new_run_id()?));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(raw.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temporary, self.credential_path())?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.map_err(|_| "Could not save credential store".into())
    }
    pub(crate) fn save_credential(
        &self,
        value: SaveCredential,
        create: bool,
    ) -> Result<serde_json::Value> {
        if !valid_name(&value.name) || value.name.starts_with(GUEST_ID_PREFIX) {
            return Err("Use an uppercase variable name, digits and underscores; the internal VM credential prefix is reserved".into());
        }
        let mut config = self.credential_config()?;
        let position = config
            .credentials
            .iter()
            .position(|e| e.placeholder == value.name);
        if create && position.is_some() {
            return Err("A credential with this name already exists".into());
        }
        if !create && position.is_none() {
            return Err("Credential not found".into());
        }
        let secret = match value.secret.filter(|s| !s.is_empty()) {
            Some(secret) => secret,
            None => position
                .map(|i| config.credentials[i].secret.clone())
                .ok_or("Enter a secret value")?,
        };
        let scopes = value
            .scopes
            .or_else(|| position.map(|i| config.credentials[i].scopes.clone()))
            .unwrap_or_default();
        if scopes.len() > 100 || scopes.iter().any(|scope| !scope.valid()) {
            return Err("Invalid credential scope: specify a profile, exact host, paths and replacement location".into());
        }
        let entry = Entry {
            placeholder: value.name,
            secret,
            scopes,
        };
        let public = public_entry(&entry);
        match position {
            Some(i) => config.credentials[i] = entry,
            None => config.credentials.push(entry),
        }
        self.write_credentials(&config)?;
        Ok(public)
    }
    pub fn delete_credential(&self, name: &str) -> Result<serde_json::Value> {
        if !valid_name(name) {
            return Err("Invalid credential name".into());
        }
        let mut config = self.credential_config()?;
        let old = config.credentials.len();
        config.credentials.retain(|e| e.placeholder != name);
        if old == config.credentials.len() {
            return Err("Credential not found".into());
        }
        self.write_credentials(&config)?;
        Ok(serde_json::json!({"deleted":true}))
    }
}
