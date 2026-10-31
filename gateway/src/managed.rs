//! The supported guest image and offline first-boot configuration.
use crate::{sandbox::Result, tls};
use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

pub const IMAGE_VERSION: &str = "ubuntu-24.04-20261017-v1";
pub const READY: &[u8] = b"AUTOMANTLE_GUEST_READY";

pub fn release_file(relative: &str) -> Result<PathBuf> {
    let executable = env::current_exe()?;
    let root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid release path")?;
    let path = root.join(relative);
    if !path.is_file() {
        return Err(format!("Release is missing {}", path.display()).into());
    }
    Ok(path)
}

pub fn base_image() -> Result<PathBuf> {
    release_file("share/guest/ubuntu.raw")
}

fn cloud_config(certificate: Option<String>) -> serde_json::Value {
    let mut config = json!({
        "users": [{"name":"automantle", "shell":"/bin/bash", "lock_passwd":true,
            "sudo":"ALL=(ALL) NOPASSWD:ALL", "groups":["sudo"]}],
        "disable_root":true, "ssh_pwauth":false, "manage_etc_hosts":true,
        "package_update":false, "package_upgrade":false,
        "growpart":{"mode":"auto", "devices":["/"], "ignore_growroot_disabled":false},
        "resize_rootfs":true,
        "write_files":[
            {"path":"/etc/environment", "content":"http_proxy=http://10.0.2.100:3128\nhttps_proxy=http://10.0.2.100:3128\nHTTP_PROXY=http://10.0.2.100:3128\nHTTPS_PROXY=http://10.0.2.100:3128\nno_proxy=localhost,127.0.0.1,::1\n"},
            {"path":"/etc/apt/apt.conf.d/90automantle", "content":"Acquire::http::Proxy \"http://10.0.2.100:3128\";\nAcquire::https::Proxy \"http://10.0.2.100:3128\";\n"},
            {"path":"/etc/systemd/system/serial-getty@ttyS0.service.d/automantle.conf", "content":"[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin automantle --noclear %I $TERM\n"},
            {"path":"/etc/systemd/system/automantle-ready.service", "content":"[Unit]\nDescription=AutoMantle guest readiness\nWants=cloud-final.service\nAfter=cloud-final.service network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/automantle-ready\nRemainAfterExit=yes\n[Install]\nWantedBy=cloud-init.target\n"},
            {"path":"/usr/local/sbin/automantle-ready", "permissions":"0755", "content":include_str!("../guest/automantle-ready.py")}
        ],
        "runcmd":[["sh","-ec", "systemctl daemon-reload; systemctl enable automantle-ready.service serial-getty@ttyS0.service; systemctl start --no-block automantle-ready.service; systemctl restart --no-block serial-getty@ttyS0.service"]]
    });
    if let Some(pem) = certificate {
        config["ca_certs"] = json!({"trusted":[pem]});
    }
    config
}

pub fn seed(runtime: &Path, id: &str, tls_config: &Path) -> Result<PathBuf> {
    seed_with_tool(
        runtime,
        id,
        tls_config,
        &release_file("bin/automantle-seed")?,
    )
}

fn seed_with_tool(runtime: &Path, id: &str, tls_config: &Path, tool: &Path) -> Result<PathBuf> {
    let certificate = if tls_config.is_file() {
        let config: serde_json::Value =
            serde_json::from_str(&tls::protected_read(tls_config, true)?)?;
        Some(tls::protected_read(
            Path::new(
                config["caCertificate"]
                    .as_str()
                    .ok_or("missing CA certificate")?,
            ),
            false,
        )?)
    } else {
        None
    };
    let directory = runtime.join("seed");
    fs::create_dir(&directory)?;
    fs::write(
        directory.join("user-data"),
        format!(
            "#cloud-config\n{}\n",
            serde_json::to_string_pretty(&cloud_config(certificate))?
        ),
    )?;
    fs::write(
        directory.join("meta-data"),
        serde_json::to_vec(&json!({"instance-id":id,"local-hostname":"automantle"}))?,
    )?;
    fs::write(
        directory.join("network-config"),
        serde_json::to_vec(
            &json!({"version":2,"ethernets":{"primary":{"match":{"macaddress":"52:54:00:12:34:56"},"dhcp4":true,"dhcp6":false}}}),
        )?,
    )?;
    let output = runtime.join("seed.iso");
    let status = Command::new(tool)
        .args(["-quiet", "-output"])
        .arg(&output)
        .args(["-volid", "cidata", "-joliet", "-rock"])
        .arg(&directory)
        .output()?;
    if !status.status.success() {
        return Err(format!(
            "Guest configuration failed: {}",
            String::from_utf8_lossy(&status.stderr)
        )
        .into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisioning_is_offline_and_contains_only_public_trust_material() {
        let config = cloud_config(Some("PUBLIC CERTIFICATE".into()));
        assert_eq!(config["package_update"], false);
        assert_eq!(config["users"][0]["lock_passwd"], true);
        assert_eq!(config["ca_certs"]["trusted"][0], "PUBLIC CERTIFICATE");
        assert!(config.get("packages").is_none());
        assert!(cloud_config(None).get("ca_certs").is_none());
    }

    #[test]
    #[ignore = "requires QEMU, genisoimage, qemu-img and the pinned guest image"]
    fn boots_managed_guest_without_an_installer() {
        let image = env::var("AUTOMANTLE_TEST_IMAGE").expect("AUTOMANTLE_TEST_IMAGE");
        let qemu = env::var("AUTOMANTLE_TEST_QEMU").unwrap_or("/usr/bin/qemu-system-x86_64".into());
        let tool = env::var("AUTOMANTLE_TEST_SEED_TOOL").unwrap_or("/usr/bin/genisoimage".into());
        let runtime = env::temp_dir().join(format!("automantle-boot-{}", std::process::id()));
        fs::create_dir(&runtime).unwrap();
        let seed = seed_with_tool(
            &runtime,
            "automantle-test",
            &runtime.join("no-tls"),
            Path::new(&tool),
        )
        .unwrap();
        let status = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../release/check-managed-guest.py"
            ))
            .args([qemu, image])
            .arg(seed)
            .arg(&runtime)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "Guest boot failed; diagnostics: {}",
            runtime.display()
        );
        fs::remove_dir_all(runtime).unwrap();
    }
}
