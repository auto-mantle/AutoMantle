use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn run_cli(arguments: impl Iterator<Item = String>) -> Result<()> {
    let args = arguments.collect::<Vec<_>>();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print_usage();
        return Ok(());
    }
    if args == ["version"] {
        println!("automantle-gateway {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("tls")
        && args.get(1).map(String::as_str) == Some("init-ca")
    {
        let values = options(&args[2..], &["--directory"])?;
        let directory = values.get("--directory").ok_or("--directory is required")?;
        return initialize_ca(Path::new(directory));
    }
    if args.first().map(String::as_str) == Some("doctor") {
        let options = options(&args[1..], &["--cloud-hypervisor"])?;
        return doctor(Path::new(
            options
                .get("--cloud-hypervisor")
                .map(String::as_str)
                .unwrap_or("/usr/local/bin/cloud-hypervisor"),
        ));
    }
    manager_cli(&args)
}

fn print_usage() {
    println!(
        "Usage:
  automantle-gateway doctor [--cloud-hypervisor PATH]
  automantle-gateway tls init-ca --directory ~/.local/share/automantle/tls
  automantle-gateway start --gateway-config PATH [--cloud-hypervisor PATH]
  automantle-gateway create-disk --name NAME --rootfs PATH
  automantle-gateway list-disks
  automantle-gateway launch --kernel PATH --rootfs PATH --agent-profile-id UUID [options]
  automantle-gateway launch --kernel PATH --saved-disk NAME --agent-profile-id UUID [options]
  automantle-gateway list
  automantle-gateway logs RUN_ID
  automantle-gateway terminal RUN_ID
  automantle-gateway stop-vm RUN_ID
  automantle-gateway stop
  automantle-gateway version

Start runs as your ordinary user; automantle up starts it with the API.
The gateway starts one Cloud Hypervisor user service per VM.
Each VM has its own Cloud Hypervisor process. Network is disabled by default.
Requires Linux, systemd, cgroup v2, Landlock, and Cloud Hypervisor v53.0.

Options:
  --disk-directory PATH     Private VM environments, start only (default: user AutoMantle data directory)
  --default-kernel PATH     Host standard kernel for saved VMs, start only
  --default-rootfs PATH     Clean Linux template for new VMs, start only
  --tls-ca-config PATH      Start: default host HTTPS CA; launch: per-run CA
  --saved-disk NAME         Use a saved installation instead of --rootfs
  --storage-mode MODE       runtime (private writable copy) or prepare (write saved disk)
  --initramfs PATH          Optional initrd with guest boot drivers
  --memory-mib NUMBER       Guest RAM (default: 512; minimum: 128)
  --vcpu-count NUMBER       Guest CPUs (default: 1; maximum: 64)
  --timeout-seconds NUMBER  Run lifetime (default: 300; maximum: 86400); 0 for persistent writable storage
  --scratch-template PATH  Copy a raw filesystem image as private /dev/vdb
  --scratch-mib NUMBER     Blank private disk size without a template (default: 64)
  --network MODE           disabled or proxy (default: disabled)
  --mode MODE              normal or setup (default: normal; setup requires proxy)
  --credentials-config PATH Host-only HTTPS header credential bindings
  --agent-profile-id UUID  Existing Agent Profile, mandatory for every VM
  --cmdline TEXT           Guest boot arguments (saved disks default to rw; other roots to ro)

Imported source images are never modified. Direct --rootfs runs have a read-only root.
Saved disks persist independently of VM runs. Preparation writes a private copy and commits it after a clean stop;
runtime writes a private copy that is discarded on stop. Preparation needs exclusive disk access.
Use a clean shutdown inside the guest to flush its filesystem before ending preparation.
Console tail is available through logs RUN_ID; supervisor status goes to stderr.
Terminal attaches to the guest serial console; Ctrl+] detaches without stopping the VM.
Start runs in the foreground. Use another terminal for commands. Stop also stops its VMs.
Up to four VMs can run together. Run records and console tails are held in memory.
All manager commands accept --socket PATH (default: $XDG_RUNTIME_DIR/automantle/control.sock).
A successful VM shutdown does NOT prove that the agent task succeeded.
HTTPS requires --tls-ca-config and a prepared guest image trusting the public CA.
Shared-host-folder, passthrough, and arbitrary VMM options are not exposed."
    );
}

pub(crate) fn options(args: &[String], allowed: &[&str]) -> Result<BTreeMap<String, String>> {
    if !args.len().is_multiple_of(2) {
        return Err("each option requires a value".into());
    }
    let mut result = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str()) {
            return Err(format!("unknown option {}", pair[0]).into());
        }
        if pair[1].is_empty() || pair[1].starts_with("--") {
            return Err(format!("missing value for {}", pair[0]).into());
        }
        if result.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!("duplicate option {}", pair[0]).into());
        }
    }
    Ok(result)
}

pub struct RunRequest {
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    pub rootfs: PathBuf,
    pub saved_disk: Option<String>,
    pub preparation: bool,
    pub hypervisor: PathBuf,
    pub scratch_template: Option<PathBuf>,
    pub scratch_mib: u64,
    pub memory_mib: u64,
    pub vcpus: u64,
    pub timeout: Duration,
    pub cmdline: String,
    pub gateway_config: PathBuf,
    pub tls_ca_config: Option<PathBuf>,
    pub credentials_config: Option<PathBuf>,
    pub managed_credentials: Option<PathBuf>,
    pub agent_profile_id: String,
    pub setup_mode: bool,
    pub proxy_network: bool,
}

impl RunRequest {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        let values = options(
            args,
            &[
                "--kernel",
                "--initramfs",
                "--rootfs",
                "--saved-disk",
                "--storage-mode",
                "--cloud-hypervisor",
                "--scratch-template",
                "--scratch-mib",
                "--memory-mib",
                "--vcpu-count",
                "--timeout-seconds",
                "--cmdline",
                "--gateway-config",
                "--tls-ca-config",
                "--credentials-config",
                "--agent-profile-id",
                "--network",
                "--mode",
            ],
        )?;
        let required = |key| -> Result<PathBuf> {
            values
                .get(key)
                .map(PathBuf::from)
                .ok_or_else(|| format!("{key} is required").into())
        };
        let number = |key, default: u64, min, max| -> Result<u64> {
            let value = values
                .get(key)
                .map(|s| s.parse::<u64>())
                .transpose()?
                .unwrap_or(default);
            if !(min..=max).contains(&value) {
                return Err(format!("{key} must be between {min} and {max}").into());
            }
            Ok(value)
        };
        if values.contains_key("--scratch-template") && values.contains_key("--scratch-mib") {
            return Err("choose --scratch-template or --scratch-mib, not both".into());
        }
        let saved_disk = values.get("--saved-disk").cloned();
        if values.contains_key("--rootfs") == saved_disk.is_some() {
            return Err("choose exactly one of --rootfs or --saved-disk".into());
        }
        if let Some(name) = &saved_disk
            && !valid_disk_name(name)
        {
            return Err(
                "saved disk names require 1-64 ASCII letters, digits, hyphens or underscores"
                    .into(),
            );
        }
        let storage_mode = values
            .get("--storage-mode")
            .map(String::as_str)
            .unwrap_or("runtime");
        if !matches!(storage_mode, "runtime" | "prepare")
            || (storage_mode == "prepare" && saved_disk.is_none())
        {
            return Err(
                "--storage-mode must be runtime or prepare; prepare requires --saved-disk".into(),
            );
        }
        let cmdline = values.get("--cmdline").cloned().unwrap_or_else(|| {
            format!(
                "console=ttyS0 root=/dev/vda {} reboot=k panic=1",
                if saved_disk.is_some() { "rw" } else { "ro" }
            )
        });
        if cmdline.len() > 2047 || cmdline.contains(['\0', '\n', '\r']) {
            return Err("invalid guest command line".into());
        }
        let network = values
            .get("--network")
            .map(String::as_str)
            .unwrap_or("disabled");
        if !matches!(network, "disabled" | "proxy") {
            return Err("--network must be disabled or proxy".into());
        }
        let mode = values.get("--mode").map(String::as_str).unwrap_or("normal");
        if !matches!(mode, "normal" | "setup") || (mode == "setup" && network != "proxy") {
            return Err("--mode must be normal or setup; setup requires --network proxy".into());
        }
        let gateway_config = values
            .get("--gateway-config")
            .map(PathBuf::from)
            .ok_or("every VM requires an Agent Profile; the running gateway supplies its connection config")?;
        let tls_ca_config = values.get("--tls-ca-config").map(PathBuf::from);
        let credentials_config = values.get("--credentials-config").map(PathBuf::from);
        if credentials_config.is_some() && tls_ca_config.is_none() {
            return Err("--credentials-config requires --tls-ca-config".into());
        }
        let agent_profile_id = values
            .get("--agent-profile-id")
            .cloned()
            .ok_or("every VM requires an Agent Profile; the running gateway supplies its connection config")?;
        if !valid_uuid(&agent_profile_id) {
            return Err("--agent-profile-id must be a UUID".into());
        }
        if network != "proxy" && tls_ca_config.is_some() {
            return Err("TLS options require --network proxy".into());
        }
        if values.get("--timeout-seconds").is_some_and(|v| v == "0") && storage_mode != "prepare" {
            return Err("Unlimited lifetime requires persistent writable storage".into());
        }
        Ok(Self {
            kernel: required("--kernel")?,
            initramfs: values.get("--initramfs").map(PathBuf::from),
            rootfs: values
                .get("--rootfs")
                .map(PathBuf::from)
                .unwrap_or_default(),
            saved_disk,
            preparation: storage_mode == "prepare",
            hypervisor: values
                .get("--cloud-hypervisor")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/usr/local/bin/cloud-hypervisor".into()),
            scratch_template: values.get("--scratch-template").map(PathBuf::from),
            scratch_mib: number("--scratch-mib", 64, 1, 1024)?,
            memory_mib: number("--memory-mib", 512, 128, 65536)?,
            vcpus: number("--vcpu-count", 1, 1, 64)?,
            timeout: Duration::from_secs(number("--timeout-seconds", 300, 0, 86400)?),
            cmdline,
            gateway_config,
            tls_ca_config,
            credentials_config,
            managed_credentials: None,
            agent_profile_id,
            setup_mode: mode == "setup",
            proxy_network: network == "proxy",
        })
    }

    pub fn vm_config_rootless(
        &self,
        runtime: &Path,
        disks: &Path,
        vsock_cid: Option<u32>,
    ) -> Value {
        let mut config = json!({
            "cpus": {"boot_vcpus": self.vcpus, "max_vcpus": self.vcpus},
            "memory": {"size": self.memory_mib * 1024 * 1024},
            "payload": {"kernel": disks.join("kernel"), "cmdline": self.cmdline},
            "disks": [
                {"path": disks.join("rootfs"), "readonly": self.saved_disk.is_none(), "image_type": "Raw"},
                {"path": disks.join("scratch"), "readonly": false, "image_type": "Raw"}
            ],
            "net": [], "fs": [], "devices": [],
            "serial": {"mode": "Socket", "socket": runtime.join("serial.sock")},
            "console": {"mode": "Off"}, "landlock_enable": true,
        });
        if self.initramfs.is_some() {
            config["payload"]["initramfs"] = json!(disks.join("initramfs"));
        }
        if let Some(cid) = vsock_cid {
            config["vsock"] = json!({
                "cid": cid,
                "socket": runtime.join("vsock")
            });
            config["payload"]["cmdline"] = json!(format!(
                "{} automantle_proxy=http://127.0.0.1:3128",
                self.cmdline
            ));
        }
        config
    }
}

pub(crate) fn valid_disk_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(target_os = "linux")]
fn initialize_ca(path: &Path) -> Result<()> {
    crate::tls::initialize(path)
}
#[cfg(not(target_os = "linux"))]
fn initialize_ca(_: &Path) -> Result<()> {
    Err("CA initialization requires Linux".into())
}

#[cfg(target_os = "linux")]
fn doctor(binary: &Path) -> Result<()> {
    crate::linux::doctor(binary)
}
#[cfg(target_os = "linux")]
fn manager_cli(args: &[String]) -> Result<()> {
    crate::manager::cli(args)
}
#[cfg(not(target_os = "linux"))]
fn doctor(_: &Path) -> Result<()> {
    Err("the gateway requires Linux with /dev/kvm".into())
}
#[cfg(not(target_os = "linux"))]
fn manager_cli(_: &[String]) -> Result<()> {
    doctor(Path::new(""))
}

#[cfg(test)]
mod tests {
    use super::{RunRequest, valid_uuid};

    #[test]
    fn profile_ids_have_exact_uuid_shape() {
        assert!(valid_uuid("12345678-1234-1234-1234-123456789abc"));
        assert!(valid_uuid("ABCDEF12-1234-1234-1234-123456789ABC"));
        assert!(!valid_uuid("12345678-1234-1234-1234-123456789ab"));
        assert!(!valid_uuid("12345678_1234-1234-1234-123456789abc"));
        assert!(!valid_uuid("12345678-1234-1234-1234-123456789abg"));
    }

    #[test]
    fn rootless_vm_has_no_network_card_and_only_explicit_vsock() {
        let arguments = [
            "--kernel",
            "/kernel",
            "--rootfs",
            "/rootfs",
            "--gateway-config",
            "/gateway.json",
            "--agent-profile-id",
            "12345678-1234-1234-1234-123456789abc",
        ];
        let parse = |extra: &[&str]| {
            RunRequest::parse(
                &arguments
                    .iter()
                    .chain(extra)
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let runtime = std::path::Path::new("/run/user/1000/automantle/vm");
        let disks = std::path::Path::new("/home/user/.local/share/automantle/runs/vm");
        let disabled = parse(&[]).vm_config_rootless(runtime, disks, None);
        assert_eq!(disabled["net"], serde_json::json!([]));
        assert!(disabled.get("vsock").is_none());
        let proxy = parse(&["--network", "proxy"]).vm_config_rootless(runtime, disks, Some(42));
        assert_eq!(proxy["net"], serde_json::json!([]));
        assert_eq!(proxy["vsock"]["cid"], 42);
        assert!(
            proxy["payload"]["cmdline"]
                .as_str()
                .unwrap()
                .contains("automantle_proxy=http://127.0.0.1:3128")
        );
    }
    #[test]
    fn launch_options_require_one_root_and_explicit_proxy_for_setup() {
        let base = [
            "--kernel",
            "/kernel",
            "--rootfs",
            "/rootfs",
            "--gateway-config",
            "/gateway.json",
            "--agent-profile-id",
            "12345678-1234-1234-1234-123456789abc",
        ];
        let args = |extra: &[&str]| {
            base.iter()
                .chain(extra)
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>()
        };

        assert!(RunRequest::parse(&args(&[])).is_ok());
        assert!(RunRequest::parse(&args(&["--saved-disk", "saved"])).is_err());
        assert!(RunRequest::parse(&args(&["--mode", "setup"])).is_err());
        assert!(RunRequest::parse(&args(&["--mode", "setup", "--network", "proxy"])).is_ok());
    }
}
