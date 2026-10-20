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
  sudo automantle-gateway tls init-ca --directory /var/lib/automantle/tls
  sudo automantle-gateway start --gateway-config PATH [--cloud-hypervisor PATH]
  sudo automantle-gateway create-disk --name NAME --rootfs PATH
  sudo automantle-gateway list-disks
  sudo automantle-gateway launch --kernel PATH --rootfs PATH --agent-profile-id UUID [options]
  sudo automantle-gateway launch --kernel PATH --saved-disk NAME --agent-profile-id UUID [options]
  sudo automantle-gateway list
  sudo automantle-gateway logs RUN_ID
  automantle-gateway terminal RUN_ID
  sudo automantle-gateway stop-vm RUN_ID
  sudo automantle-gateway stop
automantle-gateway version

Start keeps one gateway running until stopped. Launch commands use that gateway.
Each VM has its own Cloud Hypervisor process. Network is disabled by default.
Requires Linux, systemd, cgroup v2, Landlock, and Cloud Hypervisor v53.0.

Options:
  --control-group GROUP     Start only: trusted local app group allowed to manage this gateway
  --disk-directory PATH     Private VM environments, start only (default: /var/lib/automantle/vms)
  --default-kernel PATH     Host standard kernel for saved VMs, start only
  --default-rootfs PATH     Clean Linux template for new VMs, start only
  --tls-ca-config PATH      Start: default host HTTPS CA for saved VMs; launch: per-run CA
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
  --tls-ca-config PATH     Optional host CA configuration enabling inspected HTTPS
  --credentials-config PATH Host-only HTTPS header credential bindings
  --agent-profile-id UUID  Existing Agent Profile, mandatory for every VM
  --cmdline TEXT           Guest boot arguments (saved disks default to rw; other roots to ro)

Imported source images are never modified. Direct --rootfs runs have a read-only root.
Saved disks persist independently of VM runs. Preparation writes the saved installation;
runtime writes a private copy that is discarded on stop. Preparation needs exclusive disk access.
Use a clean shutdown inside the guest to flush its filesystem before ending preparation.
Console tail is available through logs RUN_ID; supervisor status goes to stderr.
Terminal attaches to the guest serial console; Ctrl+] detaches without stopping the VM.
Start runs in the foreground. Use another terminal for commands. Stop also stops its VMs.
Up to four VMs can run together. Run records and console tails are held in memory.
All manager commands accept --socket PATH (default: /run/automantle-gateway/control.sock).
A successful VM shutdown does NOT prove that the agent task succeeded.
HTTPS requires --tls-ca-config and a prepared guest image trusting the public CA.
Shared-host-folder, passthrough, and arbitrary VMM options are not exposed."
    );
}

pub(crate) fn options(args: &[String], allowed: &[&str]) -> Result<BTreeMap<String, String>> {
    if args.len() % 2 != 0 {
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
        if let Some(name) = &saved_disk {
            if !valid_disk_name(name) {
                return Err(
                    "saved disk names require 1-64 ASCII letters, digits, hyphens or underscores"
                        .into(),
                );
            }
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
        if agent_profile_id.len() != 36
            || !agent_profile_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
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

    pub fn vm_config(&self, directory: &Path, network: Option<&VmNetwork>) -> Value {
        let net = network.map_or_else(Vec::new, |network| {
            vec![json!({
                "tap": network.tap,
                "ip": null,
                "mask": null,
                "offload_tso": false,
                "offload_ufo": false,
                "offload_csum": false,
                "mac": network.guest_mac,
                "num_queues": 2,
            })]
        });
        let mut config = json!({
            "cpus": {"boot_vcpus": self.vcpus, "max_vcpus": self.vcpus},
            "memory": {"size": self.memory_mib * 1024 * 1024},
            "payload": {"kernel": directory.join("kernel"), "cmdline": self.cmdline},
            "disks": [
                {"path": directory.join("rootfs"), "readonly": self.saved_disk.is_none(), "image_type": "Raw"},
                {"path": directory.join("scratch"), "readonly": false, "image_type": "Raw"}
            ],
            "net": net, "fs": [], "devices": [],
            "serial": {"mode": "Socket", "socket": directory.join("serial.sock")},
            "console": {"mode": "Off"}, "landlock_enable": true,
        });
        if self.initramfs.is_some() {
            config["payload"]["initramfs"] = json!(directory.join("initramfs"));
        }
        if let Some(network) = network {
            config["landlock_rules"] = json!([{
                "path": format!("/sys/class/net/{}/tun_flags", network.tap), "access": "r"
            }]);
            config["payload"]["cmdline"] = json!(format!(
                "{} ip={}::{}:255.255.255.252::eth0:off automantle_proxy=http://{}:3128",
                self.cmdline, network.guest_ip, network.host_ip, network.host_ip
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

#[derive(Clone, Debug)]
pub struct VmNetwork {
    pub tap: String,
    pub host_ip: String,
    pub guest_ip: String,
    pub guest_mac: String,
    pub host_mac: String,
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
    Err("use Linux or WSL2 with /dev/kvm; native Windows is not supported".into())
}
#[cfg(not(target_os = "linux"))]
fn manager_cli(_: &[String]) -> Result<()> {
    doctor(Path::new(""))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<String> {
        let mut values = [
            vec!["--kernel", "/kernel", "--rootfs", "/rootfs"],
            extra.to_vec(),
        ]
        .concat()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
        if !extra.contains(&"--gateway-config") {
            values.extend(["--gateway-config".into(), "/config".into()]);
        }
        if !extra.contains(&"--agent-profile-id") {
            values.extend([
                "--agent-profile-id".into(),
                "10000000-0000-0000-0000-000000000001".into(),
            ]);
        }
        values
    }
    #[test]
    fn proxy_requires_backend_and_valid_fixed_profile() {
        let missing = vec![
            "--kernel",
            "/kernel",
            "--rootfs",
            "/rootfs",
            "--gateway-config",
            "/config",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert!(RunRequest::parse(&missing).is_err());
        assert!(!RunRequest::parse(&args(&[])).unwrap().proxy_network);
        assert!(
            RunRequest::parse(&args(&[
                "--network",
                "proxy",
                "--allow-hosts",
                "example.com"
            ]))
            .is_err()
        );
        assert!(
            RunRequest::parse(&args(&[
                "--network",
                "proxy",
                "--gateway-config",
                "/config",
                "--agent-profile-id",
                "invalid"
            ]))
            .is_err()
        );
        let request = RunRequest::parse(&args(&[
            "--network",
            "proxy",
            "--gateway-config",
            "/config",
            "--agent-profile-id",
            "10000000-0000-0000-0000-000000000001",
        ]))
        .unwrap();
        assert_eq!(request.gateway_config, PathBuf::from("/config"));
        assert_eq!(
            request.agent_profile_id,
            "10000000-0000-0000-0000-000000000001"
        );
    }
    #[test]
    fn credentials_require_proxy_tls_and_do_not_enter_guest_configuration() {
        assert!(
            RunRequest::parse(&args(&["--credentials-config", "/host/credentials.json"])).is_err()
        );
        let mut extra = vec![
            "--network",
            "proxy",
            "--gateway-config",
            "/host/backend.json",
            "--agent-profile-id",
            "10000000-0000-0000-0000-000000000001",
            "--credentials-config",
            "/host/credentials.json",
        ];
        assert!(RunRequest::parse(&args(&extra)).is_err());
        extra.extend(["--tls-ca-config", "/host/tls.json"]);
        let request = RunRequest::parse(&args(&extra)).unwrap();
        assert_eq!(
            request.credentials_config,
            Some(PathBuf::from("/host/credentials.json"))
        );
        let guest_config = request
            .vm_config(Path::new("/run/example"), None)
            .to_string();
        assert!(!guest_config.contains("credentials.json"));
        assert!(!guest_config.contains("backend.json"));
        assert!(!guest_config.contains("tls.json"));
    }
    #[test]
    fn network_has_receive_and_transmit_queues_for_cloud_hypervisor() {
        let request = RunRequest::parse(&args(&[])).unwrap();
        let network = VmNetwork {
            tap: "tap-test".into(),
            host_ip: "10.253.0.1".into(),
            guest_ip: "10.253.0.2".into(),
            host_mac: "02:00:00:00:00:01".into(),
            guest_mac: "02:00:00:00:00:02".into(),
        };
        let config = request.vm_config(Path::new("/run/example"), Some(&network));
        assert_eq!(config["net"][0]["num_queues"], 2);
        assert_eq!(config["net"][0]["tap"], "tap-test");
        assert!(config["net"][0].get("host_mac").is_none());
        assert_eq!(
            config["landlock_rules"],
            json!([{
                "path": "/sys/class/net/tap-test/tun_flags", "access": "r"
            }])
        );
        assert_eq!(config["landlock_enable"], true);
        assert_eq!(config["disks"][0]["readonly"], true);
    }
    #[test]
    fn rejects_invalid_limits_and_unknown_flags() {
        for extra in [
            vec!["--memory-mib", "127"],
            vec!["--vcpu-count", "0"],
            vec!["--timeout-seconds", "0"],
            vec!["--net", "tap0"],
            vec!["--jailer", "/bin/jailer"],
            vec!["--kernel", "/duplicate"],
        ] {
            assert!(RunRequest::parse(&args(&extra)).is_err());
        }
    }

    #[test]
    fn setup_is_explicit_host_configuration_and_requires_proxy_networking() {
        assert!(!RunRequest::parse(&args(&[])).unwrap().setup_mode);
        assert!(RunRequest::parse(&args(&["--mode", "setup"])).is_err());
        assert!(RunRequest::parse(&args(&["--mode", "allow-all"])).is_err());
        let request = RunRequest::parse(&args(&[
            "--mode",
            "setup",
            "--network",
            "proxy",
            "--gateway-config",
            "/etc/automantle/gateway.json",
            "--agent-profile-id",
            "10000000-0000-0000-0000-000000000001",
        ]))
        .unwrap();
        assert!(request.setup_mode);
        let config = request
            .vm_config(Path::new("/run/example"), None)
            .to_string();
        assert!(!config.contains("setupSessionId"));
        assert!(!config.contains("gateway.json"));
    }
    #[test]
    fn cannot_override_isolation_through_guest_arguments() {
        let request =
            RunRequest::parse(&args(&["--cmdline", "init=/bin/sh quoted=\"hello\""])).unwrap();
        let config = request.vm_config(Path::new("/run/example"), None);
        let roundtrip: Value =
            serde_json::from_slice(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(roundtrip["net"], json!([]));
        assert_eq!(roundtrip["disks"][0]["readonly"], true);
        assert_eq!(roundtrip["landlock_enable"], true);
        assert!(roundtrip.get("vsock").is_none());
        assert_eq!(roundtrip["payload"]["cmdline"], request.cmdline);
    }
    #[test]
    fn rejects_ambiguous_disk_options_and_missing_values() {
        assert!(
            RunRequest::parse(&args(&[
                "--scratch-template",
                "/disk",
                "--scratch-mib",
                "16"
            ]))
            .is_err()
        );
        assert!(RunRequest::parse(&args(&["--memory-mib"])).is_err());
    }

    #[test]
    fn initramfs_uses_only_the_private_copy() {
        let plain = RunRequest::parse(&args(&[])).unwrap();
        assert!(
            plain.vm_config(Path::new("/run/example"), None)["payload"]
                .get("initramfs")
                .is_none()
        );
        let request = RunRequest::parse(&args(&["--initramfs", "/source/initrd"])).unwrap();
        assert_eq!(
            request.vm_config(Path::new("/run/example"), None)["payload"]["initramfs"],
            "/run/example/initramfs"
        );
    }

    #[test]
    fn saved_disks_are_writable_and_storage_mode_is_independent_of_network_setup() {
        let mut values = args(&[]);
        let root = values.iter().position(|a| a == "--rootfs").unwrap();
        values.splice(root..root + 2, ["--saved-disk".into(), "harness".into()]);
        let runtime = RunRequest::parse(&values).unwrap();
        assert!(!runtime.preparation);
        assert!(!runtime.setup_mode);
        assert!(runtime.cmdline.contains(" rw "));
        assert_eq!(
            runtime.vm_config(Path::new("/run/test"), None)["disks"][0]["readonly"],
            false
        );
        values.extend(["--storage-mode".into(), "prepare".into()]);
        let preparation = RunRequest::parse(&values).unwrap();
        assert!(preparation.preparation);
        assert!(!preparation.setup_mode);
        assert_eq!(preparation.saved_disk.as_deref(), Some("harness"));
        let profile = values
            .iter()
            .position(|a| a == "--agent-profile-id")
            .unwrap();
        values.drain(profile..profile + 2);
        assert!(RunRequest::parse(&values).is_err());
    }

    #[test]
    fn rejects_ambiguous_storage_and_unsafe_disk_names() {
        for extra in [
            vec!["--saved-disk", "harness"],
            vec!["--storage-mode", "prepare"],
            vec!["--storage-mode", "unknown"],
        ] {
            assert!(RunRequest::parse(&args(&extra)).is_err());
        }
        for name in [
            "",
            ".",
            "..",
            "../other",
            "/root",
            "a/b",
            "a\\b",
            "space name",
        ] {
            assert!(!valid_disk_name(name));
        }
        assert!(!valid_disk_name(&"a".repeat(65)));
        assert!(valid_disk_name("antigravity_01-dev"));
    }
}
