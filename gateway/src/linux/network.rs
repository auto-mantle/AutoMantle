use super::{checked, command, run_suffix};
use crate::sandbox::{Result, VmNetwork};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
};

pub(crate) struct HostNetwork {
    pub(super) config: VmNetwork,
    table: String,
    vmm_user: String,
    active: bool,
    capture_tap: String,
    inspection_tap: String,
}

impl HostNetwork {
    pub(crate) fn create(id: &str, vmm_user: &str, gateway_user: &str) -> Result<Self> {
        if !Path::new("/usr/sbin/nft").is_file() {
            return Err("--network proxy requires nftables (/usr/sbin/nft)".into());
        }
        if !Path::new("/usr/sbin/tc").is_file() {
            return Err("--network proxy requires tc (/usr/sbin/tc)".into());
        }
        let suffix = run_suffix(id)?;
        let tap = format!("amt{}", &suffix[..10]);
        let table = format!("am_{}", &suffix[..16]);
        let mut random = [0_u8; 4];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let mut selected = None;
        for offset in 0..256_u16 {
            let third = random[0].wrapping_add(offset as u8);
            let fourth = random[1] & 0xfc;
            let subnet = format!("10.253.{third}.{fourth}/30");
            let used = command(
                Command::new("/usr/sbin/ip").args(["-4", "route", "show", "exact", &subnet]),
            )?;
            if used.status.success() && used.stdout.is_empty() {
                selected = Some((
                    subnet,
                    format!("10.253.{third}.{}", fourth + 1),
                    format!("10.253.{third}.{}", fourth + 2),
                ));
                break;
            }
        }
        let (_subnet, host_ip, guest_ip) = selected.ok_or("no free VM network subnet available")?;
        let guest_mac = format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            random[0],
            random[1],
            random[2],
            random[3],
            suffix.as_bytes()[0]
        );
        let mut host_bytes = [0_u8; 5];
        File::open("/dev/urandom")?.read_exact(&mut host_bytes)?;
        let host_mac = format!(
            "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            host_bytes[0], host_bytes[1], host_bytes[2], host_bytes[3], host_bytes[4]
        );
        let mut network = Self {
            config: VmNetwork {
                tap,
                host_ip,
                guest_ip,
                guest_mac,
                host_mac,
            },
            table,
            vmm_user: vmm_user.to_owned(),
            active: true,
            capture_tap: format!("amc{}", &suffix[..10]),
            inspection_tap: format!("ami{}", &suffix[..10]),
        };
        let tap_result = checked(Command::new("/usr/sbin/ip").args([
            "tuntap",
            "add",
            "dev",
            &network.config.tap,
            "mode",
            "tap",
            "user",
            vmm_user,
        ]));
        if let Err(error) = tap_result {
            let _ = network.remove();
            return Err(error);
        }
        let setup = (|| -> Result<()> {
            for name in [&network.capture_tap, &network.inspection_tap] {
                checked(Command::new("/usr/sbin/ip").args([
                    "tuntap",
                    "add",
                    "dev",
                    name,
                    "mode",
                    "tap",
                    "user",
                    gateway_user,
                ]))?;
                let ipv6 = format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6");
                if Path::new(&ipv6).exists() {
                    fs::write(ipv6, b"1")?;
                }
                checked(Command::new("/usr/sbin/ip").args(["link", "set", "dev", name, "up"]))?;
            }
            checked(Command::new("/usr/sbin/ip").args([
                "link",
                "set",
                "dev",
                &network.inspection_tap,
                "address",
                &network.config.host_mac,
            ]))?;
            checked(Command::new("/usr/sbin/ip").args([
                "address",
                "add",
                &format!("{}/30", network.config.host_ip),
                "dev",
                &network.inspection_tap,
            ]))?;
            let ipv6 = format!(
                "/proc/sys/net/ipv6/conf/{}/disable_ipv6",
                network.config.tap
            );
            if Path::new(&ipv6).exists() {
                fs::write(ipv6, b"1")?;
            }
            checked(Command::new("/usr/sbin/ip").args([
                "link",
                "set",
                "dev",
                &network.config.tap,
                "up",
            ]))?;
            network.install_firewall()?;
            checked(Command::new("/usr/sbin/tc").args([
                "qdisc",
                "add",
                "dev",
                &network.config.tap,
                "clsact",
            ]))?;
            checked(Command::new("/usr/sbin/tc").args([
                "filter",
                "add",
                "dev",
                &network.config.tap,
                "ingress",
                "protocol",
                "all",
                "pref",
                "1",
                "matchall",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                &network.capture_tap,
            ]))?;
            Ok(())
        })();
        if let Err(error) = setup {
            let _ = network.remove();
            return Err(error);
        }
        Ok(network)
    }

    pub(crate) fn config(&self) -> &VmNetwork {
        &self.config
    }

    pub(crate) fn detach(mut self) -> VmNetwork {
        self.active = false;
        self.config.clone()
    }

    pub(crate) fn remove_by_id(id: &str) -> Result<()> {
        let suffix = run_suffix(id)?;
        let mut network = Self {
            config: VmNetwork {
                tap: format!("amt{}", &suffix[..10]),
                host_ip: String::new(),
                guest_ip: String::new(),
                guest_mac: String::new(),
                host_mac: String::new(),
            },
            table: format!("am_{}", &suffix[..16]),
            vmm_user: String::new(),
            active: true,
            capture_tap: format!("amc{}", &suffix[..10]),
            inspection_tap: format!("ami{}", &suffix[..10]),
        };
        network.remove()
    }

    fn install_firewall(&self) -> Result<()> {
        let uid = checked(Command::new("/usr/bin/id").args(["-u", &self.vmm_user]))?;
        let uid = String::from_utf8(uid.stdout)?.trim().to_owned();
        let run = |args: &[&str]| -> Result<()> {
            checked(Command::new("/usr/sbin/nft").args(args)).map(|_| ())
        };
        run(&["add", "table", "inet", &self.table])?;
        let input = "{ type filter hook input priority -300; policy accept; }";
        let forward = "{ type filter hook forward priority -300; policy accept; }";
        let output = "{ type filter hook output priority -300; policy accept; }";
        run(&["add", "chain", "inet", &self.table, "input", input])?;
        run(&["add", "chain", "inet", &self.table, "forward", forward])?;
        run(&["add", "chain", "inet", &self.table, "output", output])?;
        for chain in ["input", "forward"] {
            run(&[
                "add",
                "rule",
                "inet",
                &self.table,
                chain,
                "iifname",
                &self.inspection_tap,
                "accept",
            ])?;
        }
        run(&[
            "add",
            "rule",
            "inet",
            &self.table,
            "input",
            "iifname",
            &self.config.tap,
            "drop",
        ])?;
        run(&[
            "add",
            "rule",
            "inet",
            &self.table,
            "forward",
            "iifname",
            &self.config.tap,
            "drop",
        ])?;
        run(&[
            "add",
            "rule",
            "inet",
            &self.table,
            "output",
            "meta",
            "skuid",
            &uid,
            "ip",
            "daddr",
            &self.config.host_ip,
            "tcp",
            "dport",
            "3128",
            "accept",
        ])?;
        run(&[
            "add",
            "rule",
            "inet",
            &self.table,
            "output",
            "meta",
            "skuid",
            &uid,
            "drop",
        ])?;
        for chain in ["input", "forward"] {
            run(&[
                "add",
                "rule",
                "inet",
                &self.table,
                chain,
                "iifname",
                &self.capture_tap,
                "drop",
            ])?;
        }
        Ok(())
    }

    pub(super) fn remove(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let mut errors = Vec::new();
        match command(Command::new("/usr/sbin/nft").args(["delete", "table", "inet", &self.table]))
        {
            Ok(table)
                if table.status.success()
                    || String::from_utf8_lossy(&table.stderr).contains("No such file") => {}
            Ok(table) => errors.push(format!(
                "firewall {}: {}",
                self.table,
                String::from_utf8_lossy(&table.stderr).trim()
            )),
            Err(error) => errors.push(format!("firewall {}: {error}", self.table)),
        }
        match command(Command::new("/usr/sbin/ip").args([
            "link",
            "delete",
            "dev",
            &self.config.tap,
        ])) {
            Ok(link)
                if link.status.success()
                    || String::from_utf8_lossy(&link.stderr).contains("Cannot find device") => {}
            Ok(link) => errors.push(format!(
                "network {}: {}",
                self.config.tap,
                String::from_utf8_lossy(&link.stderr).trim()
            )),
            Err(error) => errors.push(format!("network {}: {error}", self.config.tap)),
        }
        for name in [&self.capture_tap, &self.inspection_tap] {
            match command(Command::new("/usr/sbin/ip").args(["link", "delete", "dev", name])) {
                Ok(link)
                    if link.status.success()
                        || String::from_utf8_lossy(&link.stderr).contains("Cannot find device") => {
                }
                Ok(link) => errors.push(format!(
                    "policy interface {name}: {}",
                    String::from_utf8_lossy(&link.stderr).trim()
                )),
                Err(error) => errors.push(format!("policy interface {name}: {error}")),
            }
        }
        if errors.is_empty() {
            self.active = false;
        } else {
            return Err(format!("could not remove VM network state: {}", errors.join("; ")).into());
        }
        Ok(())
    }
}

impl Drop for HostNetwork {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            eprintln!("network cleanup failed: {error}");
        }
    }
}
