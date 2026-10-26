# AutoMantle

AutoMantle runs agent workloads in local Linux VMs and lets you control their outbound HTTP requests from a dashboard.

## Requirements

- An x86_64 Linux host with systemd, KVM (`/dev/kvm`), cgroup v2, and Landlock.
- Rust 1.88+ with Cargo, Java 25, `curl`, and `sha256sum`. Install `iproute2` and `nftables` first if your host does not use `apt-get`.
- A bootable guest kernel and raw ext4 Linux image with a serial console and your agent tools. AutoMantle does not create these guest files.

The installer downloads Cloud Hypervisor, so it needs internet access.

## Install and run

Run these commands on the Linux host, from the repository root:

```sh
cd gateway
cargo build --release --locked
sudo bash install-linux.sh "$(pwd)/target/release/automantle-gateway"
cd ..
```

Put your prepared guest files at the paths used by the dashboard:

```sh
sudo install -o automantle -g automantle -m 0644 /path/to/guest-kernel /var/lib/automantle/kernel
sudo install -o automantle -g automantle -m 0644 /path/to/guest.ext4 /var/lib/automantle/linux.ext4
```

For inspected HTTPS, create a local CA and install only its public `ca.pem` in the guest's trust store before using the VM:

```sh
sudo -u automantle /usr/local/bin/automantle-gateway tls init-ca --directory /var/lib/automantle/tls
```

Log out and back in to activate the `automantle-control` group added by the installer. Return to the repository root, then start the API in one terminal:

```sh
cd api
./mvnw spring-boot:run
```

Start the gateway in another terminal:

```sh
sudo systemctl start automantle-gateway.service
```

Open **http://localhost:8082** on the host. The API stores its SQLite database in `~/.local/share/automantle/` by default. To change the data directory, copy `.env.example` to `.env` in the repository root and set `AUTOMANTLE_DATA_DIR` before starting the API.

## Use it

1. In **Agent Profiles**, create a profile and add rules for the HTTP hosts, methods, and paths your workload needs. Requests without a matching rule are denied.
2. In **Virtual Machines**, create a VM with that profile, start it, and open its terminal to run your workload.
3. Check **Request History** for decisions. To discover needed connections interactively, enable **Setup Mode** on the VM and review prompts in **Approvals**.

See the [full documentation](docs/index.md) for guest preparation, policies, credentials, and troubleshooting.
