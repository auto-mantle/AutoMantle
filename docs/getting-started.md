# Getting started

This guide takes you from the source repository to a local dashboard and a first VM. Commands in this page run on the **Linux host** unless stated otherwise.

## Prerequisites

- x86_64 Linux with systemd, cgroup v2 (`cpu`, `memory`, and `pids` controllers), Landlock, and usable `/dev/kvm`.
- Rust 1.88 or newer and Cargo to build the gateway; Java 25 to run the API. The API includes Maven wrapper scripts.
- `curl` and `sha256sum`. The installer can install `iproute2` and `nftables` using `apt-get` if they are missing, so use a host where that package manager is available or install those tools yourself.
- A **bootable guest kernel** and a **raw ext4 Linux filesystem image** compatible with Cloud Hypervisor and a serial console. The installer does **not** download or build these guest assets. The default paths are `/var/lib/automantle/kernel` and `/var/lib/automantle/linux.ext4`.
- A prepared guest image with your desired agent harness and provider login, if your workload needs them. For inspected HTTPS, also install the gateway's public CA into the guest trust store; see [HTTPS inspection](#enable-inspected-https).

The gateway installer downloads a pinned Cloud Hypervisor v53.0 executable, checks its SHA-256, and installs it locally. An internet connection is required for this step.

## Build and install the gateway

From the repository root on the Linux host:

```sh
cd gateway
cargo build --release --locked
sudo bash install-linux.sh "$(pwd)/target/release/automantle-gateway"
```

The build creates `automantle-gateway` and `automantle-helper` in the same directory. The installer checks KVM, creates the `automantle` service user and control group, installs the binaries and systemd units, and runs `automantle-gateway doctor`. It enables the helper socket and gateway service but leaves the gateway service stopped until the API is running.

Place your guest kernel and base filesystem at the default paths, owned and readable as required by the gateway service user. The installer creates `/var/lib/automantle` and `/var/lib/automantle/vms`, but it does not place either guest file there. If you use different paths, configure the gateway with `--default-kernel` and `--default-rootfs` when starting it; see [CLI and configuration](reference.md).

## Start the API and dashboard

From the repository root, start the API in a separate terminal:

```sh
cd api
./mvnw spring-boot:run
```

The API binds to `127.0.0.1:8082` by default. It reads the optional repository-root `.env` file and stores its SQLite database under the Java process user's `~/.local/share/automantle/` directory unless `AUTOMANTLE_DATA_DIR` is set. Keep the same process user and data directory across restarts.

Start the gateway after the API is listening:

```sh
sudo systemctl start automantle-gateway.service
systemctl status automantle-gateway.service
```

Open `http://localhost:8082` **on the host**. The management API accepts loopback requests for local hostnames; it is not configured as a public dashboard. If the API user was added to `automantle-control` during installation, log out and back in so the new group membership takes effect before using VM controls.

## Enable inspected HTTPS

The gateway can inspect HTTPS only when it has a local CA and the guest trusts its public certificate. Generate the CA as the `automantle` service user:

```sh
sudo -u automantle /usr/local/bin/automantle-gateway tls init-ca --directory /var/lib/automantle/tls
```

This creates `ca.pem` (public guest certificate), `ca-key.pem` (private signing key), and `tls.json` (host configuration). The gateway's default TLS configuration path is `/var/lib/automantle/tls/tls.json`. Install **only** `ca.pem` in the guest's trust store while preparing the image, then restart the gateway. Keep the private key on the host. Without this setup, HTTPS inspection is disabled and HTTPS connections through the proxy fail.

## First profile and VM

1. In **Agent Profiles**, create a profile for one workload, such as `code-reviewer-bot`.
2. Open the profile and add a narrow `ALLOW` rule for the destination, method, and path your harness needs. Unknown supported requests are denied in normal mode; see [policy rules](policies.md).
3. In **Virtual Machines**, create a VM, select the profile, choose memory and CPU count, and start it.
4. Open the VM terminal and configure or run the harness inside the prepared guest. Watch [Request History](approvals.md#request-history) to see decisions.

For interactive discovery of a harness's connections, enable **Setup Mode** on the VM. Unknown supported requests then prompt you in the dashboard. An approval in setup mode saves an exact rule to the profile. See [setup mode](policies.md#setup-mode).

If VM creation fails, first verify that the guest kernel and filesystem exist at the configured paths, then check `sudo journalctl -u automantle-gateway.service -n 100 --no-pager`. The [troubleshooting guide](operations.md#troubleshooting) has more checks.
