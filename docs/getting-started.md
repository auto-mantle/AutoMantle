# Getting started

## Host requirements

Use Ubuntu 24.04 x86_64 or compatible Linux with systemd, a working systemd user manager, and cgroup v2 `cpu`, `memory`, and `pids` controllers. Managed environments need read/write access to `/dev/kvm`, without a graphical desktop. Advanced Cloud Hypervisor launches also require Landlock and `/dev/vhost-vsock`. AutoMantle provisions the guest automatically and does not elevate itself.

## Start and stop the compiled release

Download the Linux release archive and its `.sha256` file from the project's GitHub Releases page and extract it in a directory you own. The archive contains Java, the API, gateway, QEMU, and Cloud Hypervisor v53.0. It includes the supported Ubuntu 24.04 guest image. No Java, Rust, Cargo, Maven, or compilation is needed on the user's host.

```sh
sha256sum -c automantle-linux-x86_64.tar.gz.sha256
tar -xzf automantle-linux-x86_64.tar.gz
./automantle-linux-x86_64/bin/automantle up
```

Open the URL printed by `up` in a browser on the same host. The default is `http://localhost:8082`. If that port is occupied, run `AUTOMANTLE_PORT=18082 ./automantle-linux-x86_64/bin/automantle up` instead.

When finished:

```sh
./automantle-linux-x86_64/bin/automantle down
```

`down` asks running guests to shut down, waits briefly, then force stops those that remain. It stops the gateway and API while keeping profiles, credentials, and saved VM disks. You can run `up` again later.

## First profile and VM

1. In **Agent Profiles**, create a profile for one workload.
2. Add narrow `ALLOW` rules for its required destination, method, and path. Unknown supported requests are denied in normal mode.
3. In **Virtual Machines**, select **Create environment**, name it, and choose that profile.
4. Wait for automatic setup, then select **Open terminal**. Review [Request History](approvals.md#request-history).

AutoMantle supplies the guest OS, configures its proxy and public CA trust, and opens a terminal as the guest `automantle` account without a password prompt. See [Virtual machines](virtual-machines.md#guest-preparation).

For diagnostics, use `./automantle-linux-x86_64/bin/automantle-gateway doctor --cloud-hypervisor ./automantle-linux-x86_64/bin/cloud-hypervisor` and [Operations](operations.md).
