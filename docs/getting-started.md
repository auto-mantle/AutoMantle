# Getting started

## Host requirements

Use an x86_64 Linux host with systemd, a working systemd user manager, cgroup v2 `cpu`, `memory`, and `pids` controllers, Landlock, and Cloud Hypervisor-compatible KVM. Your normal account must be able to open `/dev/kvm` and `/dev/vhost-vsock` for reading and writing. If device permissions are missing, ask the host administrator to configure them; AutoMantle does not elevate itself.

## Start and stop the compiled release

Download the Linux release archive from the project's GitHub Releases page and extract it in a directory you own. The archive already contains the Java runtime, API, gateway, Cloud Hypervisor v53.0, guest kernel, and raw ext4 guest image. No Cargo, Maven, or compilation is needed on the user's host.

```sh
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
3. In **Virtual Machines**, create a VM with that profile and start it.
4. Open the VM terminal and run your workload. Review [Request History](approvals.md#request-history).

The release guest image must contain the tools and agent harness you intend to run. The release builder installs the guest-side VSOCK bridge; VM traffic reaches the host policy proxy through that bridge, with no VM network interface. A custom guest image must provide the same bridge and trust the public AutoMantle CA for inspected HTTPS. See [Virtual machines](virtual-machines.md#guest-preparation).

For diagnostics, use `./automantle-linux-x86_64/bin/automantle-gateway doctor --cloud-hypervisor ./automantle-linux-x86_64/bin/cloud-hypervisor` and [Operations](operations.md).
