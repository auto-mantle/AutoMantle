# AutoMantle

AutoMantle runs agent workloads in local Linux VMs and applies profile rules to their outbound HTTP requests.

## Run a compiled Linux release

Download `automantle-linux-x86_64.tar.gz` and its `.sha256` file from the [latest GitHub Release](https://github.com/auto-mantle/AutoMantle/releases/latest). The archive contains the CLI, gateway, Java runtime and API, QEMU, and Cloud Hypervisor. It includes a pinned Ubuntu 24.04 guest image with automatic setup. Verify and extract it in a directory owned by your account, then run:

```sh
sha256sum -c automantle-linux-x86_64.tar.gz.sha256
tar -xzf automantle-linux-x86_64.tar.gz
./automantle-linux-x86_64/bin/automantle up
# Open http://localhost:8082
./automantle-linux-x86_64/bin/automantle down
```

Run these commands as your normal user, without `sudo`. `up` starts the API and gateway as systemd user services. `down` shuts down their VMs and stops both services. Data stays under `~/.local/share/automantle/` or `XDG_DATA_HOME/automantle/`.

The release targets Ubuntu 24.04 x86_64 or compatible Linux systems. Managed environments need a working systemd user manager with cgroup v2 and read/write access to `/dev/kvm`; a graphical desktop is not required. A host administrator may need to grant device access once. Advanced Cloud Hypervisor launches also need Landlock and `/dev/vhost-vsock` access. The guest OS and proxy are configured automatically.

Release users do not need to install Java, Rust, Cargo, or Maven.

If port 8082 is occupied, set `AUTOMANTLE_PORT` when running `up`, for example `AUTOMANTLE_PORT=18082 ./automantle-linux-x86_64/bin/automantle up`. Open the URL printed by the command.

A raw Git checkout is source code. See [Getting started](docs/getting-started.md) and [release building](docs/reference.md#building-a-release).

## Use it

1. In **Agent Profiles**, create a profile and add rules for the HTTP hosts, methods, and paths your workload needs. Requests without a matching rule are denied.
2. In **Virtual Machines**, select **Create environment**, enter a name and profile, and wait for automatic setup. Select **Open terminal** when it is ready.
3. Check **Request History** for decisions. To discover supported connections interactively, enable **Setup Mode** and review prompts in **Approvals**.

See the [full documentation](docs/index.md) for guest preparation, policies, credentials, and troubleshooting.
