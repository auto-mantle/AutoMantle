# AutoMantle

AutoMantle runs agent workloads in local Linux VMs and applies profile rules to their outbound HTTP requests.

## Run a compiled Linux release

The release archive contains the CLI, gateway, Java runtime and API, Cloud Hypervisor, and a prepared guest kernel and image. Extract it in a directory owned by your account, then run:

```sh
tar -xzf automantle-linux-x86_64.tar.gz
./automantle-linux-x86_64/bin/automantle up
# Open http://localhost:8082
./automantle-linux-x86_64/bin/automantle down
```

Run these commands as your normal user, without `sudo`. `up` starts the API and gateway as systemd user services. `down` shuts down their VMs and stops both services. Data stays under `~/.local/share/automantle/` or `XDG_DATA_HOME/automantle/`.

The host needs Linux x86_64, a working systemd user manager with cgroup v2, Landlock, and read/write access to `/dev/kvm` and `/dev/vhost-vsock`. A host administrator may need to grant those device permissions once. AutoMantle does not ask for root privileges or install a root helper. Run `./automantle-linux-x86_64/bin/automantle-gateway doctor --cloud-hypervisor ./automantle-linux-x86_64/bin/cloud-hypervisor` to inspect prerequisites.

If port 8082 is occupied, set `AUTOMANTLE_PORT` when running `up`, for example `AUTOMANTLE_PORT=18082 ./automantle-linux-x86_64/bin/automantle up`. Open the URL printed by the command.

A raw Git checkout is source code. Its builder supplies a bootable guest image and compiles the release; the CLI does not build a checkout. See [Getting started](docs/getting-started.md) and [release building](docs/reference.md#building-a-release).

## Use it

1. In **Agent Profiles**, create a profile and add rules for the HTTP hosts, methods, and paths your workload needs. Requests without a matching rule are denied.
2. In **Virtual Machines**, create a VM with that profile, start it, and open its terminal to run your workload.
3. Check **Request History** for decisions. To discover supported connections interactively, enable **Setup Mode** and review prompts in **Approvals**.

See the [full documentation](docs/index.md) for guest preparation, policies, credentials, and troubleshooting.
