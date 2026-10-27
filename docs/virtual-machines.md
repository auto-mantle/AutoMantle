# Virtual machines

Use the **Virtual Machines** tab to create, start, stop, copy, and delete VMs. A VM has a name, an agent profile, memory in MiB, a CPU count, and a Setup Mode setting. The dashboard defaults to 2048 MiB and 2 CPUs. Accepted ranges are 128–65536 MiB and 1–64 CPUs.

## Create and run

1. Start AutoMantle from the compiled Linux release as described in [Getting started](getting-started.md).
2. Create an [agent profile](policies.md) with outbound rules.
3. Create a VM with that profile and select **Start**.
4. Open the VM terminal and run your workload.

The VM's Linux files persist between clean dashboard runs. **Stop** asks the guest to shut down; **Force stop** is available if it does not. Unflushed guest writes can be lost on a forced stop. Copying creates an independent VM and disk. The gateway allows up to four concurrent runs. Run states and console tails are in gateway memory and are not a durable record of task success.

## Guest preparation

The compiled release includes a bootable kernel and ext4 guest image. Its maintainer must prepare that image with Linux, a serial console, the desired agent tools, and any provider login needed by the workload. The release builder installs and enables the guest-side `automantle-vsock-proxy` service. Workloads must use `http://127.0.0.1:3128` for HTTP and HTTPS proxy traffic. The VM has no network card.

For inspected HTTPS, create a local AutoMantle CA under the user's private data directory, then put only its public `ca.pem` in the guest trust store before packaging the image. The private key stays on the host. An image without that trust cannot use inspected HTTPS successfully.

Advanced users can use `automantle-gateway` to launch an image directly or manage saved disks; see [CLI and configuration](reference.md#gateway-cli).
