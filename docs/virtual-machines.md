# Virtual machines

Use the **Virtual Machines** tab to create, start, stop, copy, and delete VMs. A VM has a name, an agent profile, memory in MiB, a CPU count, and a Setup Mode setting. The dashboard defaults to 2048 MiB and 2 CPUs. Accepted ranges are 128–65536 MiB and 1–64 CPUs.

## Create and run

1. Start AutoMantle from the compiled Linux release as described in [Getting started](getting-started.md).
2. Create an [agent profile](policies.md) with outbound rules.
3. Select **Create VM**, browse this machine for your downloaded x86_64 Linux installer ISO (or enter its absolute local path), and choose the profile and resources. AutoMantle creates a private, sparse 32 GiB virtual disk.
4. Select **Install OS**. Complete installation in the VM window on this machine. The installer exits when the guest reboots.
5. Select **Installation finished — boot from disk**, then **Start** to use the installed OS.

The application starts before any ISO is selected. The ISO stays at its original path and is never uploaded or modified. Keep it there until installation finishes. **Boot installer again** returns to that ISO. VM windows require a local graphical desktop and KVM.

The VM's Linux files persist between clean dashboard runs. **Stop** asks the guest to shut down; **Force stop** is available if it does not. Unflushed guest writes can be lost on a forced stop. Copying creates an independent VM and disk. The gateway allows up to four concurrent runs. Run states and console tails are in gateway memory and are not a durable record of task success.

## Guest preparation

The release contains no guest OS. ISO VMs use bundled QEMU and a restricted user network. Set the guest's HTTP and HTTPS proxy to `http://10.0.2.100:3128`, including in the OS installer if it asks for a proxy. Only this explicit connection reaches the selected profile's private policy proxy; direct connections to the host and internet are disabled. Install your own tools and sign in to providers inside the guest.

For inspected HTTPS, create a local AutoMantle CA under the user's private data directory, then put only its public `ca.pem` in the guest trust store before packaging the image. The private key stays on the host. An image without that trust cannot use inspected HTTPS successfully.

Advanced users can use `automantle-gateway` to launch an image directly or manage saved disks; see [CLI and configuration](reference.md#gateway-cli).
