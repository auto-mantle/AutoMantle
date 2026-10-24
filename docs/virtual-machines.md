# Virtual machines

Use the **Virtual Machines** tab to create, start, stop, copy, and delete VMs. A VM has a name, an agent profile, memory in MiB, a CPU count, and a Setup Mode setting. The dashboard defaults to 2048 MiB and 2 CPUs. Accepted ranges are 128–65536 MiB and 1–64 CPUs.

## Create and run

1. Prepare the guest kernel and raw ext4 Linux image described in [Getting started](getting-started.md#prerequisites).
2. Create an [agent profile](policies.md) with the outbound rules you want.
3. In **Virtual Machines**, select **Create VM**, enter its settings, and choose that profile.
4. Select **Start**. When the guest serial console is ready, choose **Open terminal** or **Open in external terminal**.

The VM's Linux files and installed tools are saved between dashboard runs. Stop a running VM with **Stop** to request a clean shutdown. **Force stop** is available if it cannot shut down cleanly; unflushed guest changes can be lost. You can edit or copy a VM while it is stopped. Copying creates an independent VM with its own files and settings. Deleting a VM removes its saved files.

The gateway allows up to four concurrent VM runs. VM run states and recent console output are kept in gateway memory, so they are not a durable record of task success. Use the workload's own output and [Request History](approvals.md#request-history) to inspect what happened.

## Guest preparation

AutoMantle does not provision a Linux distribution, install a harness, or authenticate the harness to a provider. The guest image must boot with a serial console and provide the tools you need. The gateway defaults to `/var/lib/automantle/kernel` and `/var/lib/automantle/linux.ext4` for dashboard VMs.

If your harness uses HTTPS through the inspection proxy, create the gateway CA and install its **public** `ca.pem` certificate into the guest's trust store before relying on HTTPS. See [Enable inspected HTTPS](getting-started.md#enable-inspected-https). Keep the private CA key on the host.

The gateway CLI also supports launching a VM directly from an image with a read-only root, creating saved disks, and using a temporary runtime copy of a saved disk. These are advanced flows distinct from dashboard VM management; see [CLI and configuration](reference.md#gateway-cli).
