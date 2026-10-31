# Managed environments

AutoMantle supplies Ubuntu 24.04 and configures each environment automatically. There is no OS selector, installer window, user/password wizard, or manual network setup.

## Create and run

1. Start the compiled Linux release and create an agent profile with the rules your workload needs.
2. In **Virtual Machines**, select **Create environment** and choose a name, profile, memory, and CPU count. Defaults are 2048 MiB and 2 CPUs; managed environments require at least 1024 MiB.
3. AutoMantle copies the bundled OS into a private, sparse 32 GiB disk and starts it. **Preparing** covers the first-boot configuration and proxy connectivity check. **View setup log** shows guest progress.
4. Once running, select **Open terminal**. You are signed in automatically as the guest `automantle` account. Install tools and run your agent there.

The Linux host still needs KVM, systemd user services, and cgroup v2. A graphical desktop is not required. Each environment has its own disk, resource limits, and profile-controlled proxy. The guest account has sudo inside its VM; it grants no host privileges.

## Guest preparation

The release bundles a checksum-pinned official Ubuntu cloud image. A local cloud-init configuration disk creates the account, expands the filesystem, configures HTTP/HTTPS proxy settings and APT, and installs the public AutoMantle CA. Initial provisioning requires no external guest downloads. The CA private key and managed service credentials remain on the host.

Proxy configuration uses `http://10.0.2.100:3128`. Host-side restricted QEMU networking blocks direct external connections. Tools must use the proxy to make supported HTTP/HTTPS requests; installing packages still needs appropriate profile permissions. No agent-specific runtime is preinstalled beyond the Ubuntu base tools.

## Saved data and updates

Files and installed tools persist between runs. **Stop** asks the guest to shut down; **Force stop** may lose unflushed writes. **Copy** creates an independent environment with the same files, tools, and saved guest logins. On first boot of the copy, AutoMantle reapplies its managed configuration with a new instance identity.

Image updates in a new AutoMantle release apply to newly created environments. Existing disks are never silently replaced or upgraded. Update packages inside existing environments with permitted APT access, or create a fresh environment and migrate your workspace. Changing the host CA requires updating existing guests' trust or creating a new environment.

## Older VMs

VMs created with the removed custom installer feature remain listed as legacy environments. Their disk files are preserved; they are not automatically converted or started. Back up or export their files before deleting them. Create a managed environment for the supported workflow.

The advanced Cloud Hypervisor CLI remains available for developer diagnostics; it is separate from the managed environment UI.
