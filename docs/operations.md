# Operations and troubleshooting

The API, gateway, and each Cloud Hypervisor VM run as systemd **user** services under the account that ran `automantle up`. There is no root helper or system service.

## Service checks

```sh
systemctl --user status automantle-api.service automantle-gateway.service
journalctl --user -u automantle-api.service -u automantle-gateway.service -n 100 --no-pager
./automantle-linux-x86_64/bin/automantle-gateway doctor --cloud-hypervisor ./automantle-linux-x86_64/bin/cloud-hypervisor
```

Start with `automantle up` and stop with `automantle down`. The gateway control socket is `$XDG_RUNTIME_DIR/automantle/control.sock`. VM units have names beginning with `automantle-vm-`; `down` stops any that remain after gateway shutdown.

## Data and backups

The API SQLite database, saved VM images, managed credentials, and optional inspection CA live under `$XDG_DATA_HOME/automantle/` or `~/.local/share/automantle/`. Stop AutoMantle before copying this directory for a consistent backup. Preserve ownership and file modes. Back up the SQLite directory with any WAL files. Protect credentials and the CA private key.

Preparation mode writes to a private run copy of a saved disk. A clean stop copies it back to the saved image. On abnormal termination, inspect the `rootfs.<run-id>.recovery` file in that disk's directory before retrying; the original saved image remains in place. Keep sufficient free space for the temporary copy.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `doctor` fails | Check access to `/dev/kvm` and `/dev/vhost-vsock`, systemd user manager, cgroup v2, Landlock, and bundled Cloud Hypervisor v53.0. Ask the host administrator to configure device permissions if needed. |
| Dashboard loads but VM controls fail | Check the gateway user service and its private control socket. The API and gateway must run as the same user. |
| VM does not boot | Check the guest kernel/image in the release, VM unit journal (`journalctl --user -u automantle-vm-...`), and guest serial console. |
| Guest cannot reach the proxy | Check that the guest VSOCK bridge service is installed and running, and that the workload uses `http://127.0.0.1:3128` as its HTTP/HTTPS proxy. |
| HTTPS fails | The guest must trust only the public AutoMantle CA certificate, and the gateway must have its private CA configuration. |
| Request has no matching allow rule | Check the VM's agent profile, exact host, method, and case-sensitive path. |

The management API listens on loopback only. `FRONTEND_URL` must be a loopback HTTP(S) origin; it does not turn the dashboard into a public service.
