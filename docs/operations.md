# Operations and troubleshooting

The API, gateway, and each QEMU or Cloud Hypervisor VM run as systemd **user** services under the account that ran `automantle up`. There is no root helper or system service.

## Service checks

```sh
systemctl --user status automantle-api.service automantle-gateway.service
journalctl --user -u automantle-api.service -u automantle-gateway.service -n 100 --no-pager
./automantle-linux-x86_64/bin/automantle-gateway doctor --cloud-hypervisor ./automantle-linux-x86_64/bin/cloud-hypervisor
```

Start with `automantle up` and stop with `automantle down`. The gateway control socket is `$XDG_RUNTIME_DIR/automantle/control.sock`. VM units have names beginning with `automantle-vm-`; `down` stops any that remain after gateway shutdown.

For managed environment launches, QEMU output is saved as `qemu.log` beside that VM's `rootfs` disk. The error shown in the dashboard includes the log path. The log survives runtime cleanup and is replaced on the next launch of that VM; copy it before retrying if you need to keep it. Launch failures are also written to the gateway journal. An environment stays in `preparing` until guest provisioning finishes and its proxy responds. Use **View setup log** for guest startup output.

## Data and backups

The API SQLite database, saved VM images, managed credentials, and optional inspection CA live under `$XDG_DATA_HOME/automantle/` or `~/.local/share/automantle/`. Stop AutoMantle before copying this directory for a consistent backup. Preserve ownership and file modes. Back up the SQLite directory with any WAL files. Protect credentials and the CA private key.

Managed environments write to their own saved disk. Advanced Cloud Hypervisor preparation mode writes to a private run copy and commits it after a clean stop; on abnormal termination, inspect its `rootfs.<run-id>.recovery` file before retrying.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `doctor` fails | Check access to `/dev/kvm` and `/dev/vhost-vsock`, systemd user manager, cgroup v2, Landlock, and bundled Cloud Hypervisor v53.0. Ask the host administrator to configure device permissions if needed. |
| Dashboard loads but VM controls fail | Check the gateway user service and its private control socket. The API and gateway must run as the same user. |
| `Local backend rejected ... (HTTP ...)` | Check the status and endpoint in the error. A profile lookup returning 404 can mean a deleted profile; refresh Agent Profiles and edit the environment to select an existing one. For 403 or an endpoint missing despite an existing profile, check that the API and gateway use the same release. For 5xx, inspect the API journal. |
| VM does not boot | Check the guest files selected for that VM, VM unit journal (`journalctl --user -u automantle-vm-...`), and guest serial console. |
| Guest cannot reach the proxy | Managed guests are configured automatically to use `http://10.0.2.100:3128`. Advanced Cloud Hypervisor guests use their VSOCK bridge at `http://127.0.0.1:3128`. |
| HTTPS fails | The guest must trust only the public AutoMantle CA certificate, and the gateway must have its private CA configuration. |
| Installer reports HTTP 502 | Check **Request History** for the destination and reason: `DNS_FAILED`, `CONNECT_FAILED`, `UPSTREAM_TLS_FAILED`, or `RESPONSE_BLOCKED`. There is no fixed upload or download body-size cap. Credential-bearing responses are inspected before delivery; malformed responses and reflected credentials remain blocked. An upstream server can also return its own 502. |
| Request has no matching allow rule | Check the VM's agent profile, exact host, method, and case-sensitive path. |

The management API listens on loopback only. `FRONTEND_URL` must be a loopback HTTP(S) origin; it does not turn the dashboard into a public service.

Ordinary downloads stream directly. Uploads and credential-bearing responses use private, immediately unlinked temporary files in AutoMantle's data filesystem; these are released when the transfer ends, fails, or the process exits. Large transfers require available host disk space. JSON credential substitution still parses JSON in memory. HTTP framing validation, header and preview bounds, connection timeouts, and policy checks remain independent of transfer size. The former `HTTP_POLICY_MAX_BODY_SIZE` setting no longer applies.
