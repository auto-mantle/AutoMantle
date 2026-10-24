# Operations and troubleshooting

AutoMantle's API and gateway run on the same Linux host. The API listens on loopback and uses a Unix socket for VM controls. The installed gateway and helper are systemd services.

## Service checks

```sh
sudo systemctl status automantle-helper.socket
sudo systemctl status automantle-gateway.service
sudo journalctl -u automantle-gateway.service -n 100 --no-pager
/usr/local/bin/automantle-gateway doctor
```

The installer enables the helper socket and gateway service but does not start the gateway service. Start the API first, then `sudo systemctl start automantle-gateway.service`. For an API started with `./mvnw spring-boot:run`, inspect its terminal for startup errors. The dashboard is at `http://localhost:8082` unless you changed `PORT`.

## Data and backups

The API stores `automantle.sqlite` in `AUTOMANTLE_DATA_DIR`, defaulting to the Java process user's `~/.local/share/automantle/`. The gateway stores saved VMs and its managed credential file under `/var/lib/automantle/vms/`. Its configuration is under `/etc/automantle/`, and an initialized inspection CA is under `/var/lib/automantle/tls/`.

For a consistent filesystem backup, stop VM runs and the gateway, then stop the API before copying these directories. Preserve file owners and permissions when restoring. Back up the SQLite directory as a unit, including any WAL sidecar files if present. Keep backups of credentials and the CA private key protected. Request history is capped at 10,000 records and retained for up to 30 days, so export any audit data you need for longer retention.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `doctor` fails | Confirm `/dev/kvm`, systemd, cgroup v2 controllers, Landlock, and the installed Cloud Hypervisor v53.0 binary. |
| Dashboard loads but VM controls fail | Check that the gateway service is running and the API process can access `/run/automantle-gateway/control.sock`. Re-login after joining `automantle-control`. |
| VM cannot start or create | Confirm the configured guest kernel and raw ext4 template exist and are readable by the gateway service user. Check gateway journal output. |
| HTTPS request is denied before policy evaluation | Initialize the gateway CA, install public `ca.pem` into the prepared guest trust store, and restart the gateway. Inspect Request History for the exact reason. |
| Request gets `No matching allow rule` | Check the VM's profile, method, exact host, and case-sensitive path. A `/prefix/*` rule does not match `/prefix`. |
| Request is pending | Open **Approvals**, verify the destination and payload details, then approve or reject it. The request can expire if the VM stops or waits too long. |
| Credential binding is denied | Check that the placeholder is in a supported request field and its profile, HTTPS host, path, and insertion location match the credential scope. The profile must also permit the request. |
| Private or special-use destination is blocked | The proxy does not forward to those destinations. Use a public destination supported by the gateway. |

The API's management interface is deliberately local. `FRONTEND_URL` must be a loopback HTTP(S) origin; configuring it with `docs.automantle.com` or another public hostname will not turn the dashboard into a public service. The documentation site can be public because it contains static guides rather than the management API.
