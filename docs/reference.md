# CLI and configuration reference

## Gateway CLI

The gateway executable is installed at `/usr/local/bin/automantle-gateway`. Run `automantle-gateway --help` for the complete option list. These commands cover the main operator tasks:

| Command | Purpose |
| --- | --- |
| `automantle-gateway doctor` | Check Cloud Hypervisor v53.0, KVM, systemd, cgroup v2, and Landlock. |
| `automantle-gateway tls init-ca --directory /var/lib/automantle/tls` | Create the local inspection CA; run as `automantle`. |
| `automantle-gateway version` | Print the gateway version. |
| `automantle-gateway list` | List gateway VM runs. |
| `automantle-gateway logs RUN_ID` | Read a run's recent console output. |
| `automantle-gateway terminal RUN_ID` | Attach to its serial console; Ctrl+] detaches. |
| `automantle-gateway stop-vm RUN_ID` | Stop one run. |

The installed systemd unit starts the gateway as the `automantle` user with `/etc/automantle/gateway.json` and the `automantle-control` group. The gateway configuration contains a loopback `backendUrl` such as `http://127.0.0.1:8082` and must remain owned by the gateway service user with mode `0600`.

Advanced CLI flows include `create-disk`, `list-disks`, and `launch` with a kernel, an image or saved disk, and a required agent profile UUID. Direct image launches default to a read-only root. A saved disk can use `--storage-mode prepare` for persistent changes or `runtime` for a private copy discarded after the run. `launch` defaults to disabled networking; use `--network proxy` for inspected traffic. `--mode setup` requires proxy networking. The full current syntax is printed by `automantle-gateway --help`.

Gateway `start` options include `--default-kernel`, `--default-rootfs`, `--disk-directory`, and `--tls-ca-config`. The dashboard VM defaults are `/var/lib/automantle/kernel`, `/var/lib/automantle/linux.ext4`, `/var/lib/automantle/vms`, and `/var/lib/automantle/tls/tls.json`. To change them for the installed service, edit the systemd unit's `ExecStart` or add a systemd drop-in, then reload systemd and restart the gateway. Preserve the service's unprivileged user and socket group configuration.

## API configuration

The API reads an optional `../.env` file relative to its `api/` working directory. It also accepts ordinary environment variables. `.env.example` has the minimal sample values.

| Variable | Default | Use |
| --- | --- | --- |
| `PORT` | `8082` | API and dashboard loopback port. Keep `/etc/automantle/gateway.json` in sync if changed. |
| `AUTOMANTLE_DATA_DIR` | `~/.local/share/automantle` for the Java process user | Directory for `automantle.sqlite`. |
| `JPA_DDL_AUTO` | `update` | Hibernate schema setting. |
| `SESSION_TIMEOUT` | `15m` | Browser session timeout. |
| `FRONTEND_URL` | `http://localhost:${PORT}` | Allowed loopback frontend origin. |
| `REQUIRE_HTTPS` | `false` | Require an HTTPS frontend URL and secure session cookie. |
| `HTTP_POLICY_MAX_BODY_SIZE` | `8MB` | Maximum HTTP body size accepted by policy metadata. |
| `HTTP_POLICY_MAX_PREVIEW_SIZE` | `16KB` | Maximum preview size. |

The API binds to `127.0.0.1` regardless of `PORT`. Its gateway control socket defaults to `/run/automantle-gateway/control.sock`.

## Local management API

The dashboard uses these local endpoints. This is a host management interface, not a public cloud API. Browser requests that change state use a CSRF token from `GET /csrf` in the `X-CSRF-TOKEN` header; the browser also sends its session cookie. The gateway's `/gateway/**` endpoints are reserved for local native-process requests.

| Resource | Main endpoints |
| --- | --- |
| Profiles | `GET, POST /agents/profiles`; `GET, PATCH, DELETE /agents/profiles/{profileId}` |
| Rules | `GET, POST /agents/profiles/{profileId}/rules`; `GET, PATCH, DELETE /agents/profiles/{profileId}/rules/{ruleId}` |
| Setup | `POST /agents/profiles/{profileId}/setup/finish` |
| VMs | `GET, POST /vms`; `PUT, DELETE /vms/{id}`; `POST /vms/{id}/start`, `/stop`, `/force-stop`, `/copy` |
| Terminal | `GET /vms/{runId}/terminal`; `POST /vms/{runId}/terminal/input`, `/terminal/external` |
| Credentials | `GET, POST /credentials`; `PUT, DELETE /credentials/{name}` |
| Approvals | `GET /approval-requests`; `GET /approval-requests/{id}`; `POST /approval-requests/{id}/resolve` |
| History | `GET, DELETE /request-history` |

For a rule payload and match behavior, see [Agent profiles and policies](policies.md#rule-fields). For the supported credential fields, use the dashboard described in [Credentials](credentials.md).
