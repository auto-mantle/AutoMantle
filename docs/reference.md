# CLI and configuration reference

## Lifecycle CLI

| Command | Result |
| --- | --- |
| `automantle up` | Start the compiled API and gateway as systemd user services and wait until both are ready. |
| `automantle down` | Stop the gateway and its VMs, then the API; keep persistent data. |

Run as an ordinary Linux user. `AUTOMANTLE_PORT` selects the API loopback port for `up` (default `8082`). The CLI creates a private gateway configuration under the user's AutoMantle data directory and uses a private control socket at `$XDG_RUNTIME_DIR/automantle/control.sock`.

## Gateway CLI

The release also contains `bin/automantle-gateway` for diagnostics and advanced VM operations. Run `bin/automantle-gateway --help` for all options. Its commands include `doctor`, `list`, `logs RUN_ID`, `terminal RUN_ID`, `stop-vm RUN_ID`, `create-disk`, and `launch`. The CLI does not need a root helper. Direct image launches default to a read-only root; saved disks can run from a private copy or be modified in preparation mode. Networking defaults to disabled; proxy mode uses VSOCK and the guest's local proxy bridge.

The gateway configuration contains a loopback `backendUrl` such as `http://127.0.0.1:8082` and must be a mode `0600` file owned by the current user. Saved VM data and managed credentials live under `$XDG_DATA_HOME/automantle/vms/` or `~/.local/share/automantle/vms/`. Per-run files live under the same data tree; sockets live in `$XDG_RUNTIME_DIR/automantle/`.

## API configuration

| Variable | Default | Use |
| --- | --- | --- |
| `AUTOMANTLE_PORT` | `8082` | Port chosen by `automantle up`; the CLI passes it to the API as `PORT`. |
| `AUTOMANTLE_DATA_DIR` | User AutoMantle data directory | SQLite database location; set by the CLI for the API service. |
| `SESSION_TIMEOUT` | `15m` | Browser session timeout. |
| `FRONTEND_URL` | `http://localhost:${PORT}` | Allowed loopback frontend origin. |
| `REQUIRE_HTTPS` | `false` | Require an HTTPS frontend URL and secure session cookie. |
| `HTTP_POLICY_MAX_BODY_SIZE` | `8MB` | Maximum HTTP body size accepted by policy metadata. |

The API listens on `127.0.0.1`. Its gateway socket is supplied by the CLI. Browser state-changing requests use a CSRF token from `GET /csrf` in the `X-CSRF-TOKEN` header; `/gateway/**` is reserved for local native-process requests.

## Building a release

Maintainers build on Linux x86_64 with Rust 1.88+, a JDK 25, Maven wrapper dependencies, `cc`, and `debugfs`. Set `AUTOMANTLE_JAVA_HOME`, `AUTOMANTLE_CLOUD_HYPERVISOR`, `AUTOMANTLE_GUEST_KERNEL`, and `AUTOMANTLE_GUEST_IMAGE`, then run `bash release/build-linux.sh`. The guest image must be an offline ext4 Linux image with systemd and `/usr/local/bin`; the builder copies it and installs the guest VSOCK bridge and service. The script packages the compiled components under `dist/automantle-linux-x86_64.tar.gz` and records checksums. The image still needs the agent tools desired for the release and, for HTTPS inspection, the public CA in its trust store. Source-checkout users build these components themselves.
