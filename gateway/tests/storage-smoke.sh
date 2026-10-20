#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID != 0 || $# != 4 ]]; then
    echo 'Usage: sudo bash tests/storage-smoke.sh BINARY KERNEL RAW_EXT4_ROOTFS HYPERVISOR' >&2
    exit 2
fi
cd "$(dirname "$0")/.."
binary=$(realpath "$1")
kernel=$(realpath "$2")
rootfs=$(realpath "$3")
hypervisor=$(realpath "$4")
fixture=$(mktemp -d /run/automantle-storage-smoke.XXXXXXXX)
socket=$fixture/control.sock
gateway_pid=
backend_pid=
run_ids=()
profile_a=10000000-0000-0000-0000-000000000001
profile_b=10000000-0000-0000-0000-000000000002
cleanup() {
    if [[ -n $gateway_pid ]]; then
        "$binary" stop --socket "$socket" >/dev/null 2>&1 || true
        kill "$gateway_pid" 2>/dev/null || true
        wait "$gateway_pid" 2>/dev/null || true
    fi
    if [[ -n $backend_pid ]]; then
        kill "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
    for id in "${run_ids[@]}"; do
        local pid
        pid=$(systemctl show "$id" --property=MainPID --value)
        if [[ $pid =~ ^[0-9]+$ && $pid != 0 ]]; then
            echo "Preserving files for active VMM $id: $fixture" >&2
            return
        fi
    done
    if mountpoint -q "$fixture" || findmnt -rn -o SOURCE | grep -Fq "$(basename "$fixture")"; then
        echo "Preserving mounted test files: $fixture" >&2
        return
    fi
    case "$fixture" in /run/automantle-storage-smoke.*) rm -rf -- "$fixture";; esac
}
trap cleanup EXIT
report_failure() {
    local status=$? logfile
    trap - ERR
    for logfile in "$fixture"/*.log; do
        echo "Test log: $logfile" >&2
        if [[ $logfile == *automantle-vm-* ]]; then
            json_field console <"$logfile" | tail -n 45 >&2 || true
        else
            tail -n 45 "$logfile" >&2 || true
        fi
    done
    exit "$status"
}
trap report_failure ERR
python3 - "$fixture" "$profile_a" "$profile_b" <<'PY' &
import http.server, json, pathlib, sys
directory = pathlib.Path(sys.argv[1])
profiles = set(sys.argv[2:])
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        profile = self.path.removeprefix('/gateway/agent-profiles/')
        body = {'status':'ready'} if self.path == '/gateway/health' else {'id':profile}
        code = 200 if self.path == '/gateway/health' or profile in profiles else 404
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
config = directory / 'gateway.json'
config.write_text(json.dumps({'backendUrl':f'http://127.0.0.1:{server.server_port}'}))
config.chmod(0o600)
server.serve_forever()
PY
backend_pid=$!
for _ in $(seq 1 100); do [[ -f $fixture/gateway.json ]] && break; sleep 0.1; done
"$binary" start --gateway-config "$fixture/gateway.json" --cloud-hypervisor "$hypervisor" \
    --disk-directory "$fixture/disks" --socket "$socket" >"$fixture/gateway.log" 2>&1 &
gateway_pid=$!
gw() { "$binary" "$@" --socket "$socket"; }
json_field() {
    python3 -c 'import json,sys; value=json.load(sys.stdin); field=sys.argv[1]; value=next(item for item in value if item["id"] == sys.argv[2]) if field == "state" else value; print(value[0]["name"] if field == "disk" else value[field])' "$@"
}
for _ in $(seq 1 100); do gw list >/dev/null 2>&1 && break; sleep 0.1; done
gw list >/dev/null
source_hash=$(sha256sum "$rootfs")
cp --reflink=auto --sparse=always "$rootfs" "$fixture/source.ext4"
debugfs -w -R 'mkdir /mnt' "$fixture/source.ext4" >/dev/null 2>&1 || true
debugfs -w -R 'write tests/storage-guest-init.sh /storage-test-init' "$fixture/source.ext4" >/dev/null 2>&1
debugfs -w -R 'set_inode_field /storage-test-init mode 0100755' "$fixture/source.ext4" >/dev/null 2>&1
truncate -s 16M "$fixture/scratch.ext4"
mkfs.ext4 -q -F "$fixture/scratch.ext4"
gw create-disk --name harness --rootfs "$fixture/source.ext4" >/dev/null
cmdline='console=ttyS0 root=/dev/vda rootfstype=ext4 rw reboot=k panic=1 init=/storage-test-init'
launch() {
    launched=$(gw launch --kernel "$kernel" --saved-disk harness --agent-profile-id "$1" \
        --storage-mode "$2" --scratch-template "$fixture/scratch.ext4" --timeout-seconds 90 \
        --cmdline "$cmdline storage_test=$3" | json_field id)
    run_ids+=("$launched")
}
wait_finished() {
    local id=$1 state
    for _ in $(seq 1 900); do
        state=$(gw list | json_field state "$id")
        if [[ $state == stopped || $state == failed ]]; then
            gw logs "$id" >"$fixture/$id.log"
            [[ $state == stopped ]]
            json_field console <"$fixture/$id.log" | grep -q '^STORAGE_OK'
            ! grep -q STORAGE_FAILED "$fixture/$id.log"
            [[ ! -e /run/$id && ! -e $fixture/disks/harness/$id.runtime ]]
            [[ $(systemctl show "$id" --property=MainPID --value) == 0 ]]
            return
        fi
        sleep 0.1
    done
    return 1
}
launch "$profile_a" prepare prepare
wait_finished "$launched"
echo 'PASS: writable preparation saves installation/login, then cleans its VM'
saved_hash=$(sha256sum "$fixture/disks/harness/rootfs")
launch "$profile_b" runtime runtime
wait_finished "$launched"
[[ $(sha256sum "$fixture/disks/harness/rootfs") == "$saved_hash" ]]
echo 'PASS: another profile reuses installation; writable task changes do not alter it'
launch "$profile_b" runtime terminal
shell_vm=$launched
for _ in $(seq 1 300); do gw logs "$shell_vm" | json_field console | grep -q '^STORAGE_OK' && break; sleep 0.1; done
printf 'echo VM_SHELL_CONNECTED; exit\r' | gw terminal "$shell_vm" >"$fixture/terminal.log"
wait_finished "$shell_vm"
grep -q VM_SHELL_CONNECTED "$fixture/terminal.log"
[[ $(sha256sum "$fixture/disks/harness/rootfs") == "$saved_hash" ]]
echo 'PASS: interactive terminal sends a shell command and receives guest output'
launch "$profile_a" runtime hang
active=$launched
for _ in $(seq 1 300); do gw logs "$active" | json_field console | grep -q '^STORAGE_OK' && break; sleep 0.1; done
gw logs "$active" | json_field console | grep -q '^STORAGE_OK'
if gw launch --kernel "$kernel" --saved-disk harness --agent-profile-id "$profile_a" \
    --storage-mode prepare >"$fixture/busy.log" 2>&1; then exit 1; fi
grep -q busy "$fixture/busy.log"
launch "$profile_b" runtime verify
wait_finished "$launched"
gw stop-vm "$active" >/dev/null
wait_finished "$active"
[[ $(sha256sum "$fixture/disks/harness/rootfs") == "$saved_hash" ]]
echo 'PASS: concurrent runtime isolation, exclusive preparation lock, stop cleanup'
gw stop >/dev/null
wait "$gateway_pid"
gateway_pid=
"$binary" start --gateway-config "$fixture/gateway.json" --cloud-hypervisor "$hypervisor" \
    --disk-directory "$fixture/disks" --socket "$socket" >"$fixture/restarted.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 100); do gw list >/dev/null 2>&1 && break; sleep 0.1; done
[[ $(gw list-disks | json_field disk) == harness ]]
launch "$profile_a" runtime verify
wait_finished "$launched"
[[ $(sha256sum "$rootfs") == "$source_hash" ]]
echo 'PASS: saved installation survives gateway restart; original image unchanged'
