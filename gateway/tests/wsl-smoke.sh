#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID != 0 || $# -lt 4 || $# -gt 5 ]]; then
    echo 'Usage: sudo bash tests/wsl-smoke.sh KERNEL RAW_ROOTFS CLOUD_HYPERVISOR PROFILE_UUID [INITRAMFS]' >&2
    exit 2
fi
cd "$(dirname "$0")/.."
kernel=$(realpath "$1")
rootfs=$(realpath "$2")
hypervisor=$(realpath "$3")
binary=$(realpath target/wsl/debug/automantle-gateway)
command -v jq >/dev/null
"$binary" list >/dev/null # Gateway must already be running.
fixture=$(mktemp -d "$PWD/target/wsl-smoke.XXXXXXXX")
run_ids=()
cleanup() {
    for id in "${run_ids[@]}"; do "$binary" stop-vm "$id" >/dev/null 2>&1 || true; done
    case "$fixture" in "$PWD"/target/wsl-smoke.*) rm -rf -- "$fixture";; esac
}
trap cleanup EXIT
trap 'status=$?; trap - ERR; tail -n 70 "$fixture"/*.log >&2; exit "$status"' ERR
echo "Test artifacts: $fixture"
source_hash=$(sha256sum "$rootfs")
cp --reflink=auto --sparse=always "$rootfs" "$fixture/rootfs.ext4"
debugfs -w -R 'mkdir /mnt' "$fixture/rootfs.ext4"
debugfs -w -R "write tests/guest-init.sh /automantle-test-init" "$fixture/rootfs.ext4"
debugfs -w -R 'set_inode_field /automantle-test-init mode 0100755' "$fixture/rootfs.ext4"
truncate -s 16M "$fixture/scratch.ext4"
mkfs.ext4 -q -F "$fixture/scratch.ext4"
args=(launch --kernel "$kernel" --rootfs "$fixture/rootfs.ext4" --agent-profile-id "$4" --scratch-template "$fixture/scratch.ext4")
if [[ $# == 5 ]]; then args+=(--initramfs "$(realpath "$5")"); fi
cmdline='console=ttyS0 root=/dev/vda rootfstype=ext4 modules=virtio_pci,virtio_blk,ext4 ro reboot=k panic=1 init=/automantle-test-init'
verify_cleanup() {
    local id=$1
    [[ $id == automantle-vm-* && ! -e /run/$id && ! -L /run/$id && ! -e /run/private/$id ]]
    [[ $(systemctl show "$id" --property=MainPID --value) == 0 ]]
}
launch() {
    launched=$("$binary" "${args[@]}" "$@" | jq -er .id)
    run_ids+=("$launched")
}
wait_finished() {
    local id=$1 state
    for _ in $(seq 1 600); do
        state=$("$binary" list | jq -er --arg id "$id" '.[] | select(.id == $id) | .state')
        if [[ $state == stopped || $state == failed ]]; then return; fi
        sleep 0.1
    done
    echo "Run did not finish: $id" >&2; return 1
}
logs() { "$binary" logs "$1" | jq -r '.console, (.error // "")'; }
"$binary" doctor --cloud-hypervisor "$hypervisor"
launch --timeout-seconds 40 --cmdline "$cmdline"
normal=$launched
wait_finished "$normal"
logs "$normal" > "$fixture/normal.log"
grep -q '^AUTOMANTLE_TEST_OK' "$fixture/normal.log"
! grep -q 'AUTOMANTLE_TEST_FAILED' "$fixture/normal.log"
verify_cleanup "$normal"
echo 'PASS: VM boot/shutdown, no guest NIC, read-only root, writable private scratch, cleanup'
launch --timeout-seconds 8 --cmdline "$cmdline automantle_test=hang"
timeout=$launched
wait_finished "$timeout"
logs "$timeout" > "$fixture/timeout.log"
grep -q 'AUTOMANTLE_ISOLATION_OK' "$fixture/timeout.log"
grep -Eq 'timeout|timed out' "$fixture/timeout.log"
verify_cleanup "$timeout"
echo 'PASS: timeout terminates VM and cleans its files'
launch --timeout-seconds 40 --cmdline "$cmdline automantle_test=hang"
first=$launched
launch --timeout-seconds 40 --cmdline "$cmdline automantle_test=delay"
second=$launched
for _ in $(seq 1 100); do
    logs "$first" > "$fixture/cancel.log"
    logs "$second" > "$fixture/concurrent.log"
    if grep -q 'AUTOMANTLE_ISOLATION_OK' "$fixture/cancel.log" && grep -q 'AUTOMANTLE_ISOLATION_OK' "$fixture/concurrent.log"; then break; fi
    sleep 0.1
done
grep -q 'AUTOMANTLE_ISOLATION_OK' "$fixture/cancel.log"
"$binary" stop-vm "$first" >/dev/null
wait_finished "$first"
wait_finished "$second"
logs "$second" > "$fixture/concurrent.log"
grep -q '^AUTOMANTLE_TEST_OK' "$fixture/concurrent.log"
verify_cleanup "$first"
verify_cleanup "$second"
[[ $(sha256sum "$rootfs") == "$source_hash" ]]
echo 'PASS: cancellation, concurrent runs, independent cleanup, original image unchanged'
"$binary" list >/dev/null
echo 'PASS: gateway remains running; temporary test files are removed on exit'
