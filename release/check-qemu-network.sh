#!/usr/bin/env bash
set -euo pipefail

# Packaging regression check; TCG tests device initialization without requiring KVM.
qemu=$(realpath "${1:?usage: check-qemu-network.sh QEMU}")
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
common=(-machine q35 -accel tcg -display none -S -monitor none
        -global "e1000e.romfile=$temporary/efi-e1000e.rom")

# Force a missing default ROM even on builders with system iPXE files installed.
status=0
timeout 3 "$qemu" "${common[@]}" \
    -nic 'user,model=e1000e,restrict=on' 2>"$temporary/before.log" || status=$?
cat "$temporary/before.log"
[[ $status == 1 ]]
grep -Fq 'failed to find romfile' "$temporary/before.log"

# The gateway explicitly disables the ROM while retaining its restricted network.
status=0
timeout 3 "$qemu" "${common[@]}" \
    -netdev 'user,id=proxy,restrict=on,guestfwd=tcp:10.0.2.100:3128-cmd:/bin/true' \
    -device 'e1000e,netdev=proxy,romfile=' \
    2>"$temporary/after.log" || status=$?
cat "$temporary/after.log"
[[ $status == 124 ]]
echo 'PASS: QEMU starts with restricted networking and no network boot ROM.'
