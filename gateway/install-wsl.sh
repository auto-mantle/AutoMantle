#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID != 0 || $# != 1 ]]; then
    echo 'Usage: sudo bash install-wsl.sh /absolute/path/to/automantle-gateway' >&2
    exit 2
fi
if [[ $(uname -m) != x86_64 ]]; then
    echo 'This installer currently supports x86_64 only.' >&2
    exit 1
fi
if [[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo 'KVM is unavailable at /dev/kvm. Enable nested virtualization and KVM in the WSL host first.' >&2
    exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
    echo 'systemd must be enabled and running in WSL.' >&2
    exit 1
fi

gateway=$(realpath -- "$1")
if [[ ! -f $gateway || ! -x $gateway ]]; then
    echo 'The gateway binary must be an executable file.' >&2
    exit 1
fi
if ! "$gateway" version | grep -q '^automantle-gateway '; then
    echo 'The supplied file is not an Automantle Gateway binary.' >&2
    exit 1
fi

command -v curl >/dev/null || { echo 'Install curl first.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'Install coreutils first.' >&2; exit 1; }
if ! command -v ip >/dev/null || ! command -v nft >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 nftables
fi
getent group kvm >/dev/null || { echo 'The WSL host must provide a kvm group for /dev/kvm access.' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
url='https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v53.0/cloud-hypervisor-static'
expected='448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc'
curl --fail --location --silent --show-error --max-time 120 --output "$tmp/cloud-hypervisor" "$url"
actual=$(sha256sum "$tmp/cloud-hypervisor" | cut -d ' ' -f 1)
if [[ $actual != "$expected" ]]; then
    echo 'Cloud Hypervisor download checksum did not match the pinned v53.0 release.' >&2
    exit 1
fi
chmod 0755 "$tmp/cloud-hypervisor"
if [[ $($tmp/cloud-hypervisor --version) != 'cloud-hypervisor v53.0' ]]; then
    echo 'Downloaded Cloud Hypervisor version check failed.' >&2
    exit 1
fi

install -o root -g root -m 0755 "$tmp/cloud-hypervisor" /usr/local/bin/cloud-hypervisor
install -o root -g root -m 0755 "$gateway" /usr/local/bin/automantle-gateway
echo 'Installed Automantle Gateway and Cloud Hypervisor v53.0.'
echo 'KVM was already available and has not been changed. Checking gateway setup:'
/usr/local/bin/automantle-gateway doctor
