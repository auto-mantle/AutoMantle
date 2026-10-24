#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID != 0 || $# != 1 ]]; then
    echo 'Usage: sudo bash install-linux.sh /absolute/path/to/automantle-gateway' >&2
    exit 2
fi
if [[ $(uname -m) != x86_64 ]]; then
    echo 'This installer currently supports x86_64 only.' >&2
    exit 1
fi
if [[ ! -c /dev/kvm || ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo 'KVM is unavailable at /dev/kvm. Enable KVM on the Linux host first.' >&2
    exit 1
fi
if [[ ! -d /run/systemd/system ]]; then
    echo 'systemd must be running on the Linux host.' >&2
    exit 1
fi

gateway=$(realpath -- "$1")
if [[ ! -f $gateway || ! -x $gateway ]]; then
    echo 'The gateway binary must be an executable file.' >&2
    exit 1
fi
helper=$(dirname -- "$gateway")/automantle-helper
if [[ ! -f $helper || ! -x $helper ]]; then
    echo 'Build the automantle-helper binary alongside the gateway before installing.' >&2
    exit 1
fi
if ! "$gateway" version | grep -q '^automantle-gateway '; then
    echo 'The supplied file is not an Automantle Gateway binary.' >&2
    exit 1
fi
if ! "$helper" version | grep -q '^automantle-helper '; then
    echo 'The helper binary is not an Automantle Helper binary.' >&2
    exit 1
fi

command -v curl >/dev/null || { echo 'Install curl first.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'Install coreutils first.' >&2; exit 1; }
if ! command -v ip >/dev/null || ! command -v nft >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 nftables
fi
getent group kvm >/dev/null || { echo 'The Linux host must provide a kvm group for /dev/kvm access.' >&2; exit 1; }
getent group automantle >/dev/null || groupadd --system automantle
if ! getent passwd automantle >/dev/null; then
    useradd --system --no-create-home --home-dir /var/lib/automantle \
        --shell /usr/sbin/nologin --gid automantle --groups kvm automantle
fi
if [[ $(id -gn automantle) != automantle ]]; then
    echo 'The automantle service user must have the automantle primary group.' >&2
    exit 1
fi
usermod -aG kvm automantle
getent group automantle-control >/dev/null || groupadd --system automantle-control
usermod -aG automantle-control automantle
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for unit in automantle-helper.socket automantle-helper.service automantle-gateway.service; do
    [[ -f $script_dir/systemd/$unit ]] || { echo "Missing systemd unit: $unit" >&2; exit 1; }
done
if [[ -e /var/lib/automantle ]]; then
    owner=$(stat -c '%U' /var/lib/automantle)
    if [[ $owner != automantle ]]; then
        echo 'Existing /var/lib/automantle data needs an ownership migration to automantle:automantle.' >&2
        exit 1
    fi
    if [[ -n $(find /var/lib/automantle -xdev ! -user automantle -print -quit) ]]; then
        echo 'Some files under /var/lib/automantle are not owned by automantle; migrate them before installing.' >&2
        exit 1
    fi
fi
if [[ -e /etc/automantle/gateway.json ]]; then
    owner=$(stat -c '%U' /etc/automantle/gateway.json)
    mode=$(stat -c '%a' /etc/automantle/gateway.json)
    if [[ $owner != automantle || $mode != 600 ]]; then
        echo 'Existing gateway config needs an ownership migration to automantle:automantle mode 0600.' >&2
        exit 1
    fi
fi
if systemctl is-active --quiet automantle-gateway.service; then
    echo 'Stop the running gateway service before replacing its binaries.' >&2
    exit 1
fi
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
install -o root -g root -m 0755 "$helper" /usr/local/bin/automantle-helper
install -d -o automantle -g automantle -m 0700 /var/lib/automantle
install -d -o automantle -g automantle -m 0700 /var/lib/automantle/vms
install -d -o root -g automantle -m 0710 /etc/automantle
if [[ ! -e /etc/automantle/gateway.json ]]; then
    printf '%s\n' '{"backendUrl":"http://127.0.0.1:8082"}' > "$tmp/gateway.json"
    install -o automantle -g automantle -m 0600 "$tmp/gateway.json" /etc/automantle/gateway.json
fi
for unit in automantle-helper.socket automantle-helper.service automantle-gateway.service; do
    install -o root -g root -m 0644 "$script_dir/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now automantle-helper.socket
systemctl enable automantle-gateway.service
if [[ ${SUDO_USER:-root} != root ]]; then
    usermod -aG automantle-control "$SUDO_USER"
fi
echo 'Installed unprivileged AutoMantle Gateway, root helper, and Cloud Hypervisor v53.0.'
echo 'KVM was already available and has not been changed. Checking gateway setup:'
/usr/local/bin/automantle-gateway doctor
echo 'Start the API, then run: sudo systemctl start automantle-gateway.service'
echo 'Log out and back in before using dashboard VM controls as the sudo user.'
