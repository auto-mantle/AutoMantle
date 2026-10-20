#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID != 0 || $# -gt 2 ]]; then
  echo 'Usage: sudo bash scripts/build-linux-template.sh [OUTPUT_EXT4 [PUBLIC_CA_PEM]]' >&2; exit 2
fi
output=${1:-/var/lib/automantle/linux.ext4}
ca=${2:-/var/lib/automantle/tls/ca.pem}
[[ $output = /* && $ca = /* && -f $ca && ! -L $ca && ! -e $output ]] || {
  echo 'Use absolute paths, an existing public CA, and a new output path.' >&2; exit 1;
}
parent=$(dirname "$output")
mkdir -p "$parent"
python3 - "$parent" <<'PY'
import os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1])
for directory in [p,*p.parents]:
    s=os.lstat(directory)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
        raise SystemExit('Template directories must be real, root-owned, and not writable by others')
PY
docker_bin=${DOCKER_BIN:-docker}
command -v "$docker_bin" >/dev/null
for tool in mkfs.ext4 tar truncate python3 openssl; do command -v "$tool" >/dev/null; done
work=$(mktemp -d /var/tmp/automantle-linux-template.XXXXXXXX)
chmod 0700 "$work"
tag="automantle-linux-template-build:${work##*.}"
container=
publish=
cleanup() {
  [[ -z $publish ]] || rm -f -- "$publish"
  [[ -z $container ]] || "$docker_bin" rm -f "$container" </dev/null >/dev/null 2>&1 || true
  "$docker_bin" image rm "$tag" </dev/null >/dev/null 2>&1 || true
  [[ $(realpath "$work") == /var/tmp/automantle-linux-template.* ]] && rm -rf -- "$work"
}
trap cleanup EXIT
cat > "$work/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv udev dbus acpid sudo curl git python3 ca-certificates iproute2 procps util-linux openssl && rm -rf /var/lib/apt/lists/* && useradd -m -s /bin/bash agent && usermod -aG sudo agent && printf 'agent ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/agent && chmod 0440 /etc/sudoers.d/agent
DOCKER
tar -C "$work" -cf - Dockerfile | "$docker_bin" build --tag "$tag" -
container=$("$docker_bin" create "$tag" /sbin/init </dev/null | tr -d '\r')
mkdir "$work/root"
"$docker_bin" export "$container" </dev/null > "$work/root.tar"
tar --numeric-owner -xf "$work/root.tar" -C "$work/root"
guest="$work/root"
rm -f "$guest/.dockerenv" "$guest/run/.containerenv" "$guest/run/systemd/container"
openssl x509 -in "$ca" -out "$work/public-ca.pem"
install -m 0644 "$work/public-ca.pem" "$guest/usr/local/share/ca-certificates/automantle.crt"
mkdir -p "$guest/etc/systemd/system/serial-getty@ttyS0.service.d" "$guest/etc/systemd/system/getty.target.wants" "$guest/etc/systemd/system/multi-user.target.wants"
cat > "$guest/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'UNIT'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin agent --noclear %I 115200,38400,9600 vt100
UNIT
ln -sf /lib/systemd/system/serial-getty@.service "$guest/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service"
ln -sf /lib/systemd/system/multi-user.target "$guest/etc/systemd/system/default.target"
cat > "$guest/usr/local/sbin/automantle-network" <<'GUEST'
#!/bin/bash
set -eu
proxy=; config=
for arg in $(cat /proc/cmdline); do
 case "$arg" in automantle_proxy=*) proxy=${arg#automantle_proxy=};; ip=*) config=${arg#ip=};; esac
done
if [[ -n $config ]]; then
 guest_ip=${config%%:*}; remaining=${config#*::}; host_ip=${remaining%%:*}
 ip link set eth0 up
 ip addr replace "$guest_ip/30" dev eth0
 ip route replace default via "$host_ip"
fi
if [[ -n $proxy ]]; then
 printf 'http_proxy=%s\nhttps_proxy=%s\nHTTP_PROXY=%s\nHTTPS_PROXY=%s\n' "$proxy" "$proxy" "$proxy" "$proxy" > /etc/environment
fi
update-ca-certificates >/dev/null
GUEST
chmod 0755 "$guest/usr/local/sbin/automantle-network"
cat > "$guest/etc/systemd/system/automantle-network.service" <<'UNIT'
[Unit]
Description=AutoMantle guest networking and public CA
After=local-fs.target
Before=serial-getty@ttyS0.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/automantle-network
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/automantle-network.service "$guest/etc/systemd/system/multi-user.target.wants/automantle-network.service"
mkdir -p "$guest/etc/acpi/events"
cat > "$guest/etc/acpi/events/automantle-power" <<'EVENT'
event=button/power.*
action=/sbin/poweroff
EVENT
ln -sf /lib/systemd/system/acpid.service "$guest/etc/systemd/system/multi-user.target.wants/acpid.service"
printf 'AutoMantle Linux VM\n' > "$guest/etc/issue"
printf 'automantle\n' > "$guest/etc/hostname"
: > "$guest/etc/machine-id"
rm -f "$guest/var/lib/dbus/machine-id"
mkdir -p "$guest/home/agent/project"
agent_uid=$(awk -F: '$1=="agent"{print $3}' "$guest/etc/passwd")
agent_gid=$(awk -F: '$1=="agent"{print $4}' "$guest/etc/passwd")
chown "$agent_uid:$agent_gid" "$guest/home/agent/project"
printf '\ncd "$HOME/project"\n' >> "$guest/home/agent/.bashrc"
truncate -s 8G "$work/linux.ext4"
mkfs.ext4 -q -F -L automantle-linux -d "$guest" "$work/linux.ext4"
chmod 0600 "$work/linux.ext4"
publish=$(mktemp "$parent/.linux-template.XXXXXXXX")
cp --sparse=always "$work/linux.ext4" "$publish"
chmod 0600 "$publish"
sync "$publish"
ln -T "$publish" "$output"
sync "$parent"
echo "Clean Linux template installed: $output"
