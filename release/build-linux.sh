#!/usr/bin/env bash
set -euo pipefail

# Maintainer build. The published archive is self-contained; users only extract it.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${AUTOMANTLE_JAVA_HOME:?set AUTOMANTLE_JAVA_HOME to a Linux JDK 25 directory}"
: "${AUTOMANTLE_CLOUD_HYPERVISOR:?set AUTOMANTLE_CLOUD_HYPERVISOR to the pinned v53.0 static binary}"
: "${AUTOMANTLE_GUEST_KERNEL:?set AUTOMANTLE_GUEST_KERNEL to a bootable x86_64 guest kernel}"
: "${AUTOMANTLE_GUEST_IMAGE:?set AUTOMANTLE_GUEST_IMAGE to an offline systemd ext4 guest image}"
for tool in cargo cc debugfs e2fsck sha256sum tar; do
    command -v "$tool" >/dev/null || { echo "Missing release build tool: $tool" >&2; exit 1; }
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Build on Linux x86_64.' >&2; exit 1; }
expected_cloud_hypervisor_sha256='448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc'
read -r actual_cloud_hypervisor_sha256 _ < <(sha256sum "$AUTOMANTLE_CLOUD_HYPERVISOR")
[[ $actual_cloud_hypervisor_sha256 == "$expected_cloud_hypervisor_sha256" ]] || { echo 'Cloud Hypervisor v53.0 checksum did not match the pinned static binary.' >&2; exit 1; }
[[ $("$AUTOMANTLE_CLOUD_HYPERVISOR" --version) == 'cloud-hypervisor v53.0' ]] || { echo 'Cloud Hypervisor v53.0 is required.' >&2; exit 1; }
"$AUTOMANTLE_JAVA_HOME/bin/java" -version 2>&1 | grep -q 'version "25' || { echo 'Java 25 is required.' >&2; exit 1; }
[[ -s $AUTOMANTLE_GUEST_KERNEL && -s $AUTOMANTLE_GUEST_IMAGE ]] || { echo 'Guest kernel or image is missing.' >&2; exit 1; }

cargo build --release --locked --manifest-path "$root/gateway/Cargo.toml"
JAVA_HOME="$AUTOMANTLE_JAVA_HOME" "$root/api/mvnw" -f "$root/api/pom.xml" -DskipTests package
jar="$root/api/target/api-0.0.1-SNAPSHOT.jar"
[[ -s $jar ]] || { echo 'Maven did not produce the API JAR.' >&2; exit 1; }

mkdir -p "$root/dist"
stage=$(mktemp -d "$root/dist/.automantle-build.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
bundle="$stage/automantle-linux-x86_64"
mkdir -p "$bundle/bin" "$bundle/app" "$bundle/runtime" "$bundle/share/guest"
install -m 0755 "$root/gateway/target/release/automantle" "$bundle/bin/automantle"
install -m 0755 "$root/gateway/target/release/automantle-gateway" "$bundle/bin/automantle-gateway"
install -m 0755 "$AUTOMANTLE_CLOUD_HYPERVISOR" "$bundle/bin/cloud-hypervisor"
cp -a "$AUTOMANTLE_JAVA_HOME"/. "$bundle/runtime"/
install -m 0644 "$jar" "$bundle/app/api.jar"
install -m 0644 "$AUTOMANTLE_GUEST_KERNEL" "$bundle/share/guest/kernel"
install -m 0644 "$AUTOMANTLE_GUEST_IMAGE" "$bundle/share/guest/linux.ext4"

# The guest owns this loopback listener. No host networking privilege is needed.
cc -std=c11 -O2 -Wall -Wextra -Werror -static -pthread \
    "$root/gateway/guest/automantle-vsock-proxy.c" -o "$stage/automantle-vsock-proxy"
image="$bundle/share/guest/linux.ext4"
if ! debugfs -R 'stat /etc/systemd/system' "$image" 2>&1 | grep -q 'Inode:'; then
    echo 'Guest image must contain systemd and /etc/systemd/system.' >&2; exit 1
fi
if ! debugfs -R 'cat /etc/passwd' "$image" 2>/dev/null | grep -q '^nobody:'; then
    echo 'Guest image must have an unprivileged nobody account for its proxy bridge.' >&2; exit 1
fi
if ! debugfs -R 'stat /usr/local/bin' "$image" 2>&1 | grep -q 'Inode:'; then
    echo 'Guest image must contain /usr/local/bin.' >&2; exit 1
fi
if ! debugfs -R 'stat /etc/systemd/system/multi-user.target.wants' "$image" 2>&1 | grep -q 'Inode:'; then
    debugfs -w -R 'mkdir /etc/systemd/system/multi-user.target.wants' "$image" >/dev/null
fi
for guest_path in \
    /usr/local/bin/automantle-vsock-proxy \
    /etc/systemd/system/automantle-vsock-proxy.service \
    /etc/systemd/system/multi-user.target.wants/automantle-vsock-proxy.service; do
    if debugfs -R "stat $guest_path" "$image" 2>&1 | grep -q 'Inode:'; then
        echo "Guest image already contains $guest_path; use a clean input image." >&2; exit 1
    fi
done
debugfs -w -R "write $stage/automantle-vsock-proxy /usr/local/bin/automantle-vsock-proxy" "$image" >/dev/null
debugfs -w -R 'sif /usr/local/bin/automantle-vsock-proxy mode 0100755' "$image" >/dev/null
debugfs -w -R "write $root/gateway/guest/automantle-vsock-proxy.service /etc/systemd/system/automantle-vsock-proxy.service" "$image" >/dev/null
debugfs -w -R 'symlink /etc/systemd/system/multi-user.target.wants/automantle-vsock-proxy.service ../automantle-vsock-proxy.service' "$image" >/dev/null
for guest_path in \
    /usr/local/bin/automantle-vsock-proxy \
    /etc/systemd/system/automantle-vsock-proxy.service \
    /etc/systemd/system/multi-user.target.wants/automantle-vsock-proxy.service; do
    debugfs -R "stat $guest_path" "$image" 2>&1 | grep -q 'Inode:' || { echo "Guest image patch failed: $guest_path" >&2; exit 1; }
done
e2fsck -fn "$image" >/dev/null
(
    cd "$bundle"
    sha256sum bin/* app/api.jar share/guest/* > SHA256SUMS
)
archive="$root/dist/automantle-linux-x86_64.tar.gz"
[[ ! -e $archive ]] || { echo "Output already exists: $archive" >&2; exit 1; }
tar -C "$stage" -czf "$archive" automantle-linux-x86_64
printf 'Built %s\n' "$archive"
