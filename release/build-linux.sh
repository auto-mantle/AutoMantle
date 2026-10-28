#!/usr/bin/env bash
set -euo pipefail

# Maintainer build. The published archive is self-contained; users only extract it.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${AUTOMANTLE_JAVA_HOME:?set AUTOMANTLE_JAVA_HOME to a Linux JDK 25 directory}"
: "${AUTOMANTLE_CLOUD_HYPERVISOR:?set AUTOMANTLE_CLOUD_HYPERVISOR to the pinned v53.0 static binary}"
for tool in cargo cc sha256sum tar ldd qemu-system-x86_64; do
    command -v "$tool" >/dev/null || { echo "Missing release build tool: $tool" >&2; exit 1; }
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Build on Linux x86_64.' >&2; exit 1; }
expected_cloud_hypervisor_sha256='448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc'
read -r actual_cloud_hypervisor_sha256 _ < <(sha256sum "$AUTOMANTLE_CLOUD_HYPERVISOR")
[[ $actual_cloud_hypervisor_sha256 == "$expected_cloud_hypervisor_sha256" ]] || { echo 'Cloud Hypervisor v53.0 checksum did not match the pinned static binary.' >&2; exit 1; }
[[ $("$AUTOMANTLE_CLOUD_HYPERVISOR" --version) == 'cloud-hypervisor v53.0' ]] || { echo 'Cloud Hypervisor v53.0 is required.' >&2; exit 1; }
"$AUTOMANTLE_JAVA_HOME/bin/java" -version 2>&1 | grep -q 'version "25' || { echo 'Java 25 is required.' >&2; exit 1; }

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
install -m 0755 "$root/gateway/target/release/automantle-proxy-stdio" "$bundle/bin/automantle-proxy-stdio"
"$root/gateway/target/release/automantle-bundle-qemu" "$bundle/qemu"
install -m 0755 "$root/release/automantle-qemu" "$bundle/bin/automantle-qemu"
"$bundle/bin/automantle-qemu" --version
"$bundle/bin/automantle-qemu" -display help | grep -q gtk
install -m 0755 "$AUTOMANTLE_CLOUD_HYPERVISOR" "$bundle/bin/cloud-hypervisor"
cp -a "$AUTOMANTLE_JAVA_HOME"/. "$bundle/runtime"/
install -m 0644 "$jar" "$bundle/app/api.jar"

# Users install this bridge inside a compatible guest when they need proxy networking.
cc -std=c11 -O2 -Wall -Wextra -Werror -static -pthread \
    "$root/gateway/guest/automantle-vsock-proxy.c" -o "$bundle/share/guest/automantle-vsock-proxy"
install -m 0644 "$root/gateway/guest/automantle-vsock-proxy.service" "$bundle/share/guest/automantle-vsock-proxy.service"
(
    cd "$bundle"
    sha256sum bin/* app/api.jar share/guest/* > SHA256SUMS
)
archive="$root/dist/automantle-linux-x86_64.tar.gz"
[[ ! -e $archive ]] || { echo "Output already exists: $archive" >&2; exit 1; }
tar -C "$stage" -czf "$archive" automantle-linux-x86_64
printf 'Built %s\n' "$archive"
