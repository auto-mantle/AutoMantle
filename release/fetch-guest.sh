#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/guest-image.env"
destination=${1:?usage: fetch-guest.sh DESTINATION}
curl --fail --location --retry 3 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --output "$destination" "$GUEST_IMAGE_URL"
echo "$GUEST_IMAGE_SHA256  $destination" | sha256sum --check --strict
