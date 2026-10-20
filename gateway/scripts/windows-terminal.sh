#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $# != 6 || $1 != -e || $3 != terminal || $5 != --socket || ! $4 =~ ^automantle-vm-[0-9a-fA-F]{32}$ ]]; then
  echo 'Expected: -e GATEWAY terminal RUN_ID --socket SOCKET' >&2;exit 2
fi
shift
[[ $1 = /* && $5 = /* ]] || { echo 'Gateway and socket paths must be absolute' >&2;exit 2; }
distro=${AUTOMANTLE_WSL_DISTRO:-${WSL_DISTRO_NAME:-}}
if [[ -z $distro ]] && command -v wslinfo >/dev/null;then distro=$(wslinfo --get-distro-name);fi
[[ -n $distro ]] || { echo 'Set AUTOMANTLE_WSL_DISTRO for the app service' >&2;exit 1; }
terminal=${AUTOMANTLE_WINDOWS_TERMINAL:-}
if [[ -z $terminal ]];then terminal=$(command -v wt.exe || true);fi
[[ -n $terminal && -x $terminal ]] || { echo 'Install Windows Terminal and set AUTOMANTLE_WINDOWS_TERMINAL to its WSL path' >&2;exit 1; }
export WSL_INTEROP=${WSL_INTEROP:-/run/WSL/1_interop}
[[ -S $WSL_INTEROP ]] || { echo 'WSL Windows interoperability is unavailable' >&2;exit 1; }
exec "$terminal" -w new new-tab --title "AutoMantle VM terminal" --suppressApplicationTitle \
  wsl.exe --distribution "$distro" --user "$(id -un)" --exec "$@"
