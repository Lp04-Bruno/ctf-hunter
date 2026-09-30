#!/bin/sh
set -eu

: "${CTF_HUNTER_PODMAN_ROOT:=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/artifacts/.podman-root}"
: "${CTF_HUNTER_PODMAN_RUNROOT:=/tmp/ctf-hunter-podman-run}"
: "${CTF_HUNTER_PODMAN_DRIVER:=overlay}"
: "${XDG_RUNTIME_DIR:=$CTF_HUNTER_PODMAN_RUNROOT}"
export XDG_RUNTIME_DIR

mkdir -p "$CTF_HUNTER_PODMAN_ROOT" "$CTF_HUNTER_PODMAN_RUNROOT"
chmod 0700 "$CTF_HUNTER_PODMAN_RUNROOT"

exec podman \
    --root "$CTF_HUNTER_PODMAN_ROOT" \
    --runroot "$CTF_HUNTER_PODMAN_RUNROOT" \
    --storage-driver="$CTF_HUNTER_PODMAN_DRIVER" \
    "$@"
