#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"
: "${CTF_HUNTER_BUILD_IMAGE:=localhost/ctf-hunter-build:0.1.1-bookworm}"

exec "$project_root/scripts/podman-release.sh" build \
    --pull=never \
    --build-arg "DEBIAN_IMAGE=$DEBIAN_IMAGE" \
    --build-arg "RUST_STABLE=$RUST_STABLE" \
    --build-arg "RUST_NIGHTLY=$RUST_NIGHTLY" \
    --build-arg "RUSTUP_INIT_SHA256=$RUSTUP_INIT_SHA256" \
    --build-arg "NODE_VERSION=$NODE_VERSION" \
    --build-arg "NODE_SHA256=$NODE_SHA256" \
    --build-arg "BPF_LINKER_VERSION=$BPF_LINKER_VERSION" \
    --build-arg "BPF_LINKER_SHA256=$BPF_LINKER_SHA256" \
    --file "$project_root/release/debian12/Containerfile" \
    --tag "$CTF_HUNTER_BUILD_IMAGE" \
    "$project_root"
