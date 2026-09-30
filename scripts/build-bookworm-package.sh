#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"
: "${CTF_HUNTER_BUILD_IMAGE:=localhost/ctf-hunter-build:0.1.0-bookworm}"
: "${ARTIFACT_SUBDIRECTORY:=bookworm}"

if ! "$project_root/scripts/podman-release.sh" image exists "$CTF_HUNTER_BUILD_IMAGE"; then
    "$project_root/scripts/build-release-container.sh"
fi

if test -z "${SOURCE_DATE_EPOCH:-}"; then
    SOURCE_DATE_EPOCH=$(git -C "$project_root" log -1 --format=%ct)
fi
export SOURCE_DATE_EPOCH

artifact_dir="$project_root/artifacts/$ARTIFACT_SUBDIRECTORY"
cache_dir="$project_root/artifacts/.release-cache"
mkdir -p "$artifact_dir"
mkdir -p "$cache_dir/cargo-registry" "$cache_dir/npm"
log_file="$artifact_dir/build.log"

"$project_root/scripts/podman-release.sh" run --rm \
    --security-opt label=disable \
    --volume "$project_root:/workspace:rw" \
    --volume "$cache_dir/cargo-registry:/opt/cargo/registry:rw" \
    --volume "$cache_dir/npm:/root/.npm:rw" \
    --workdir /workspace \
    --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --env "CTF_HUNTER_EBPF_TOOLCHAIN=$RUST_NIGHTLY" \
    --env "ARTIFACT_SUBDIRECTORY=$ARTIFACT_SUBDIRECTORY" \
    "$CTF_HUNTER_BUILD_IMAGE" \
    bash -o errexit -o nounset -o pipefail -c '
        rm -rf /build/source
        mkdir -p /build/source
        rsync -a \
            --exclude /.git/ \
            --exclude /.git-data/ \
            --exclude /.agents/ \
            --exclude /.codex/ \
            --exclude /artifacts/ \
            --exclude /setup/ \
            --exclude /target/ \
            --exclude /ui/dist/ \
            --exclude /ui/node_modules/ \
            /workspace/ /build/source/
        cd /build/source
        python3 scripts/check-build-toolchain.py
        cargo fetch --locked
        rust_sysroot=$(rustup run "$CTF_HUNTER_EBPF_TOOLCHAIN" rustc --print sysroot)
        rustup run "$CTF_HUNTER_EBPF_TOOLCHAIN" cargo fetch \
            --manifest-path "$rust_sysroot/lib/rustlib/src/rust/library/sysroot/Cargo.toml"
        npm --prefix ui ci --ignore-scripts
        rm -rf ui/node_modules
        ARTIFACT_DIR="/workspace/artifacts/$ARTIFACT_SUBDIRECTORY" \
            scripts/build-debian-package.sh
        lintian --profile debian --pedantic \
            "/workspace/artifacts/$ARTIFACT_SUBDIRECTORY/ctf-hunter_0.1.0-1_amd64.changes"
    ' 2>&1 | tee "$log_file"
