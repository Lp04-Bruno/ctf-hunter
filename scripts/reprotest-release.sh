#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
store_dir=$project_root/artifacts/reprotest
work_dir=$project_root/artifacts/.reprotest-work
source_root=$work_dir/source
temp_dir=$work_dir/tmp
podman_root=$project_root/artifacts/.podman-root
podman_runroot=/tmp/ctf-hunter-podman-run
build_image=localhost/ctf-hunter-build:0.1.0-bookworm

for directory in "$store_dir" "$work_dir"; do
    case "$directory" in
        "$project_root/artifacts/reprotest"|\
        "$project_root/artifacts/.reprotest-work")
            rm -rf -- "$directory"
            ;;
        *)
            echo "Refusing to remove unexpected reprotest directory: $directory" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$source_root" "$temp_dir"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

rsync -a \
    --exclude '/.git/' \
    --exclude '/.git-data/' \
    --exclude '/.agents/' \
    --exclude '/.codex/' \
    --exclude '/artifacts/' \
    --exclude '/setup/' \
    --exclude '/target/' \
    --exclude '/ui/dist/' \
    --exclude '/ui/node_modules/' \
    --exclude '/ui/.svelte-kit/' \
    "$project_root/" "$source_root/"

source_date_epoch=$(git -C "$project_root" log -1 --format=%ct)
CTF_HUNTER_PODMAN_ROOT=$podman_root \
CTF_HUNTER_PODMAN_RUNROOT=$podman_runroot \
    "$project_root/scripts/podman-release.sh" image exists "$build_image"
printf -v build_command \
    'SOURCE_DATE_EPOCH=%q CTF_HUNTER_PODMAN_ROOT=%q CTF_HUNTER_PODMAN_RUNROOT=%q CTF_HUNTER_PODMAN_DRIVER=overlay CTF_HUNTER_BUILD_IMAGE=%q ARTIFACT_SUBDIRECTORY=reprotest/output scripts/build-bookworm-package.sh && cp artifacts/reprotest/output/ctf-hunter_0.1.0-1_amd64.deb ctf-hunter-reprotest.deb' \
    "$source_date_epoch" "$podman_root" "$podman_runroot" "$build_image"
export TMPDIR=$temp_dir

# reprotest perturbs the outer environment and build path. The nested pinned
# Bookworm builder intentionally normalizes those inputs.
reprotest \
    --source-root "$source_root" \
    --variations=environment,build_path,timezone,locales,umask,fileordering \
    --store-dir "$store_dir" \
    "$build_command" \
    'ctf-hunter-reprotest.deb' \
    -- null

echo "PASS: extended reprotest perturbation matrix produced identical package bytes"
