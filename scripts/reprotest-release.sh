#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
store_dir=$project_root/artifacts/reprotest
rm -rf "$store_dir"

# reprotest perturbs the outer environment and build path. The nested pinned
# Bookworm builder intentionally normalizes those inputs.
reprotest \
    --source-root "$project_root" \
    --variations=environment,build_path,timezone,locales,umask,fileordering \
    --store-dir "$store_dir" \
    'ARTIFACT_SUBDIRECTORY=reprotest/output scripts/build-bookworm-package.sh && cp artifacts/reprotest/output/ctf-hunter_0.1.0-1_amd64.deb ctf-hunter-reprotest.deb' \
    'ctf-hunter-reprotest.deb' \
    -- null
