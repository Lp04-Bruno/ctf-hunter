#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${ARTIFACT_DIR:=$project_root/artifacts}"
artifact_dir=$ARTIFACT_DIR
metadata_values=$(python3 -c 'import pathlib, sys, tomllib; data = tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(data["package_name"], data["debian_version"], data["debian_prerelease_example"])' "$project_root/release/metadata.toml")
set -- $metadata_values
package_name=$1
release_debian_version=$2
prerelease_debian_version=$3
debian_version=${CTF_HUNTER_DEBIAN_VERSION_OVERRIDE:-$release_debian_version}
export CTF_HUNTER_DEBIAN_VERSION_OVERRIDE
dpkg --validate-version "$debian_version"
if test "$debian_version" != "$release_debian_version" \
    && test "$debian_version" != "$prerelease_debian_version"; then
    echo "unsupported Debian version override: $debian_version" >&2
    exit 1
fi
architecture=$(dpkg-architecture -qDEB_HOST_ARCH)
mkdir -p "$artifact_dir"
if test -n "${CTF_HUNTER_BUILD_ROOT:-}"; then
    case "$CTF_HUNTER_BUILD_ROOT" in
        /build/*) build_root=$CTF_HUNTER_BUILD_ROOT ;;
        *) echo "CTF_HUNTER_BUILD_ROOT must be below /build" >&2; exit 1 ;;
    esac
    rm -rf -- "$build_root"
    mkdir -p "$build_root"
else
    build_root=$(mktemp -d "$artifact_dir/.build.XXXXXX")
fi
source_dir="$build_root/$package_name-${debian_version%-*}"

cleanup() {
    rm -rf -- "$build_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$source_dir"
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
    "$project_root/" "$source_dir/"

if test "$debian_version" != "$release_debian_version"; then
    python3 - "$source_dir/debian/changelog" "$debian_version" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
version = sys.argv[2]
contents = path.read_text()
updated, replacements = re.subn(
    r"\A(ctf-hunter \()[^)]+(\) unstable; urgency=medium\n)",
    rf"\g<1>{version}\g<2>",
    contents,
    count=1,
)
if replacements != 1:
    raise SystemExit("unable to apply Debian version override")
path.write_text(updated)
PY
fi

if test -z "${SOURCE_DATE_EPOCH:-}"; then
    if git -C "$project_root" rev-parse --git-dir >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH=$(git -C "$project_root" log -1 --format=%ct)
    elif test -d "$project_root/.git-data"; then
        SOURCE_DATE_EPOCH=$(git --git-dir="$project_root/.git-data" \
            --work-tree="$project_root" log -1 --format=%ct)
    else
        changelog_date=$(dpkg-parsechangelog -l"$project_root/debian/changelog" -S Date)
        SOURCE_DATE_EPOCH=$(date --date="$changelog_date" +%s)
    fi
fi
export SOURCE_DATE_EPOCH
: "${CTF_HUNTER_EBPF_TOOLCHAIN:=nightly-2026-09-19}"
export CTF_HUNTER_EBPF_TOOLCHAIN
: "${TZ:=UTC}"
export TZ
: "${LC_ALL:=C.UTF-8}"
export LC_ALL
: "${LANG:=C.UTF-8}"
export LANG
export CARGO_INCREMENTAL=0
canonical_source="/usr/src/$package_name-${debian_version%-*}"
: "${RUSTFLAGS:=}"
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$source_dir=$canonical_source"
export RUSTFLAGS
umask 022
: "${DEB_BUILD_OPTIONS:=nocheck}"
export DEB_BUILD_OPTIONS

(cd "$source_dir" && dpkg-buildpackage --build=binary --unsigned-source --unsigned-changes)

find "$build_root" -maxdepth 1 -type f \
    \( -name 'ctf-hunter_*.deb' \
    -o -name 'ctf-hunter-dbgsym_*.deb' \
    -o -name 'ctf-hunter_*.buildinfo' \
    -o -name 'ctf-hunter_*.changes' \) \
    -exec cp -f -- {} "$artifact_dir/" \;

package="$artifact_dir/${package_name}_${debian_version}_${architecture}.deb"
test -f "$package"
python3 "$project_root/scripts/verify-debian-package.py" \
    --expected-version "$debian_version" "$package"

printf '%s\n' "Debian artifacts written to $artifact_dir"
