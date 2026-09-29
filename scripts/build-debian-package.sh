#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifact_dir="$project_root/artifacts"
package_name=$(python3 -c 'import pathlib, sys, tomllib; print(tomllib.loads(pathlib.Path(sys.argv[1]).read_text())["package_name"])' "$project_root/release/metadata.toml")
debian_version=$(dpkg-parsechangelog -l"$project_root/debian/changelog" -S Version)
architecture=$(dpkg-architecture -qDEB_HOST_ARCH)
mkdir -p "$artifact_dir"
build_root=$(mktemp -d "$artifact_dir/.build.XXXXXX")
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

if git -C "$project_root" rev-parse --git-dir >/dev/null 2>&1; then
    source_date_epoch=$(git -C "$project_root" log -1 --format=%ct)
elif test -d "$project_root/.git-data"; then
    source_date_epoch=$(git --git-dir="$project_root/.git-data" \
        --work-tree="$project_root" log -1 --format=%ct)
else
    changelog_date=$(dpkg-parsechangelog -l"$project_root/debian/changelog" -S Date)
    source_date_epoch=$(date --date="$changelog_date" +%s)
fi
export SOURCE_DATE_EPOCH="$source_date_epoch"
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
python3 "$project_root/scripts/verify-debian-package.py" "$package"

printf '%s\n' "Debian artifacts written to $artifact_dir"
