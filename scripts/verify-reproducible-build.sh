#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=0.1.0-1
first_dir=reproducible/build-a
second_dir=reproducible/build-b
artifact_root=$project_root/artifacts/reproducible
first_root=$project_root/artifacts/$first_dir
second_root=$project_root/artifacts/$second_dir

SOURCE_DATE_EPOCH=$(git -C "$project_root" log -1 --format=%ct)
export SOURCE_DATE_EPOCH

for directory in "$first_root" "$second_root"; do
    case "$directory" in
        "$artifact_root"/*) rm -rf -- "$directory" ;;
        *) echo "Refusing to remove unexpected build directory: $directory" >&2; exit 1 ;;
    esac
done

ARTIFACT_SUBDIRECTORY=$first_dir "$project_root/scripts/build-bookworm-package.sh"
ARTIFACT_SUBDIRECTORY=$second_dir "$project_root/scripts/build-bookworm-package.sh"

packages=(
    "ctf-hunter_${version}_amd64.deb"
    "ctf-hunter-dbgsym_${version}_amd64.deb"
)
for name in "${packages[@]}"; do
    first=$first_root/$name
    second=$second_root/$name
    test -f "$first" && test -f "$second"
    if ! cmp -s "$first" "$second"; then
        report=$artifact_root/diffoscope-${name%.deb}.html
        mkdir -p "$artifact_root"
        diffoscope --html "$report" "$first" "$second" || true
        echo "Debian package is not reproducible: $name; inspect $report" >&2
        exit 1
    fi
    echo "Reproducible: $name $(sha256sum "$first" | cut -d' ' -f1)"
done

for suffix in amd64.buildinfo amd64.changes; do
    first=$first_root/ctf-hunter_${version}_$suffix
    second=$second_root/ctf-hunter_${version}_$suffix
    if test -f "$first" && test -f "$second" && ! cmp -s "$first" "$second"; then
        echo "NOTICE: $suffix metadata differs; both binary packages remain byte-identical"
    fi
done

echo "PASS: both Debian binary packages are byte-for-byte reproducible"
