#!/bin/bash
set -euo pipefail

if test "$#" -ne 4; then
    echo "usage: publish-apt-snapshot.sh <testing|stable> PACKAGE TAG SHA256" >&2
    exit 2
fi

channel=$1
package=$(realpath "$2")
tag=$3
expected_sha=$4
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "$channel" in
    testing|stable) ;;
    *) echo "channel must be testing or stable" >&2; exit 2 ;;
esac
test -f "$package"
test "$(sha256sum "$package" | cut -d' ' -f1)" = "$expected_sha"

: "${APTLY_CONFIG:?APTLY_CONFIG must name the protected aptly configuration}"
: "${APTLY_PUBLISH_TARGET:?APTLY_PUBLISH_TARGET must name the configured endpoint and prefix}"
: "${APTLY_GPG_KEY:?APTLY_GPG_KEY must identify the archive signing key}"
: "${APTLY_ORIGIN:?APTLY_ORIGIN is required}"
: "${APTLY_LABEL:?APTLY_LABEL is required}"

metadata_values=$(python3 -c '
import pathlib, sys, tomllib
metadata = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
if not metadata.get("apt_repository_enabled", False):
    raise SystemExit("APT publication is disabled")
print(metadata["apt_repository_origin"])
print(metadata["apt_repository_label"])
' "$project_root/release/metadata.toml")
expected_origin=$(sed -n '1p' <<<"$metadata_values")
expected_label=$(sed -n '2p' <<<"$metadata_values")
test "$APTLY_ORIGIN" = "$expected_origin"
test "$APTLY_LABEL" = "$expected_label"

test -f "$APTLY_CONFIG"
command -v aptly >/dev/null

repository=ctf-hunter-incoming
version_tag=${tag#v}
snapshot="ctf-hunter-${version_tag}-${expected_sha}"
aptly_command=(aptly -config="$APTLY_CONFIG")
signing=(-batch -gpg-key="$APTLY_GPG_KEY")
if test -n "${APTLY_GPG_PASSPHRASE_FILE:-}"; then
    test -f "$APTLY_GPG_PASSPHRASE_FILE"
    signing+=("-passphrase-file=$APTLY_GPG_PASSPHRASE_FILE")
fi

if test "$channel" = testing; then
    if ! "${aptly_command[@]}" repo show "$repository" >/dev/null 2>&1; then
        "${aptly_command[@]}" repo create \
            -component=main -distribution=testing "$repository"
    fi
    "${aptly_command[@]}" repo add -force-replace "$repository" "$package"
    if ! "${aptly_command[@]}" snapshot show "$snapshot" >/dev/null 2>&1; then
        "${aptly_command[@]}" snapshot create "$snapshot" from repo "$repository"
    fi
fi

"${aptly_command[@]}" snapshot show "$snapshot" >/dev/null

if "${aptly_command[@]}" publish show "$channel" "$APTLY_PUBLISH_TARGET" >/dev/null 2>&1; then
    "${aptly_command[@]}" publish switch \
        "${signing[@]}" -component=main \
        "$channel" "$APTLY_PUBLISH_TARGET" "$snapshot"
else
    "${aptly_command[@]}" publish snapshot \
        "${signing[@]}" \
        -architectures=amd64 \
        -component=main \
        -distribution="$channel" \
        -origin="$APTLY_ORIGIN" \
        -label="$APTLY_LABEL" \
        "$snapshot" "$APTLY_PUBLISH_TARGET"
fi

echo "Published immutable snapshot $snapshot to $channel"
