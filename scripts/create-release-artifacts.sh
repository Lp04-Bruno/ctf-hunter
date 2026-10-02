#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
artifact_dir=${1:-$project_root/artifacts/bookworm}
require_signature=${REQUIRE_SIGNATURE:-0}
signing_key=${CTF_HUNTER_SIGNING_KEY:-}
signing_passphrase_file=${CTF_HUNTER_SIGNING_PASSPHRASE_FILE:-}

artifact_dir=$(realpath "$artifact_dir")
package=$artifact_dir/ctf-hunter_0.1.0-1_amd64.deb
test -f "$package" || {
    echo "release package not found: $package" >&2
    exit 1
}

if test -z "${SOURCE_DATE_EPOCH:-}"; then
    SOURCE_DATE_EPOCH=$(git -C "$project_root" log -1 --format=%ct)
fi
export SOURCE_DATE_EPOCH

sbom=$artifact_dir/ctf-hunter_0.1.0-1_amd64.spdx.json
python3 "$project_root/scripts/generate-spdx-sbom.py" "$package" "$sbom"

(
    cd "$artifact_dir"
    find . -maxdepth 1 -type f \
        \( -name '*.deb' -o -name '*.buildinfo' -o -name '*.changes' -o -name '*.spdx.json' \) \
        -printf '%f\n' \
        | LC_ALL=C sort \
        | xargs sha256sum >SHA256SUMS
)

rm -f "$artifact_dir/SHA256SUMS.asc"
if test -n "$signing_key"; then
    gpg_arguments=(--batch --yes --local-user "$signing_key")
    if test -n "$signing_passphrase_file"; then
        test -f "$signing_passphrase_file" || {
            echo "signing passphrase file not found" >&2
            exit 1
        }
        gpg_arguments+=(--pinentry-mode loopback --passphrase-file "$signing_passphrase_file")
    fi
    gpg "${gpg_arguments[@]}" \
        --armor --detach-sign \
        --output "$artifact_dir/SHA256SUMS.asc" \
        "$artifact_dir/SHA256SUMS"
elif test "$require_signature" = 1; then
    echo "CTF_HUNTER_SIGNING_KEY is required for a release signature" >&2
    exit 1
else
    echo "NOTICE: checksum signature deferred; set CTF_HUNTER_SIGNING_KEY and REQUIRE_SIGNATURE=1"
fi

python3 "$project_root/scripts/verify-release-artifacts.py" "$artifact_dir"
