#!/bin/bash
set -euo pipefail

if test "$#" -ne 5; then
    echo "usage: test-apt-repository.sh URL SUITE KEYRING VERSION SHA256" >&2
    exit 2
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"
repository_url=${1%/}
suite=$2
keyring=$(realpath "$3")
expected_version=$4
expected_sha=$5
test -f "$keyring"
expected_repository_url=$(python3 -c '
import pathlib, sys, tomllib
metadata = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
if not metadata.get("apt_repository_enabled", False):
    raise SystemExit("APT publication is disabled")
print(metadata["apt_repository_url"].rstrip("/"))
' "$project_root/release/metadata.toml")
test "$repository_url" = "$expected_repository_url"

"$project_root/scripts/podman-release.sh" run --rm \
    --security-opt label=disable \
    --volume "$keyring:/tmp/ctf-hunter-archive-keyring.gpg:ro" \
    --env "REPOSITORY_URL=$repository_url" \
    --env "REPOSITORY_SUITE=$suite" \
    --env "EXPECTED_VERSION=$expected_version" \
    --env "EXPECTED_SHA=$expected_sha" \
    "$DEBIAN_IMAGE" \
    /bin/bash -o errexit -o nounset -o pipefail -c '
        install -m 0644 /tmp/ctf-hunter-archive-keyring.gpg \
            /usr/share/keyrings/ctf-hunter-archive-keyring.gpg
        cat >/etc/apt/sources.list.d/ctf-hunter.sources <<EOF
Types: deb
URIs: $REPOSITORY_URL
Suites: $REPOSITORY_SUITE
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/ctf-hunter-archive-keyring.gpg
EOF
        found=0
        for attempt in 1 2 3 4 5 6; do
            if apt-get update; then
                candidate=$(apt-cache policy ctf-hunter | awk "/Candidate:/ {print \$2}")
                if test "$candidate" = "$EXPECTED_VERSION"; then
                    found=1
                    break
                fi
            fi
            sleep 10
        done
        test "$found" -eq 1
        cd /tmp
        apt-get download "ctf-hunter=$EXPECTED_VERSION"
        package=$(find /tmp -maxdepth 1 -name "ctf-hunter_*.deb" -print -quit)
        test -n "$package"
        test "$(sha256sum "$package" | cut -d" " -f1)" = "$EXPECTED_SHA"
        apt-get install -y --no-install-recommends "ctf-hunter=$EXPECTED_VERSION"
        test "$(dpkg-query -W -f="\${Version}" ctf-hunter)" = "$EXPECTED_VERSION"
        apt-get remove -y ctf-hunter
        apt-get purge -y ctf-hunter
    '

echo "PASS: $suite APT source served and installed the expected package bytes"
