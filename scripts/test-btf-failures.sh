#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"
package=${1:-$project_root/artifacts/bookworm/ctf-hunter_0.1.1-1_amd64.deb}
package=$(realpath "$package")
test -f "$package" || {
    echo "package not found: $package" >&2
    exit 1
}

test_root=$(mktemp -d /tmp/ctf-hunter-btf.XXXXXX)
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/missing"
printf 'not kernel BTF\n' >"$test_root/incompatible"

run_failure() {
    local source=$1
    local destination=$2
    local expected=$3
    local label=$4
    local output=$test_root/output

    set +e
    "$project_root/scripts/podman-release.sh" run --rm \
        --security-opt label=disable \
        --volume "$package:/tmp/ctf-hunter.deb:ro" \
        --volume "$source:$destination:ro" \
        "$DEBIAN_IMAGE" \
        /bin/bash -o errexit -o nounset -o pipefail -c \
        'dpkg-deb --extract /tmp/ctf-hunter.deb /tmp/package && /tmp/package/usr/libexec/ctf-hunter-capture preflight' \
        >"$output" 2>&1
    status=$?
    set -e
    test "$status" -ne 0 || {
        cat "$output" >&2
        echo "FAIL: $label unexpectedly passed" >&2
        exit 1
    }
    grep -Eiq "$expected" "$output" || {
        cat "$output" >&2
        echo "FAIL: $label did not produce an actionable BTF diagnostic" >&2
        exit 1
    }
    echo "PASS: $label fails closed"
}

run_failure "$test_root/missing" /sys/kernel/btf 'BTF|No such file|load kernel' 'missing kernel BTF'
run_failure "$test_root/incompatible" /sys/kernel/btf/vmlinux 'BTF|magic|header|load kernel' 'incompatible kernel BTF'
