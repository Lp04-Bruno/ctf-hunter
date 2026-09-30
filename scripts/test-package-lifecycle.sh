#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"

package=${1:-$project_root/artifacts/bookworm/ctf-hunter_0.1.0-1_amd64.deb}
target=${2:-all}
package=$(realpath "$package")
test -f "$package" || {
    echo "package not found: $package" >&2
    exit 1
}

run_suite() {
    local image=$1
    local label=$2
    echo "=== $label package lifecycle ==="
    "$project_root/scripts/podman-release.sh" run --rm \
        --security-opt label=disable \
        --volume "$package:/packages/ctf-hunter.deb:ro" \
        --volume "$project_root/scripts/package-lifecycle-test.sh:/test/package-lifecycle-test.sh:ro" \
        "$image" \
        /bin/bash /test/package-lifecycle-test.sh /packages/ctf-hunter.deb "$label"
}

case "$target" in
    all)
        run_suite "$DEBIAN_IMAGE" "Debian 12"
        run_suite "$KALI_IMAGE" "Kali Rolling"
        ;;
    debian) run_suite "$DEBIAN_IMAGE" "Debian 12" ;;
    kali) run_suite "$KALI_IMAGE" "Kali Rolling" ;;
    *)
        echo "usage: test-package-lifecycle.sh [PACKAGE] [all|debian|kali]" >&2
        exit 2
        ;;
esac
