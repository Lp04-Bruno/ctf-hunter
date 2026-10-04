#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
candidate_version=$(python3 - "$project_root/release/metadata.toml" <<'PY'
from pathlib import Path
import sys
import tomllib

print(tomllib.loads(Path(sys.argv[1]).read_text())["debian_prerelease_example"])
PY
)
package=${1:-$project_root/artifacts/release-candidate/build-a/ctf-hunter_${candidate_version}_amd64.deb}
package=$(realpath "$package")

if test "$(id -u)" -ne 0 || test -z "${SUDO_USER:-}" || test "$SUDO_USER" = root; then
    echo "Run this host-kernel acceptance test as a regular user through sudo." >&2
    exit 2
fi

"$project_root/scripts/test-package-systemd.sh" "$package"
"$project_root/scripts/test-packaged-capture.exp" "$package"
"$project_root/scripts/test-packaged-daemon-capture.exp" "$package"

echo "PASS: release candidate passed booted-systemd and packaged capture gates"
