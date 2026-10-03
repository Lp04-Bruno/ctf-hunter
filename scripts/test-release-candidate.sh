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
artifact_dir=${1:-$project_root/artifacts/release-candidate/build-a}
artifact_dir=$(realpath "$artifact_dir")
package=$artifact_dir/ctf-hunter_${candidate_version}_amd64.deb

test -f "$package" || {
    echo "release-candidate package not found: $package" >&2
    exit 1
}

python3 "$project_root/scripts/verify-debian-package.py" \
    --expected-version "$candidate_version" "$package"
python3 "$project_root/scripts/verify-release-artifacts.py" "$artifact_dir"
"$project_root/scripts/test-package-lifecycle.sh" "$package"
"$project_root/scripts/test-btf-failures.sh" "$package"

echo "PASS: release candidate passed Debian 12, Kali, and BTF package gates"
