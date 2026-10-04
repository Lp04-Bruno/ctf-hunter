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

export CTF_HUNTER_DEBIAN_VERSION_OVERRIDE=$candidate_version
export REPRODUCIBLE_SUBDIRECTORY=release-candidate

"$project_root/scripts/verify-reproducible-build.sh"
artifact_dir=$project_root/artifacts/$REPRODUCIBLE_SUBDIRECTORY/build-a
"$project_root/scripts/create-release-artifacts.sh" "$artifact_dir"
python3 "$project_root/scripts/verify-release-artifacts.py" "$artifact_dir"
python3 "$project_root/scripts/verify-debian-package.py" \
    --expected-version "$candidate_version" \
    "$artifact_dir/ctf-hunter_${candidate_version}_amd64.deb"

printf 'Release candidate: %s\n' \
    "$artifact_dir/ctf-hunter_${candidate_version}_amd64.deb"
sha256sum "$artifact_dir/ctf-hunter_${candidate_version}_amd64.deb"
echo "PASS: reproducible release-candidate artifacts created"
