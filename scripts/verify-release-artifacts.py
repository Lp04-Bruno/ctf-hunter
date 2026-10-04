#!/usr/bin/env python3
"""Verify release checksums, SPDX binding, and optional OpenPGP signature."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    args = parser.parse_args()
    artifact_dir = args.artifact_dir.resolve()
    errors: list[str] = []
    manifest = artifact_dir / "SHA256SUMS"
    package_names = sorted(
        path.name
        for path in artifact_dir.glob("ctf-hunter_*_amd64.deb")
        if not path.name.startswith("ctf-hunter-dbgsym_")
    )
    if len(package_names) == 1:
        package_name = package_names[0]
        sbom_name = f"{package_name.removesuffix('.deb')}.spdx.json"
    else:
        package_name = ""
        sbom_name = ""
        errors.append("expected exactly one primary Debian package")
    package = artifact_dir / package_name
    sbom_path = artifact_dir / sbom_name

    if not manifest.is_file():
        errors.append("SHA256SUMS is missing")
        entries = {}
    else:
        entries = {}
        for line in manifest.read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if not match:
                errors.append(f"invalid SHA256SUMS line: {line!r}")
                continue
            checksum, name = match.groups()
            if name in entries:
                errors.append(f"duplicate checksum entry: {name}")
                continue
            entries[name] = checksum
        if list(entries) != sorted(entries):
            errors.append("SHA256SUMS entries are not sorted")
        for name, expected in entries.items():
            path = artifact_dir / name
            if not path.is_file():
                errors.append(f"checksummed artifact is missing: {name}")
            elif digest(path) != expected:
                errors.append(f"checksum mismatch: {name}")

    for required in (package_name, sbom_name):
        if not required:
            continue
        if required not in entries:
            errors.append(f"SHA256SUMS does not cover {required}")

    if package.is_file() and sbom_path.is_file():
        sbom = json.loads(sbom_path.read_text())
        if sbom.get("spdxVersion") != "SPDX-2.3":
            errors.append("SBOM is not SPDX 2.3")
        described = [
            relationship.get("relatedSpdxElement")
            for relationship in sbom.get("relationships", [])
            if relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and relationship.get("relationshipType") == "DESCRIBES"
        ]
        packages = {
            item.get("SPDXID"): item for item in sbom.get("packages", [])
        }
        if len(described) != 1 or described[0] not in packages:
            errors.append("SBOM does not describe exactly one release package")
        else:
            app = packages[described[0]]
            checksums = {
                item.get("algorithm"): item.get("checksumValue")
                for item in app.get("checksums", [])
            }
            if checksums.get("SHA256") != digest(package):
                errors.append("SBOM is not bound to the exact Debian package")
        component_names = {
            str(item.get("SPDXID", "")) for item in sbom.get("packages", [])
        }
        if not any(name.startswith("SPDXRef-Cargo-") for name in component_names):
            errors.append("SBOM has no Cargo dependencies")
        if not any(name.startswith("SPDXRef-Npm-") for name in component_names):
            errors.append("SBOM has no npm dependencies")
        if not any(name.startswith("SPDXRef-Deb-") for name in component_names):
            errors.append("SBOM has no Debian runtime dependencies")
        if not sbom.get("files"):
            errors.append("SBOM has no packaged-file inventory")

    signature = artifact_dir / "SHA256SUMS.asc"
    if signature.is_file():
        verification = subprocess.run(
            ["gpg", "--batch", "--verify", signature, manifest],
            capture_output=True,
            text=True,
        )
        if verification.returncode != 0:
            errors.append(f"OpenPGP signature verification failed: {verification.stderr.strip()}")
    elif args.require_signature:
        errors.append("SHA256SUMS.asc is missing")

    if errors:
        print("Release artifact verification failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    signature_status = "verified" if signature.is_file() else "not present (pre-release)"
    print(f"Release artifacts valid: {len(entries)} checksums; signature {signature_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
