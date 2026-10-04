#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 SBOM for the exact Debian package."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent.parent


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def spdx_id(kind: str, name: str, version: str = "") -> str:
    digest = hashlib.sha256(f"{kind}\0{name}\0{version}".encode()).hexdigest()[:16]
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-.") or "component"
    return f"SPDXRef-{kind}-{safe[:48]}-{digest}"


def package_component(
    ecosystem: str,
    name: str,
    version: str,
    download: str,
    purl_type: str,
) -> dict[str, object]:
    component: dict[str, object] = {
        "name": name,
        "SPDXID": spdx_id(ecosystem, name, version),
        "versionInfo": version,
        "downloadLocation": download,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
    }
    if version:
        component["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": (
                    f"pkg:{purl_type}/{quote(name, safe='@/') }@{quote(version, safe='.+:~')}"
                ),
            }
        ]
    return component


def cargo_components() -> list[dict[str, object]]:
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    components = []
    for package in lock.get("package", []):
        name = package["name"]
        version = package["version"]
        source = package.get("source", "NOASSERTION")
        components.append(package_component("Cargo", name, version, source, "cargo"))
    return components


def npm_components() -> list[dict[str, object]]:
    lock = json.loads((ROOT / "ui" / "package-lock.json").read_text())
    components = []
    for path, package in sorted(lock.get("packages", {}).items()):
        if not path or "version" not in package:
            continue
        name = package.get("name")
        if not name:
            marker = "node_modules/"
            name = path.rsplit(marker, 1)[-1]
        version = str(package["version"])
        download = package.get("resolved", "NOASSERTION")
        components.append(package_component("Npm", name, version, download, "npm"))
    return components


def debian_components(package: Path) -> list[dict[str, object]]:
    depends = subprocess.run(
        ["dpkg-deb", "--field", package, "Depends"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    components = []
    for clause in depends.split(","):
        alternative = clause.strip().split("|", 1)[0].strip()
        match = re.fullmatch(r"([A-Za-z0-9+.-]+)(?::[A-Za-z0-9-]+)?(?:\s+\(([^)]+)\))?", alternative)
        if not match:
            raise ValueError(f"cannot parse Debian dependency: {alternative!r}")
        name, constraint = match.groups()
        version = constraint or "unspecified"
        components.append(package_component("Deb", name, version, "NOASSERTION", "deb/debian"))
    return components


def package_files(package: Path) -> list[dict[str, object]]:
    archive = subprocess.run(
        ["dpkg-deb", "--fsys-tarfile", package], check=True, capture_output=True
    ).stdout
    files = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as payload:
        for member in payload.getmembers():
            if not member.isfile():
                continue
            extracted = payload.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            normalized = member.name.removeprefix("./")
            files.append(
                {
                    "fileName": f"/{normalized}",
                    "SPDXID": spdx_id("File", normalized),
                    "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(data)}],
                    "licenseConcluded": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                }
            )
    return sorted(files, key=lambda item: str(item["fileName"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    package = args.package.resolve()
    output = args.output.resolve()
    package_bytes = package.read_bytes()
    package_hash = sha256(package_bytes)
    metadata = tomllib.loads((ROOT / "release" / "metadata.toml").read_text())
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    if epoch <= 0:
        raise SystemExit("SOURCE_DATE_EPOCH must be a positive Unix timestamp")
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    app_id = "SPDXRef-Package-CTF-Hunter"
    app = {
        "name": metadata["product_name"],
        "SPDXID": app_id,
        "versionInfo": metadata["debian_version"],
        "packageFileName": package.name,
        "downloadLocation": f"{metadata['repository']}/releases/tag/{metadata['git_flow']['release_tag']}",
        "filesAnalyzed": True,
        "checksums": [{"algorithm": "SHA256", "checksumValue": package_hash}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": metadata["license"],
        "copyrightText": f"Copyright {metadata['copyright_year']} {metadata['copyright_holder']}",
        "supplier": f"Person: {metadata['maintainer_name']} ({metadata['maintainer_email']})",
        "homepage": metadata["homepage"],
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": (
                    f"pkg:deb/debian/{metadata['package_name']}@{metadata['debian_version']}"
                    f"?arch={metadata['architecture']}"
                ),
            }
        ],
    }

    components_by_id: dict[str, dict[str, object]] = {}
    for component in cargo_components() + npm_components() + debian_components(package):
        components_by_id[str(component["SPDXID"])] = component
    components = [components_by_id[key] for key in sorted(components_by_id)]
    files = package_files(package)
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": app_id,
        }
    ]
    relationships.extend(
        {
            "spdxElementId": app_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": component["SPDXID"],
        }
        for component in components
    )
    relationships.extend(
        {
            "spdxElementId": app_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": file["SPDXID"],
        }
        for file in files
    )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ctf-hunter-{metadata['debian_version']}",
        "documentNamespace": (
            f"{metadata['repository']}/releases/{metadata['application_version']}"
            f"/spdx/{package_hash}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: ctf-hunter-generate-spdx-sbom"],
            "licenseListVersion": "3.25",
        },
        "packages": [app, *components],
        "files": files,
        "relationships": relationships,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(
        f"SPDX SBOM generated: {output.name} "
        f"({len(components)} dependencies, {len(files)} packaged files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
