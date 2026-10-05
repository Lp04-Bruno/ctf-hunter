#!/usr/bin/env python3
"""Validate CTF Hunter release identity and version consistency."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = ROOT / "release" / "metadata.toml"


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def cargo_packages(errors: list[str]) -> list[dict[str, Any]]:
    command = ["cargo", "metadata", "--locked", "--no-deps", "--format-version=1"]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        errors.append(f"cargo metadata failed: {result.stderr.strip()}")
        return []
    return json.loads(result.stdout)["packages"]


def expect(errors: list[str], label: str, actual: object, expected: object) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, found {actual!r}")


def main() -> int:
    errors: list[str] = []
    metadata = load_toml(METADATA_PATH)
    version = metadata["application_version"]
    debian_version = metadata["debian_version"]
    requested_debian_version = os.environ.get("CTF_HUNTER_DEBIAN_VERSION_OVERRIDE", "")
    effective_debian_version = debian_version
    if requested_debian_version:
        expect(
            errors,
            "Debian version override",
            requested_debian_version,
            metadata["debian_prerelease_example"],
        )
        effective_debian_version = requested_debian_version
    maintainer = f'{metadata["maintainer_name"]} <{metadata["maintainer_email"]}>'

    expect(
        errors,
        "derived Debian version",
        debian_version,
        f'{version}-{metadata["debian_revision"]}',
    )
    expect(errors, "package name", metadata["package_name"], "ctf-hunter")
    expect(errors, "architecture", metadata["architecture"], "amd64")
    expect(errors, "license", metadata["license"], "MIT OR Apache-2.0")
    expect(errors, "copyright holder", metadata["copyright_holder"], "Lp04-Bruno")
    expect(errors, "maintainer", maintainer, metadata["git_flow"]["tag_signing_identity"])
    release_branch = metadata["git_flow"]["release_branch"]
    if release_branch not in {f"release/{version}", f"hotfix/{version}"}:
        errors.append(
            "release branch: expected "
            f"'release/{version}' or 'hotfix/{version}', found {release_branch!r}"
        )
    expect(errors, "release tag", metadata["git_flow"]["release_tag"], f"v{version}")

    workspace = load_toml(ROOT / "Cargo.toml")["workspace"]["package"]
    expect(errors, "Cargo workspace version", workspace["version"], version)
    expect(errors, "Cargo workspace authors", workspace["authors"], [maintainer])
    expect(errors, "Cargo workspace license", workspace["license"], metadata["license"])
    expect(errors, "Cargo workspace repository", workspace["repository"], metadata["repository"])
    expect(errors, "minimum Rust version", workspace["rust-version"], metadata["platform"]["minimum_rust"])

    for package in cargo_packages(errors):
        name = package["name"]
        expect(errors, f"Cargo package {name} version", package["version"], version)
        expect(errors, f"Cargo package {name} authors", package["authors"], [maintainer])
        expect(errors, f"Cargo package {name} license", package["license"], metadata["license"])
        expect(errors, f"Cargo package {name} repository", package["repository"], metadata["repository"])

    package_json = load_json(ROOT / "ui" / "package.json")
    expect(errors, "npm package version", package_json["version"], version)
    expect(errors, "npm package license", package_json["license"], metadata["license"])
    expect(errors, "npm package author", package_json["author"], maintainer)
    expect(errors, "npm package homepage", package_json["homepage"], metadata["homepage"])
    expect(errors, "npm bug URL", package_json["bugs"]["url"], metadata["bug_reports"])

    package_lock = load_json(ROOT / "ui" / "package-lock.json")
    expect(errors, "npm lockfile version", package_lock["version"], version)
    expect(errors, "npm root lock entry version", package_lock["packages"][""]["version"], version)

    tauri = load_json(ROOT / "ui" / "src-tauri" / "tauri.conf.json")
    expect(errors, "Tauri version", tauri["version"], version)
    expect(errors, "Tauri product name", tauri["productName"], metadata["product_name"])
    expect(errors, "Tauri identifier", tauri["identifier"], metadata["desktop_identifier"])

    changelog = (ROOT / "debian" / "changelog").read_text(encoding="utf-8")
    first_line = changelog.splitlines()[0]
    match = re.fullmatch(r"ctf-hunter \(([^)]+)\) [^;]+; urgency=[a-z]+", first_line)
    if match is None:
        errors.append(f"Debian changelog header is invalid: {first_line!r}")
    else:
        expect(
            errors,
            "Debian changelog version",
            match.group(1),
            effective_debian_version,
        )

    migration_files = sorted((ROOT / "crates" / "hunter-database" / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))
    migration_versions = [int(path.name[:4]) for path in migration_files]
    expected_migrations = list(range(1, metadata["database"]["schema_generation"] + 1))
    expect(errors, "database schema generation", migration_versions, expected_migrations)

    mit_text = (ROOT / "LICENSE-MIT").read_text(encoding="utf-8")
    apache_text = (ROOT / "LICENSE-APACHE").read_text(encoding="utf-8")
    if "Copyright (c) 2026 Lp04-Bruno" not in mit_text:
        errors.append("LICENSE-MIT does not identify the confirmed copyright holder")
    if "Apache License" not in apache_text or "Version 2.0, January 2004" not in apache_text:
        errors.append("LICENSE-APACHE is not the Apache License 2.0 text")

    if metadata["apt_repository_enabled"]:
        apt_url = metadata.get("apt_repository_url", "")
        if not apt_url.startswith("https://"):
            errors.append("enabled APT publishing requires an HTTPS apt_repository_url")
        for field in ("apt_repository_origin", "apt_repository_label"):
            if not str(metadata.get(field, "")).strip():
                errors.append(f"enabled APT publishing requires {field}")

    if shutil.which("dpkg") is None:
        errors.append("dpkg is required to validate Debian version ordering")
    else:
        prerelease = metadata["debian_prerelease_example"]
        comparisons = ((prerelease, "lt", debian_version), (debian_version, "lt", f"{version}-2"))
        for left, relation, right in comparisons:
            result = subprocess.run(["dpkg", "--compare-versions", left, relation, right], check=False)
            if result.returncode != 0:
                errors.append(f"invalid Debian version ordering: {left} !{relation} {right}")

    if errors:
        print("Release metadata validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Release metadata valid: CTF Hunter {version}, Debian {effective_debian_version}, "
        f"schema {metadata['database']['schema_generation']}, {metadata['architecture']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
