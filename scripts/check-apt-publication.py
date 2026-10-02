#!/usr/bin/env python3
"""Fail closed until the signed APT publication contract is provisioned."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    with (ROOT / "release" / "metadata.toml").open("rb") as handle:
        metadata = tomllib.load(handle)

    errors: list[str] = []
    if not metadata.get("apt_repository_enabled", False):
        errors.append("APT publication is disabled in release/metadata.toml")
    repository_url = str(metadata.get("apt_repository_url", ""))
    if not repository_url.startswith("https://"):
        errors.append("apt_repository_url must be an HTTPS URL")
    if args.tag != metadata["git_flow"]["release_tag"]:
        errors.append("requested tag does not match the frozen release tag")
    if re.fullmatch(r"[0-9a-f]{64}", args.sha256) is None:
        errors.append("expected package SHA-256 must be 64 lowercase hexadecimal characters")

    for field in ("apt_repository_origin", "apt_repository_label"):
        if not str(metadata.get(field, "")).strip():
            errors.append(f"{field} is not configured")

    if errors:
        print("APT publication preflight failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"APT publication enabled for {repository_url} and {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
