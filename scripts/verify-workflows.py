#!/usr/bin/env python3
"""Check immutable action pins and workflow permission separation."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
EXPECTED = {"ci.yml", "package.yml", "release.yml", "publish-apt.yml"}
ALLOWED_ACTIONS = {
    "actions/checkout": "9f698171ed81b15d1823a05fc7211befd50c8ae0",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
    "actions/attest": "508db95dd578ae2727ebd6217d5ba78e4fbda05d",
}


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []
    paths = {path.name: path for path in WORKFLOW_DIR.glob("*.yml")}
    require(set(paths) == EXPECTED, f"workflow set must be exactly {sorted(EXPECTED)}", errors)

    contents: dict[str, str] = {}
    action_pattern = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
    for name, path in sorted(paths.items()):
        text = path.read_text(encoding="utf-8")
        contents[name] = text
        require("pull_request_target:" not in text, f"{name} uses pull_request_target", errors)
        for action, reference in action_pattern.findall(text):
            require(
                re.fullmatch(r"[0-9a-f]{40}", reference) is not None,
                f"{name}: {action} is not pinned to a full commit SHA",
                errors,
            )
            expected = ALLOWED_ACTIONS.get(action)
            require(expected is not None, f"{name}: unreviewed external action {action}", errors)
            if expected is not None:
                require(
                    reference == expected,
                    f"{name}: {action} pin differs from the reviewed commit",
                    errors,
                )

    for name in ("ci.yml", "package.yml"):
        text = contents.get(name, "")
        require("${{ secrets." not in text, f"{name} must not access secrets", errors)
        require("contents: write" not in text, f"{name} must not write repository contents", errors)
        require("id-token: write" not in text, f"{name} must not mint OIDC tokens", errors)
        require("attestations: write" not in text, f"{name} must not publish attestations", errors)

    release = contents.get("release.yml", "")
    require("tags:" in release and "- v*.*.*" in release, "release must be tag-only", errors)
    require("environment: release-signing" in release, "release signing is not environment-gated", errors)
    require("permissions: {}" in release, "release must deny permissions by default", errors)
    require("actions/attest@" in release, "release lacks GitHub attestation", errors)
    require("scripts/run-ci-gates.sh" in release, "release does not repeat complete quality gates", errors)
    require("--draft" in release, "release workflow must create only a draft", errors)
    require("--clobber" not in release, "release assets must never be overwritten", errors)

    apt = contents.get("publish-apt.yml", "")
    require("pull_request:" not in apt and "push:" not in apt, "APT publication must be manual-only", errors)
    require("environment: apt-testing" in apt, "APT testing is not environment-gated", errors)
    require("environment: apt-stable" in apt, "APT stable is not environment-gated", errors)
    require("needs: publish-testing" in apt, "stable promotion does not depend on testing", errors)
    for forbidden in ("build-bookworm-package", "build-release-container", "cargo build", "dpkg-buildpackage"):
        require(forbidden not in apt, f"APT publication attempts to rebuild via {forbidden}", errors)
    for line in apt.splitlines():
        if "${{ inputs." not in line:
            continue
        stripped = line.strip()
        safe_mapping = re.fullmatch(r"[A-Z][A-Z0-9_]*:\s*\$\{\{ inputs\.[a-z0-9_]+ \}\}", stripped)
        safe_condition = stripped.startswith("if:")
        require(
            safe_mapping is not None or safe_condition,
            "manual workflow input is interpolated outside an env mapping or condition",
            errors,
        )

    if errors:
        print("Workflow policy validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    action_count = sum(len(action_pattern.findall(text)) for text in contents.values())
    print(f"Workflow policy valid: {len(paths)} workflows, {action_count} immutable action references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
