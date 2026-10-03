#!/usr/bin/env python3
"""Check immutable action pins and workflow permission separation."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
DEPENDABOT_PATH = ROOT / ".github" / "dependabot.yml"
RENOVATE_PATH = ROOT / "renovate.json"
EXPECTED = {
    "ci.yml",
    "package.yml",
    "release-candidate.yml",
    "release.yml",
    "publish-apt.yml",
}
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
    require(
        set(paths) == EXPECTED,
        f"workflow set must be exactly {sorted(EXPECTED)}",
        errors,
    )

    require(
        not DEPENDABOT_PATH.exists(),
        "Dependabot configuration must remain removed",
        errors,
    )
    try:
        renovate = json.loads(RENOVATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"Renovate configuration is invalid: {error}")
        renovate = {}
    require(
        renovate.get("baseBranchPatterns") == ["develop"],
        "Renovate must target only develop",
        errors,
    )
    require(
        renovate.get("enabledManagers") == ["github-actions"],
        "Renovate must remain limited to GitHub Actions",
        errors,
    )
    renovate_extends = renovate.get("extends", [])
    require(
        "config:recommended" in renovate_extends
        and "schedule:monthly" in renovate_extends,
        "Renovate must use recommended monthly updates",
        errors,
    )
    require(
        renovate.get("prConcurrentLimit") == 5,
        "Renovate PR limit must remain five",
        errors,
    )
    require(
        renovate.get("minimumReleaseAge") == "7 days",
        "Renovate release age must remain seven days",
        errors,
    )
    require(
        renovate.get("internalChecksFilter") == "strict",
        "Renovate release-age checks must be strict",
        errors,
    )
    require(
        renovate.get("automerge") is False,
        "Renovate must never automerge",
        errors,
    )
    require(
        renovate.get("semanticCommits") == "disabled",
        "Renovate must use plain commit titles",
        errors,
    )
    require(
        renovate.get("commitMessageAction") == "Update",
        "Renovate commit titles must start in English",
        errors,
    )

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

    package = contents.get("package.yml", "")
    require(
        "diffoscope disorderfs podman reprotest rsync" in package,
        "package validation lacks complete reprotest prerequisites",
        errors,
    )
    require(
        "scripts/reprotest-release.sh" in package,
        "package validation lacks the extended reprotest gate",
        errors,
    )

    release = contents.get("release.yml", "")
    require("tags:" in release and "- v*.*.*" in release, "release must be tag-only", errors)
    require("environment: release-signing" in release, "release signing is not environment-gated", errors)
    require("permissions: {}" in release, "release must deny permissions by default", errors)
    require("actions/attest@" in release, "release lacks GitHub attestation", errors)
    require("scripts/run-ci-gates.sh" in release, "release does not repeat complete quality gates", errors)
    release_quality = release.find("scripts/run-ci-gates.sh")
    release_cleanup = release.find("scripts/reclaim-release-space.sh")
    release_package = release.find("scripts/verify-reproducible-build.sh")
    require(
        -1 not in (release_quality, release_cleanup, release_package)
        and release_quality < release_cleanup < release_package,
        "release must reclaim source-gate artifacts before package builds",
        errors,
    )
    require("--draft" in release, "release workflow must create only a draft", errors)
    require("--clobber" not in release, "release assets must never be overwritten", errors)

    candidate = contents.get("release-candidate.yml", "")
    require(
        "push:" in candidate
        and "- release/0.1.0" in candidate
        and "pull_request:" not in candidate
        and "workflow_dispatch:" not in candidate,
        "release candidate must run only for release-branch pushes",
        errors,
    )
    require(
        "github.ref == 'refs/heads/release/0.1.0'" in candidate,
        "release candidate is not restricted to the release branch",
        errors,
    )
    require(
        "environment: release-candidate" in candidate,
        "release-candidate publication is not environment-gated",
        errors,
    )
    require(
        'test "$CTF_HUNTER_RC_STAGING" = enabled' in candidate,
        "release-candidate staging does not require the protected environment marker",
        errors,
    )
    require("permissions: {}" in candidate, "release candidate must deny permissions by default", errors)
    require("scripts/build-release-candidate.sh" in candidate, "release candidate uses no isolated RC build", errors)
    candidate_quality = candidate.find("scripts/run-ci-gates.sh")
    candidate_cleanup = candidate.find("scripts/reclaim-release-space.sh")
    candidate_package = candidate.find("scripts/build-release-candidate.sh")
    require(
        -1 not in (candidate_quality, candidate_cleanup, candidate_package)
        and candidate_quality < candidate_cleanup < candidate_package,
        "release candidate must reclaim source-gate artifacts before package builds",
        errors,
    )
    require("--draft --prerelease" in candidate, "release candidate is not staged as a draft prerelease", errors)
    require(
        'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"' in candidate
        and '-f ref="refs/tags/$tag"' in candidate
        and '-f sha="$GITHUB_SHA"' in candidate,
        "release candidate does not explicitly bind its RC tag to the workflow commit",
        errors,
    )
    require(
        "--verify-tag" in candidate,
        "release candidate draft does not require the preverified RC tag",
        errors,
    )
    require(
        '--json targetCommitish --jq .targetCommitish)" = "$GITHUB_SHA"' in candidate,
        "release candidate does not verify the draft target commit",
        errors,
    )
    require(
        'test "$tag_target" = "commit $GITHUB_SHA"' in candidate,
        "release candidate does not bind its RC tag to the validated commit",
        errors,
    )
    require("--clobber" not in candidate, "release-candidate assets must never be overwritten", errors)

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
