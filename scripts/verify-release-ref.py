#!/usr/bin/env python3
"""Validate that a release tag is an annotated tag on the master merge."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    args = parser.parse_args()
    with (ROOT / "release" / "metadata.toml").open("rb") as handle:
        metadata = tomllib.load(handle)

    errors: list[str] = []
    expected_tag = metadata["git_flow"]["release_tag"]
    production_branch = metadata["git_flow"]["production_branch"]
    tag_ref = f"refs/tags/{args.tag}"

    if args.tag != expected_tag:
        errors.append(f"expected release tag {expected_tag}, received {args.tag}")

    object_type = git("cat-file", "-t", tag_ref, check=False)
    if object_type.returncode != 0:
        errors.append(f"tag does not exist: {args.tag}")
        commit = ""
    elif object_type.stdout.strip() != "tag":
        errors.append("release tag must be annotated, not lightweight")
        commit = git("rev-parse", tag_ref, check=False).stdout.strip()
    else:
        commit = git("rev-parse", f"{tag_ref}^{{commit}}").stdout.strip()
        tagger = git(
            "for-each-ref",
            "--format=%(taggername) %(taggeremail)",
            tag_ref,
        ).stdout.strip()
        if tagger != metadata["git_flow"]["tag_signing_identity"]:
            errors.append(
                "tagger identity differs from the frozen release signing identity"
            )

    github_sha = os.environ.get("GITHUB_SHA", "")
    if commit and github_sha:
        tag_object = git("rev-parse", tag_ref).stdout.strip()
        if github_sha not in {commit, tag_object}:
            errors.append("workflow SHA is not the tagged release commit")

    if commit:
        parents = git("show", "-s", "--format=%P", commit).stdout.split()
        if len(parents) != 2:
            errors.append("release tag must point to an explicit two-parent merge commit")

        production_refs = (
            f"refs/remotes/origin/{production_branch}",
            f"refs/heads/{production_branch}",
        )
        available_ref = next(
            (
                ref
                for ref in production_refs
                if git("show-ref", "--verify", "--quiet", ref, check=False).returncode == 0
            ),
            None,
        )
        if available_ref is None:
            errors.append(f"production branch ref is unavailable: {production_branch}")
        elif (
            git("merge-base", "--is-ancestor", commit, available_ref, check=False).returncode
            != 0
        ):
            errors.append(f"tagged commit is not contained in {production_branch}")

    if errors:
        print("Release reference validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Release reference valid: {args.tag} -> {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
