#!/usr/bin/env python3
"""Decide whether a pull request needs the complete native quality matrix."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FAST_ONLY_PATTERNS = (
    re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"),
    re.compile(r"^\.github/CODEOWNERS$"),
    re.compile(r"^renovate\.json$"),
    re.compile(r"^docs/"),
    re.compile(r"^(README\.md|LICENSE-[A-Z0-9-]+)$"),
    re.compile(r"^scripts/(ci-change-scope|verify-workflows)\.py$"),
    re.compile(r"^scripts/tests/"),
)


def requires_native(paths: list[str]) -> bool:
    if not paths:
        return True
    return any(
        not any(pattern.search(path) for pattern in FAST_ONLY_PATTERNS)
        for path in paths
    )


def changed_paths(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", base, head],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    return [line for line in result.stdout.splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args()
    try:
        paths = changed_paths(args.base, args.head)
    except RuntimeError as error:
        print(f"change-scope detection failed: {error}", file=sys.stderr)
        print("run_native=true")
        return 0

    run_native = requires_native(paths)
    print(f"run_native={'true' if run_native else 'false'}")
    classification = "complete native gates" if run_native else "policy-only gates"
    print(
        f"CI scope: {classification} for {len(paths)} changed path(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
