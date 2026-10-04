#!/usr/bin/env python3
"""Verify every mutable release tool against the Phase 10E lock file."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_environment() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / "release/build-environment.env").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            raise ValueError(f"invalid build-environment entry: {line!r}")
        values[key] = value
    return values


def output(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip()


def require(actual: str, expected: str, label: str, errors: list[str]) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, found {actual!r}")


def main() -> int:
    locked = load_environment()
    errors: list[str] = []

    require(output("rustc", "--version").split()[1], locked["RUST_STABLE"], "Rust stable", errors)
    nightly_version = output("rustup", "run", locked["RUST_NIGHTLY"], "rustc", "--version")
    require(
        nightly_version.split()[1],
        locked["RUST_NIGHTLY_VERSION"],
        "Rust nightly compiler",
        errors,
    )
    require(output("node", "--version").removeprefix("v"), locked["NODE_VERSION"], "Node.js", errors)
    require(output("npm", "--version"), locked["NPM_VERSION"], "npm", errors)
    linker_version = output("bpf-linker", "--version")
    match = re.search(r"([0-9]+(?:\.[0-9]+)+)", linker_version)
    require(match.group(1) if match else linker_version, locked["BPF_LINKER_VERSION"], "bpf-linker", errors)
    require(platform.machine(), "x86_64", "build architecture", errors)

    if os.environ.get("CTF_HUNTER_REQUIRE_BOOKWORM") == "1":
        os_release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator:
                os_release[key] = value.strip('"')
        require(os_release.get("ID", ""), "debian", "build distribution", errors)
        require(os_release.get("VERSION_CODENAME", ""), "bookworm", "build baseline", errors)

    if errors:
        print("Release toolchain validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "Release toolchain valid: "
        f"Rust {locked['RUST_STABLE']}, {locked['RUST_NIGHTLY']}, "
        f"Node.js {locked['NODE_VERSION']}, npm {locked['NPM_VERSION']}, "
        f"bpf-linker {locked['BPF_LINKER_VERSION']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
