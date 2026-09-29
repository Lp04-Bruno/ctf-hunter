#!/usr/bin/env python3
"""Prove that a release capture helper contains its complete eBPF ELF."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture_helper", type=Path)
    parser.add_argument("cargo_build_directory", type=Path)
    args = parser.parse_args()

    helper = args.capture_helper.read_bytes()
    if not helper.startswith(b"\x7fELF"):
        parser.error(f"capture helper is not an ELF file: {args.capture_helper}")

    candidates = sorted(
        args.cargo_build_directory.glob("ctf-hunter-capture-*/out/ctf-hunter-ebpf")
    )
    if not candidates:
        parser.error("Cargo produced no ctf-hunter-ebpf build artifact")

    matches: list[tuple[Path, bytes]] = []
    for candidate in candidates:
        payload = candidate.read_bytes()
        if payload.startswith(b"\x7fELF") and payload in helper:
            matches.append((candidate, payload))

    if len(matches) != 1:
        parser.error(
            f"expected exactly one complete embedded eBPF artifact, found {len(matches)}"
        )

    candidate, payload = matches[0]
    digest = hashlib.sha256(payload).hexdigest()
    print(
        f"embedded eBPF verified: {candidate} ({len(payload)} bytes, sha256={digest})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
