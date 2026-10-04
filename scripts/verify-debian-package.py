#!/usr/bin/env python3
"""Validate the Phase 10B CTF Hunter Debian binary package."""

from __future__ import annotations

import argparse
import io
import subprocess
import tarfile
import tomllib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
with (PROJECT_ROOT / "release" / "metadata.toml").open("rb") as metadata_file:
    RELEASE_METADATA = tomllib.load(metadata_file)

EXPECTED_FIELDS = {
    "Package": RELEASE_METADATA["package_name"],
    "Architecture": RELEASE_METADATA["architecture"],
}

REQUIRED_MODES = {
    "./usr/bin/ctf-hunter": 0o755,
    "./usr/bin/ctf-hunterctl": 0o755,
    "./usr/bin/ctf-hunterd": 0o755,
    "./usr/libexec/ctf-hunter-capture": 0o755,
    "./usr/libexec/ctf-hunter-enable-capture": 0o755,
    "./lib/systemd/system/ctf-hunter-capture.service": 0o644,
    "./usr/lib/systemd/user/ctf-hunterd.service": 0o644,
    "./usr/lib/sysusers.d/ctf-hunter.conf": 0o644,
    "./usr/share/polkit-1/actions/dev.ctfhunter.enable-capture.policy": 0o644,
    "./usr/share/applications/dev.ctfhunter.desktop": 0o644,
    "./usr/share/man/man1/ctf-hunter.1.gz": 0o644,
    "./usr/share/man/man1/ctf-hunterctl.1.gz": 0o644,
    "./usr/share/man/man1/ctf-hunterd.1.gz": 0o644,
    "./usr/share/man/man8/ctf-hunter-capture.8.gz": 0o644,
    "./usr/share/man/man8/ctf-hunter-enable-capture.8.gz": 0o644,
    "./usr/share/metainfo/dev.ctfhunter.desktop.metainfo.xml": 0o644,
}

ICON_PATHS = {
    f"./usr/share/icons/hicolor/{size}x{size}/apps/dev.ctfhunter.desktop.png"
    for size in (48, 128, 256, 512)
}


def field(package: Path, name: str) -> str:
    return subprocess.run(
        ["dpkg-deb", "--field", package, name],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    parser.add_argument(
        "--expected-version", default=RELEASE_METADATA["debian_version"]
    )
    args = parser.parse_args()
    package = args.package.resolve()
    errors: list[str] = []

    expected_fields = {**EXPECTED_FIELDS, "Version": args.expected_version}

    for name, expected in expected_fields.items():
        actual = field(package, name)
        if actual != expected:
            errors.append(f"{name}: expected {expected!r}, found {actual!r}")

    depends = field(package, "Depends")
    if not depends or "${" in depends:
        errors.append(f"unresolved or empty Depends field: {depends!r}")
    for dependency in ("libc6", "libwebkit2gtk-4.1", "pkexec", "systemd"):
        if dependency not in depends:
            errors.append(f"dynamic dependency was not derived: {dependency}")

    archive = subprocess.run(
        ["dpkg-deb", "--fsys-tarfile", package], check=True, capture_output=True
    ).stdout
    members: dict[str, tarfile.TarInfo] = {}
    capture_payload = b""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as payload:
        for member in payload.getmembers():
            members[member.name] = member
            if member.name == "./usr/libexec/ctf-hunter-capture":
                extracted = payload.extractfile(member)
                if extracted is not None:
                    capture_payload = extracted.read()

    sysusers = members.get("./usr/lib/sysusers.d/ctf-hunter.conf")
    if sysusers is not None:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as payload:
            extracted = payload.extractfile(sysusers)
            if extracted is None or extracted.read() != b"g ctf-hunter - -\n":
                errors.append("sysusers declaration does not create exactly the capture group")

    for path, expected_mode in REQUIRED_MODES.items():
        member = members.get(path)
        if member is None:
            errors.append(f"required package path is missing: {path}")
            continue
        if member.mode != expected_mode:
            errors.append(
                f"{path}: expected mode {expected_mode:o}, found {member.mode:o}"
            )

    for path in ICON_PATHS:
        member = members.get(path)
        if member is None:
            errors.append(f"required icon is missing: {path}")
        elif member.mode != 0o644:
            errors.append(f"{path}: expected mode 644, found {member.mode:o}")

    for member in members.values():
        if member.uid != 0 or member.gid != 0:
            errors.append(
                f"{member.name}: expected root ownership, found {member.uid}:{member.gid}"
            )
        lowered = member.name.lower()
        if "ctf-hunter-ebpf" in lowered or lowered.endswith((".bpf.o", ".ebpf", ".o")):
            errors.append(f"standalone eBPF/object payload is prohibited: {member.name}")

    if capture_payload.count(b"\x7fELF") < 2:
        errors.append("packaged capture helper does not contain an embedded ELF payload")

    control_archive = subprocess.run(
        ["dpkg-deb", "--ctrl-tarfile", package], check=True, capture_output=True
    ).stdout
    control_files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(control_archive), mode="r:") as control:
        for member in control.getmembers():
            if member.isfile():
                extracted = control.extractfile(member)
                if extracted is not None:
                    control_files[member.name] = extracted.read()

    postinst = control_files.get("./postinst", b"").decode(errors="replace")
    if "systemd-sysusers" not in postinst or "ctf-hunter.conf" not in postinst:
        errors.append("postinst does not integrate the ctf-hunter sysusers declaration")
    for unit in ("ctf-hunter-capture.service", "ctf-hunterd.service"):
        if unit not in postinst:
            errors.append(f"postinst does not integrate {unit}")
    if "SUDO_USER" in postinst or "usermod" in postinst:
        errors.append("maintainer scripts must not infer or modify a desktop account")
    for name in ("./postinst", "./prerm", "./postrm"):
        script = control_files.get(name)
        if script is None:
            errors.append(f"generated maintainer script is missing: {name}")
            continue
        syntax = subprocess.run(["sh", "-n"], input=script, capture_output=True)
        if syntax.returncode != 0:
            errors.append(f"generated maintainer script has invalid shell syntax: {name}")

    if errors:
        print("Debian package validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"Debian package valid: {package.name}")
    print(f"Depends: {depends}")
    print(f"Payload entries: {len(members)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
