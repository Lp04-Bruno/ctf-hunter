#!/usr/bin/env python3
"""Validate the Phase 10C service, group, and authorization contracts."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []
    capture_unit = (ROOT / "packaging/systemd/ctf-hunter-capture.service").read_text()
    daemon_unit = (ROOT / "packaging/systemd/ctf-hunterd.service").read_text()
    rules = (ROOT / "debian/rules").read_text()
    control = (ROOT / "debian/control").read_text()
    packaged_sysusers = (ROOT / "debian/ctf-hunter.sysusers").read_text()
    source_sysusers = (ROOT / "packaging/sysusers/ctf-hunter.conf").read_text()

    require(
        packaged_sysusers == source_sysusers == "g ctf-hunter - -\n",
        "sysusers definitions must agree and create only the ctf-hunter group",
        errors,
    )
    for setting in (
        "User=root",
        "Group=ctf-hunter",
        "AmbientCapabilities=CAP_BPF CAP_PERFMON",
        "CapabilityBoundingSet=CAP_BPF CAP_PERFMON",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX",
        "SystemCallFilter=@system-service bpf",
    ):
        require(setting in capture_unit, f"capture unit is missing {setting}", errors)
    require("WantedBy=multi-user.target" in capture_unit, "capture unit is not enabled system-wide", errors)
    require("User=root" not in daemon_unit, "user daemon must not declare root execution", errors)
    require("WantedBy=default.target" in daemon_unit, "user daemon is not enabled for desktop sessions", errors)
    require("UMask=0077" in daemon_unit, "user daemon must retain a private umask", errors)
    require(
        "RuntimeDirectory=ctf-hunter" in daemon_unit,
        "user daemon must create its runtime directory before namespace setup",
        errors,
    )
    require(
        "RuntimeDirectoryMode=0700" in daemon_unit,
        "user daemon runtime directory must remain private",
        errors,
    )

    for integration in (
        "dh_installsystemd --restart-after-upgrade ctf-hunter-capture.service",
        "dh_installsystemduser ctf-hunterd.service",
        "dh_installsysusers",
    ):
        require(integration in rules, f"debian/rules is missing: {integration}", errors)
    require("pkexec" in control, "binary package must depend on pkexec for guided setup", errors)

    policy_path = ROOT / "packaging/polkit/dev.ctfhunter.enable-capture.policy"
    try:
        policy = ET.parse(policy_path).getroot()
    except ET.ParseError as error:
        errors.append(f"polkit policy is not valid XML: {error}")
    else:
        action = policy.find("./action[@id='dev.ctfhunter.enable-capture']")
        require(action is not None, "polkit action identifier is missing", errors)
        if action is not None:
            annotations = {
                item.attrib.get("key"): (item.text or "").strip()
                for item in action.findall("annotate")
            }
            require(
                annotations.get("org.freedesktop.policykit.exec.path")
                == "/usr/libexec/ctf-hunter-enable-capture",
                "polkit action must authorize only the fixed-purpose setup helper",
                errors,
            )
            require(
                action.findtext("./defaults/allow_active") == "auth_admin",
                "active sessions must require administrator authentication",
                errors,
            )
            require(
                action.findtext("./defaults/allow_any") == "no"
                and action.findtext("./defaults/allow_inactive") == "no",
                "inactive and remote sessions must not receive setup authorization",
                errors,
            )

    if errors:
        print("Service lifecycle validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Service lifecycle contract valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
