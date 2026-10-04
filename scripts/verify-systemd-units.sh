#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d /tmp/ctf-hunter-systemd-verify.XXXXXX)
trap 'rm -rf -- "$test_root"' EXIT

capture_unit=$test_root/ctf-hunter-capture.service
daemon_unit=$test_root/ctf-hunterd.service
cp "$project_root/packaging/systemd/ctf-hunter-capture.service" "$capture_unit"
cp "$project_root/packaging/systemd/ctf-hunterd.service" "$daemon_unit"

# The source-tree check validates systemd syntax without requiring the package's
# executables or sysusers group to be installed on the CI host. The separate
# policy validator checks the untouched production values, and the package test
# verifies the installed units with their real paths and group.
sed -i \
    -e '/^Documentation=/d' \
    -e 's/^Group=ctf-hunter$/Group=root/' \
    -e 's#^ExecStart=/usr/libexec/ctf-hunter-capture .*#ExecStart=/bin/true#' \
    "$capture_unit"
sed -i \
    -e 's#^ExecStart=/usr/bin/ctf-hunterd .*#ExecStart=/bin/true#' \
    -e '/^ReadWritePaths=/d' \
    "$daemon_unit"

SYSTEMD_LOG_LEVEL=warning systemd-analyze verify "$capture_unit"
SYSTEMD_LOG_LEVEL=warning systemd-analyze --user verify "$daemon_unit"

echo "PASS: systemd unit syntax validated"
