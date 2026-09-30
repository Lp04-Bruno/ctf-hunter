#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package=${1:-$project_root/artifacts/bookworm/ctf-hunter_0.1.0-1_amd64.deb}
package=$(realpath "$package")
test -f "$package" || {
    echo "package not found: $package" >&2
    exit 1
}
if test "$(id -u)" -ne 0; then
    echo "Run this isolated systemd integration test with sudo." >&2
    exit 2
fi

rootfs=$(mktemp -d /var/tmp/ctf-hunter-systemd.XXXXXX)
machine=ctf-hunter-test-$$
nspawn_pid=

cleanup() {
    if machinectl show "$machine" >/dev/null 2>&1; then
        machinectl poweroff "$machine" >/dev/null 2>&1 || true
    fi
    if test -n "${nspawn_pid:-}"; then
        wait "$nspawn_pid" 2>/dev/null || true
    fi
    case "$rootfs" in
        /var/tmp/ctf-hunter-systemd.*) rm -rf -- "$rootfs" ;;
        *) echo "refusing to remove unexpected path: $rootfs" >&2 ;;
    esac
}
trap cleanup EXIT

debootstrap --variant=minbase \
    --include=systemd,systemd-sysv,dbus,dbus-user-session,ca-certificates \
    bookworm "$rootfs" https://deb.debian.org/debian
install -m 0644 "$package" "$rootfs/tmp/ctf-hunter.deb"

systemd-nspawn --quiet --directory="$rootfs" --machine="$machine" \
    --boot --notify-ready=yes >/tmp/ctf-hunter-systemd-nspawn.log 2>&1 &
nspawn_pid=$!

for _ in $(seq 1 120); do
    if test "$(machinectl show "$machine" --property=State --value 2>/dev/null || true)" = running; then
        break
    fi
    kill -0 "$nspawn_pid" 2>/dev/null || {
        sed -n '1,240p' /tmp/ctf-hunter-systemd-nspawn.log >&2
        echo "nspawn systemd instance exited during startup" >&2
        exit 1
    }
    sleep 0.25
done
test "$(machinectl show "$machine" --property=State --value)" = running

systemd-run --quiet --collect --wait --pipe --machine="$machine" \
    /bin/bash -o errexit -o nounset -o pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y /tmp/ctf-hunter.deb
        systemctl is-enabled --quiet ctf-hunter-capture.service
        systemctl is-active --quiet ctf-hunter-capture.service
        test -S /run/ctf-hunter/capture.sock
        test "$(stat -c %G /run/ctf-hunter/capture.sock)" = ctf-hunter
        systemctl restart ctf-hunter-capture.service
        systemctl is-active --quiet ctf-hunter-capture.service
        systemd-analyze verify /lib/systemd/system/ctf-hunter-capture.service
        systemd-analyze verify /usr/lib/systemd/user/ctf-hunterd.service

        useradd --create-home --uid 2000 --shell /bin/bash ctfhuntertest
        if id -nG ctfhuntertest | tr " " "\n" | grep -Fxq ctf-hunter; then
            echo "package unexpectedly enrolled a desktop user" >&2
            exit 1
        fi
        PKEXEC_UID=2000 /usr/libexec/ctf-hunter-enable-capture
        id -nG ctfhuntertest | tr " " "\n" | grep -Fxq ctf-hunter
        loginctl enable-linger ctfhuntertest
        systemctl start user@2000.service
        runuser -u ctfhuntertest -- env \
            XDG_RUNTIME_DIR=/run/user/2000 \
            DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/2000/bus \
            systemctl --user enable --now ctf-hunterd.service
        runuser -u ctfhuntertest -- env \
            XDG_RUNTIME_DIR=/run/user/2000 \
            DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/2000/bus \
            systemctl --user is-active --quiet ctf-hunterd.service
        systemctl restart ctf-hunter-capture.service
        systemctl is-active --quiet ctf-hunter-capture.service
    '

echo "PASS: Debian 12 systemd system/user service lifecycle validated"
