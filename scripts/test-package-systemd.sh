#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package=${1:-$project_root/artifacts/bookworm/ctf-hunter_0.1.1-1_amd64.deb}
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
chmod 0755 "$rootfs"
nspawn_log=/tmp/ctf-hunter-systemd-nspawn.log
machine=ctf-hunter-test-$$

cleanup() {
    case "$rootfs" in
        /var/tmp/ctf-hunter-systemd.*) rm -rf -- "$rootfs" ;;
        *) echo "refusing to remove unexpected path: $rootfs" >&2 ;;
    esac
}
trap cleanup EXIT

debootstrap --variant=minbase \
    --include=systemd,systemd-sysv,dbus,dbus-user-session,ca-certificates \
    bookworm "$rootfs" https://deb.debian.org/debian
install -m 0644 "$package" "$rootfs/root/ctf-hunter.deb"

install -D -m 0755 /dev/stdin \
    "$rootfs/usr/local/sbin/ctf-hunter-package-systemd-test" <<'TEST_SCRIPT'
#!/bin/bash
set -euxo pipefail

result=/var/tmp/ctf-hunter-package-systemd-test.result
finish() {
    status=$?
    trap - EXIT
    printf '%s\n' "$status" >"$result"
    sync
    systemctl --no-block poweroff >/dev/null 2>&1 || true
    exit "$status"
}
trap finish EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y /root/ctf-hunter.deb
systemctl is-enabled --quiet ctf-hunter-capture.service
systemctl is-active --quiet ctf-hunter-capture.service
test -S /run/ctf-hunter/capture.sock
test "$(stat -c %G /run/ctf-hunter/capture.sock)" = ctf-hunter
systemctl restart ctf-hunter-capture.service
systemctl is-active --quiet ctf-hunter-capture.service
systemd-analyze verify --man=no /lib/systemd/system/ctf-hunter-capture.service
systemd-analyze verify --man=no /usr/lib/systemd/user/ctf-hunterd.service

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
test -d /run/user/2000/ctf-hunter
test "$(stat -c %U:%G:%a /run/user/2000/ctf-hunter)" = ctfhuntertest:ctfhuntertest:700
systemctl restart ctf-hunter-capture.service
systemctl is-active --quiet ctf-hunter-capture.service
TEST_SCRIPT

install -D -m 0644 /dev/stdin \
    "$rootfs/etc/systemd/system/ctf-hunter-package-systemd-test.service" <<'TEST_UNIT'
[Unit]
Description=CTF Hunter package systemd integration test
After=dbus.service systemd-logind.service network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ctf-hunter-package-systemd-test
TimeoutStartSec=10min
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
TEST_UNIT
mkdir -p "$rootfs/etc/systemd/system/multi-user.target.wants"
ln -s ../ctf-hunter-package-systemd-test.service \
    "$rootfs/etc/systemd/system/multi-user.target.wants/ctf-hunter-package-systemd-test.service"

# Run the assertions as a boot service inside the container. This exercises the
# real system and user managers without depending on the host machine D-Bus.
nspawn_status=0
timeout --signal=TERM --kill-after=30s 12m \
    systemd-nspawn --quiet --directory="$rootfs" --machine="$machine" \
    --boot --notify-ready=yes --private-users=no \
    --capability=CAP_BPF,CAP_PERFMON 2>&1 \
    | tee "$nspawn_log" || nspawn_status=$?

result_file=$rootfs/var/tmp/ctf-hunter-package-systemd-test.result
if test ! -f "$result_file"; then
    tail -120 "$nspawn_log" >&2
    echo "systemd integration test did not produce a result (nspawn status $nspawn_status)" >&2
    exit 1
fi
if test "$(cat "$result_file")" != 0; then
    tail -120 "$nspawn_log" >&2
    echo "systemd integration assertions failed" >&2
    exit 1
fi

echo "PASS: Debian 12 systemd system/user service lifecycle validated"
