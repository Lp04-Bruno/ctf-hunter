#!/bin/bash
set -euo pipefail

package=${1:?usage: package-lifecycle-test.sh PACKAGE DISTRO}
distro=${2:?usage: package-lifecycle-test.sh PACKAGE DISTRO}
test_user=ctfhuntertest
test_home=/home/$test_user
runtime_dir=/run/user/2000
database=$test_home/.local/share/ctf-hunter/hunter.db
socket=$runtime_dir/ctf-hunter/daemon.sock
capture_socket=$runtime_dir/ctf-hunter/missing-capture.sock
daemon_log=/tmp/ctf-hunterd-lifecycle.log
session_id=
daemon_pid=
notification_service_pid=
session_bus_pid=
xvfb_pid=
session_bus_address=
display_number=:99

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export TZ=UTC

fail() {
    echo "FAIL [$distro]: $*" >&2
    exit 1
}

pass() {
    echo "PASS [$distro]: $*"
}

cleanup() {
    if test -n "${daemon_pid:-}" && kill -0 "$daemon_pid" 2>/dev/null; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    for pid in "$notification_service_pid" "$session_bus_pid" "$xvfb_pid"; do
        if test -n "$pid" && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

if test "$(id -u)" -ne 0; then
    fail "the lifecycle test must run as root in a disposable container"
fi
test -f "$package" || fail "package not found: $package"

# Package scripts are deliberately tested without systemd as PID 1. This policy
# prevents unrelated dependency packages from trying to start services.
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d

updated=0
for attempt in 1 2 3 4 5; do
    if apt-get update; then
        updated=1
        break
    fi
    echo "APT index refresh attempt $attempt failed; retrying after mirror resynchronization" >&2
    find /var/lib/apt/lists -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    sleep 10
done
test "$updated" = 1 || fail "APT indexes remained inconsistent after five attempts"
apt-get install -y --no-install-recommends \
    ca-certificates dbus-x11 jq libglib2.0-bin procps python3 python3-dbus \
    python3-gi util-linux xauth xvfb
apt-get install -y "$package"

test "$(dpkg-query -W -f='${Status}' ctf-hunter)" = "install ok installed" \
    || fail "clean installation did not reach the installed state"
test -x /usr/bin/ctf-hunter
test -x /usr/bin/ctf-hunterctl
test -x /usr/bin/ctf-hunterd
test -x /usr/libexec/ctf-hunter-capture
test -f /lib/systemd/system/ctf-hunter-capture.service
test -f /usr/lib/systemd/user/ctf-hunterd.service
getent group ctf-hunter >/dev/null || fail "sysusers did not create the capture group"
pass "clean non-interactive installation and dependency resolution"

apt-get install --reinstall -y "$package"
pass "idempotent reinstall"

if ! id "$test_user" >/dev/null 2>&1; then
    useradd --create-home --uid 2000 --shell /bin/bash "$test_user"
fi
mkdir -p "$runtime_dir" "$test_home/.local/share/ctf-hunter"
chown -R "$test_user:$test_user" "$runtime_dir" "$test_home/.local"
chmod 0700 "$runtime_dir"
printf 'preserve-on-remove-and-purge\n' >"$test_home/.local/share/ctf-hunter/user-data.sentinel"
chown "$test_user:$test_user" "$test_home/.local/share/ctf-hunter/user-data.sentinel"

if id -nG "$test_user" | tr ' ' '\n' | grep -Fxq ctf-hunter; then
    fail "package installation modified an existing account"
fi
PKEXEC_UID=$(id -u "$test_user") /usr/libexec/ctf-hunter-enable-capture
if ! id -nG "$test_user" | tr ' ' '\n' | grep -Fxq ctf-hunter; then
    fail "fixed-purpose setup helper did not add the selected account"
fi
PKEXEC_UID=$(id -u "$test_user") /usr/libexec/ctf-hunter-enable-capture
pass "explicit and idempotent capture-group enrollment"

as_user() {
    runuser -u "$test_user" -- env \
        HOME="$test_home" \
        USER="$test_user" \
        LOGNAME="$test_user" \
        XDG_RUNTIME_DIR="$runtime_dir" \
        DISPLAY="$display_number" \
        DBUS_SESSION_BUS_ADDRESS="${session_bus_address:-unix:path=$runtime_dir/nonexistent-bus}" \
        "$@"
}

Xvfb "$display_number" -screen 0 1280x720x24 -nolisten tcp -ac \
    >/tmp/ctf-hunter-xvfb.log 2>&1 &
xvfb_pid=$!
for _ in $(seq 1 100); do
    test -S "/tmp/.X11-unix/X${display_number#:}" && break
    kill -0 "$xvfb_pid" 2>/dev/null || fail "Xvfb exited during desktop setup"
    sleep 0.05
done
test -S "/tmp/.X11-unix/X${display_number#:}" || fail "Xvfb did not become ready"

mapfile -t bus_info < <(runuser -u "$test_user" -- env \
    HOME="$test_home" USER="$test_user" LOGNAME="$test_user" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    dbus-daemon --session --fork --print-address=1 --print-pid=1)
test "${#bus_info[@]}" -eq 2 || fail "session D-Bus did not report address and PID"
session_bus_address=${bus_info[0]}
session_bus_pid=${bus_info[1]}

notification_log=/tmp/ctf-hunter-notifications.jsonl
rm -f "$notification_log"
as_user env CTF_HUNTER_NOTIFICATION_LOG="$notification_log" \
    python3 /test/mock-notification-service.py \
    >/tmp/ctf-hunter-notification-service.log 2>&1 &
notification_service_pid=$!
notification_ready=0
for _ in $(seq 1 100); do
    if as_user gdbus call --session \
        --dest org.freedesktop.Notifications \
        --object-path /org/freedesktop/Notifications \
        --method org.freedesktop.Notifications.GetServerInformation \
        >/dev/null 2>&1; then
        notification_ready=1
        break
    fi
    if ! kill -0 "$notification_service_pid" 2>/dev/null; then
        sed -n '1,200p' /tmp/ctf-hunter-notification-service.log >&2 || true
        fail "notification test service exited during desktop setup"
    fi
    sleep 0.05
done
if test "$notification_ready" != 1; then
    sed -n '1,200p' /tmp/ctf-hunter-notification-service.log >&2 || true
    fail "notification test service did not become ready"
fi

wait_for_socket() {
    for _ in $(seq 1 100); do
        test -S "$socket" && return 0
        kill -0 "$daemon_pid" 2>/dev/null || {
            sed -n '1,200p' "$daemon_log" >&2 || true
            fail "daemon exited before creating its socket"
        }
        sleep 0.05
    done
    fail "daemon socket did not appear"
}

start_daemon() {
    rm -f "$socket"
    as_user /usr/bin/ctf-hunterd \
        --database "$database" \
        --socket "$socket" \
        --capture-socket "$capture_socket" >"$daemon_log" 2>&1 &
    daemon_pid=$!
    wait_for_socket
}

stop_daemon() {
    as_user /usr/bin/ctf-hunterctl --socket "$socket" shutdown >/dev/null
    wait "$daemon_pid"
    daemon_pid=
}

start_daemon
create_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" \
    create "Package lifecycle" 'FLAG{*}')
session_id=$(printf '%s' "$create_response" | jq -er '.response.id')
watch_dir=$test_home/watched
mkdir -p "$watch_dir"
chown "$test_user:$test_user" "$watch_dir"
as_user /usr/bin/ctf-hunterctl --socket "$socket" \
    add-watch "$session_id" "$watch_dir" >/dev/null
as_user /usr/bin/ctf-hunterctl --socket "$socket" start "$session_id" >/dev/null
as_user python3 -c 'from pathlib import Path; import sys; Path(sys.argv[1]).write_text("FLAG{package_file_watch}")' \
    "$watch_dir/response.bin"
finding_ready=0
for _ in $(seq 1 100); do
    finding_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" list "$session_id")
    if printf '%s' "$finding_response" | grep -Fq 'FLAG{package_file_watch}'; then
        finding_ready=1
        break
    fi
    sleep 0.05
done
test "$finding_ready" = 1 || fail "packaged file monitor did not persist a finding"
status_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" status)
printf '%s' "$status_response" | jq -e '.response.result == "status"' >/dev/null \
    || fail "daemon stopped responding with desktop services"
printf '%s' "$status_response" | jq -e \
    '.response.file_collector.files_read >= 1 and .response.file_collector.analyzed_files >= 1' \
    >/dev/null || fail "file collector did not report the watched payload"
notification_ready=0
for _ in $(seq 1 100); do
    status_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" status)
    if printf '%s' "$status_response" | jq -e '.response.notifications.delivered >= 1' \
        >/dev/null; then
        notification_ready=1
        break
    fi
    sleep 0.05
done
test "$notification_ready" = 1 || fail "desktop finding notification was not delivered"
as_user python3 -c '
import json, pathlib, sys
records = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert any(
    record["app_name"] == "CTF Hunter"
    and record["summary"] == "Flag candidate found"
    and "FLAG{package_file_watch}" in record["body"]
    and "Session: Package lifecycle" in record["body"]
    for record in records
)
' "$notification_log" || fail "desktop notification payload was incorrect"
stop_daemon
pass "watched-file analysis and desktop notification delivery"

start_daemon
sessions_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" sessions)
printf '%s' "$sessions_response" | grep -Fq 'Package lifecycle' \
    || fail "session was lost across daemon restart"
finding_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" list "$session_id")
printf '%s' "$finding_response" | grep -Fq 'FLAG{package_file_watch}' \
    || fail "finding was lost across daemon restart"
as_user python3 -c 'from pathlib import Path; import sys; Path(sys.argv[1]).write_text("FLAG{package_restored_watch}")' \
    "$watch_dir/restored.bin"
restored_watch_ready=0
for _ in $(seq 1 100); do
    finding_response=$(as_user /usr/bin/ctf-hunterctl --socket "$socket" list "$session_id")
    if printf '%s' "$finding_response" | grep -Fq 'FLAG{package_restored_watch}'; then
        restored_watch_ready=1
        break
    fi
    sleep 0.05
done
test "$restored_watch_ready" = 1 || fail "file watch was not restored after restart"
stop_daemon
pass "daemon restart, database recovery, and restored file monitoring"

fixture_dir=$(mktemp -d /tmp/ctf-hunter-previous.XXXXXX)
dpkg-deb --raw-extract "$package" "$fixture_dir/root"
package_version=$(dpkg-deb --field "$package" Version)
case "$package_version" in
    0.1.0~rc1-1) previous_version=0.1.0~rc0-1 ;;
    0.1.0~rc2-1) previous_version=0.1.0~rc1-1 ;;
    0.1.0-1) previous_version=0.1.0~rc2-1 ;;
    0.1.1~rc1-1) previous_version=0.1.0-1 ;;
    0.1.1-1) previous_version=0.1.1~rc1-1 ;;
    *) fail "unsupported package version in lifecycle test: $package_version" ;;
esac
sed -i "s/^Version: .*/Version: $previous_version/" "$fixture_dir/root/DEBIAN/control"
previous_package=$fixture_dir/ctf-hunter_${previous_version}_amd64.deb
dpkg-deb --root-owner-group --build "$fixture_dir/root" "$previous_package" >/dev/null

apt-get install --allow-downgrades -y "$previous_package"
test "$(dpkg-query -W -f='${Version}' ctf-hunter)" = "$previous_version" \
    || fail "same-schema downgrade did not install the fixture"
test -f "$database" || fail "database was lost during downgrade"
apt-get install -y "$package"
test "$(dpkg-query -W -f='${Version}' ctf-hunter)" = "$package_version" \
    || fail "upgrade from the previous fixture failed"
test -f "$database" || fail "database was lost during upgrade"
pass "same-schema downgrade and upgrade data retention"

apt-get remove -y ctf-hunter
test -f "$test_home/.local/share/ctf-hunter/user-data.sentinel" \
    || fail "remove deleted user data"
for path in \
    /usr/bin/ctf-hunter \
    /usr/bin/ctf-hunterctl \
    /usr/bin/ctf-hunterd \
    /usr/libexec/ctf-hunter-capture \
    /lib/systemd/system/ctf-hunter-capture.service \
    /usr/lib/systemd/user/ctf-hunterd.service \
    /usr/share/applications/dev.ctfhunter.desktop; do
    test ! -e "$path" || fail "remove retained package-owned path: $path"
done
pass "remove keeps user data and removes package payload"

apt-get install -y "$package"
test -f "$database" || fail "reinstall after remove lost the database"
apt-get purge -y ctf-hunter
test -f "$test_home/.local/share/ctf-hunter/user-data.sentinel" \
    || fail "purge deleted user data"
test ! -e /usr/bin/ctf-hunter || fail "purge retained package payload"
apt-get install -y "$package"
test -f "$database" || fail "reinstall after purge lost the database"
pass "purge and reinstall preserve user-owned state"

set +e
timeout 12s runuser -u "$test_user" -- env \
    HOME="$test_home" \
    USER="$test_user" \
    LOGNAME="$test_user" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    dbus-run-session -- xvfb-run -a /usr/bin/ctf-hunter \
    >/tmp/ctf-hunter-gui.log 2>&1
gui_status=$?
set -e
if test "$gui_status" -ne 124; then
    sed -n '1,200p' /tmp/ctf-hunter-gui.log >&2 || true
    fail "headless GUI exited unexpectedly with status $gui_status"
fi
pass "headless native GUI remained healthy"

rm -rf "$fixture_dir"
echo "PASS [$distro]: complete package lifecycle suite"
