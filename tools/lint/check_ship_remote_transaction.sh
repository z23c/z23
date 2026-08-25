#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Execute ship.sh's exact remote activation heredoc against a fake user service.
# This is a behavioral transaction test: success must activate exact process
# bytes, identity, and both package-verify workers staged beside the executable,
# while failures after either identity reload or executable replacement must
# restore all three files and restart the outgoing process.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-ship-remote-test.XXXXXX")"
pidfile="$tmp/service.pid"

cleanup() {
    if [ -s "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

awk '
    /<<'\''REMOTE_SCRIPT'\''$/ { copying=1; next }
    copying && /^REMOTE_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$tmp/activate.sh"
awk '
    /<<'\''ROLLBACK_SCRIPT'\''/ { copying=1; next }
    copying && /^ROLLBACK_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$tmp/rollback.sh"
bash -n "$tmp/activate.sh" "$tmp/rollback.sh"

cat > "$tmp/node.c" <<'EOF'
#include <signal.h>
#include <string.h>
#include <unistd.h>
#ifndef VERSION
#define VERSION "unset"
#endif
static volatile const char *version = VERSION;
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0)
        return version[0] == '\0';
    for (;;) pause();
}
EOF
cc -O0 -DVERSION='"old"' "$tmp/node.c" -o "$tmp/old"
cc -O0 -DVERSION='"new"' "$tmp/node.c" -o "$tmp/new"
old_sha="$(sha256sum < "$tmp/old" | awk '{print $1}')"
new_sha="$(sha256sum < "$tmp/new" | awk '{print $1}')"
[ "$old_sha" != "$new_sha" ]

mkdir -p "$tmp/mockbin" "$tmp/home/.config/systemd/user/zclassic23.service.d"
cat > "$tmp/mockbin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = --user ]; then shift; fi
case "${1:-}" in
    show)
        cat "$ZCL_SHIP_TEST_PIDFILE"
        ;;
    daemon-reload)
        if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = reload ] &&
           [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
            : > "$ZCL_SHIP_TEST_FAIL_MARKER"
            exit 1
        fi
        ;;
    restart)
        if [ "${ZCL_SHIP_TEST_FAIL_ALWAYS:-}" = restart ]; then
            exit 1
        fi
        if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = restart ] &&
           [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
            : > "$ZCL_SHIP_TEST_FAIL_MARKER"
            exit 1
        fi
        old_pid="$(cat "$ZCL_SHIP_TEST_PIDFILE" 2>/dev/null || true)"
        [ -z "$old_pid" ] || kill "$old_pid" 2>/dev/null || true
        ZCL_AGENT_EXPECT_SOURCE_ID="$ZCL_SHIP_TEST_WANT_SOURCE" \
        ZCL_AGENT_EXPECT_BUILD_COMMIT="$ZCL_SHIP_TEST_WANT_COMMIT" \
        ZCL_AGENT_EXPECT_BUILD_SOURCE=ship \
            "$ZCL_SHIP_TEST_TARGET" >/dev/null 2>&1 &
        echo $! > "$ZCL_SHIP_TEST_PIDFILE"
        ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$tmp/mockbin/systemctl"

target="$tmp/zclassic23"
worker_v="$tmp/zclassic23-package-verify"
worker_d="$tmp/zclassic23-package-verify-dev"
dropin="$tmp/home/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"

start_old() {
    install -m 755 "$tmp/old" "$target"
    install -m 755 "$tmp/old" "$worker_v"
    install -m 755 "$tmp/old" "$worker_d"
    "$target" >/dev/null 2>&1 &
    echo $! > "$pidfile"
}

stop_current() {
    if [ -s "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        : > "$pidfile"
    fi
}

invoke() {
    HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" \
    ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_WANT_SOURCE="$(printf 'a%.0s' {1..64})" \
    ZCL_SHIP_TEST_WANT_COMMIT=candidate-commit \
    ZCL_SHIP_TEST_FAIL_MARKER="$tmp/fail.marker" \
    ZCL_SHIP_TEST_FAIL_ONCE="${1:-}" \
    ZCL_SHIP_TEST_FAIL_ALWAYS="${2:-}" \
    ZCL_SHIP_REMOTE_HEALTH_SECONDS=5 \
    ZCL_SHIP_ROLLBACK_HEALTH_SECONDS=5 \
        bash "$tmp/activate.sh" "$target" "$new_sha" \
            "$(printf 'a%.0s' {1..64})" candidate-commit \
            "$new_sha" "$new_sha"
}

assert_rolled_back() {
    [ "$(sha256sum < "$target" | awk '{print $1}')" = "$old_sha" ]
    [ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$old_sha" ]
    [ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$old_sha" ]
    grep -qx 'old identity' "$dropin"
    live_pid="$(cat "$pidfile")"
    [ "$(sha256sum < "/proc/$live_pid/exe" | awk '{print $1}')" = "$old_sha" ]
}

for fault in reload restart; do
    stop_current
    rm -f "$tmp/fail.marker" "${target}.incoming" \
        "${target}.rollback" "${dropin}.ship.rollback" "${dropin}.ship.absent" \
        "${worker_v}.incoming" "${worker_d}.incoming" \
        "${worker_v}.ship.rollback" "${worker_d}.ship.rollback" \
        "${worker_v}.ship.absent" "${worker_d}.ship.absent"
    printf 'old identity\n' > "$dropin"
    start_old
    install -m 755 "$tmp/new" "${target}.incoming"
    install -m 755 "$tmp/new" "${worker_v}.incoming"
    install -m 755 "$tmp/new" "${worker_d}.incoming"
    if invoke "$fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: activation unexpectedly survived $fault fault" >&2
        exit 1
    fi
    assert_rolled_back
done

# A rollback restart that also fails must never print a success claim. The
# outgoing process is deliberately left alive by this injected systemctl
# failure, allowing the test to prove the files were restored while the
# transaction reports the rollback as unverified.
stop_current
rm -f "$tmp/fail.marker" "${target}.incoming" \
    "${target}.rollback" "${dropin}.ship.rollback" "${dropin}.ship.absent" \
    "${worker_v}.incoming" "${worker_d}.incoming" \
    "${worker_v}.ship.rollback" "${worker_d}.ship.rollback" \
    "${worker_v}.ship.absent" "${worker_d}.ship.absent"
printf 'old identity\n' > "$dropin"
start_old
install -m 755 "$tmp/new" "${target}.incoming"
install -m 755 "$tmp/new" "${worker_v}.incoming"
install -m 755 "$tmp/new" "${worker_d}.incoming"
if out="$(invoke "" restart 2>&1)"; then
    echo "check_ship_remote_transaction: activation survived persistent restart fault" >&2
    exit 1
fi
case "$out" in
    *'CRITICAL — rollback could not be process-qualified'*) ;;
    *) echo "check_ship_remote_transaction: missing activation rollback alarm" >&2; exit 1 ;;
esac
assert_rolled_back

stop_current
rm -f "$tmp/fail.marker" "${target}.incoming" \
    "${target}.rollback" "${dropin}.ship.rollback" "${dropin}.ship.absent" \
    "${worker_v}.incoming" "${worker_d}.incoming" \
    "${worker_v}.ship.rollback" "${worker_d}.ship.rollback" \
    "${worker_v}.ship.absent" "${worker_d}.ship.absent"
printf 'old identity\n' > "$dropin"
start_old
install -m 755 "$tmp/new" "${target}.incoming"
install -m 755 "$tmp/new" "${worker_v}.incoming"
install -m 755 "$tmp/new" "${worker_d}.incoming"
invoke "" >/dev/null
[ "$(sha256sum < "$target" | awk '{print $1}')" = "$new_sha" ]
[ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$new_sha" ]
[ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$new_sha" ]
live_pid="$(cat "$pidfile")"
[ "$(sha256sum < "/proc/$live_pid/exe" | awk '{print $1}')" = "$new_sha" ]
grep -q '^Environment="ZCL_AGENT_EXPECT_SOURCE_ID=a\{64\}"$' "$dropin"
grep -qx 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=candidate-commit"' "$dropin"

# Exercise the exact post-activation fallback heredoc too. It must qualify the
# restored old process, and its permanent restart-failure case must be loud.
HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_TARGET="$target" \
ZCL_SHIP_TEST_WANT_SOURCE="$(printf 'a%.0s' {1..64})" \
ZCL_SHIP_TEST_WANT_COMMIT=candidate-commit \
ZCL_SHIP_TEST_FAIL_ONCE="" ZCL_SHIP_TEST_FAIL_ALWAYS="" \
ZCL_SHIP_ROLLBACK_HEALTH_SECONDS=5 \
    bash "$tmp/rollback.sh" "$target" >/dev/null
assert_rolled_back

# Re-activate new bytes, then deny the fallback restart. The fallback must
# return nonzero and call the rollback unqualified rather than claiming it.
install -m 755 "$tmp/new" "${target}.incoming"
install -m 755 "$tmp/new" "${worker_v}.incoming"
install -m 755 "$tmp/new" "${worker_d}.incoming"
invoke "" >/dev/null
if out="$(HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_FAIL_ONCE="" ZCL_SHIP_TEST_FAIL_ALWAYS=restart \
    ZCL_SHIP_ROLLBACK_HEALTH_SECONDS=5 \
    bash "$tmp/rollback.sh" "$target" 2>&1)"; then
    echo "check_ship_remote_transaction: fallback survived persistent restart fault" >&2
    exit 1
fi
case "$out" in
    *'CRITICAL — rollback restart'*) ;;
    *) echo "check_ship_remote_transaction: missing fallback rollback alarm" >&2; exit 1 ;;
esac

echo "check_ship_remote_transaction: PASS (activation/fallback faults rollback bytes+identity+workers; success and rollback process-qualified)"
