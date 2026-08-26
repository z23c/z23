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
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/activate.sh" > "$tmp/activate.full" && mv "$tmp/activate.full" "$tmp/activate.sh"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/rollback.sh" > "$tmp/rollback.full" && mv "$tmp/rollback.full" "$tmp/rollback.sh"
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
# A candidate that installs perfectly and then never answers `status`. This is
# the fault a countdown could not tell apart from a slow disk.
cc -O0 -DVERSION='""' "$tmp/node.c" -o "$tmp/mute"
old_sha="$(sha256sum < "$tmp/old" | awk '{print $1}')"
new_sha="$(sha256sum < "$tmp/new" | awk '{print $1}')"
mute_sha="$(sha256sum < "$tmp/mute" | awk '{print $1}')"
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
run_id="test-run"

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
        bash "$tmp/activate.sh" "$target" "$new_sha" \
            "$(printf 'a%.0s' {1..64})" candidate-commit \
            "$new_sha" "$new_sha" "$run_id" \
            20 6 20 6 2 2 "2 4 6"
}

reset_transaction() {
    rm -f "$tmp/fail.marker" "${target}.incoming.${run_id}" \
        "${target}.rollback.${run_id}" "${dropin}.ship.rollback.${run_id}" \
        "${dropin}.ship.absent.${run_id}" \
        "${worker_v}.incoming.${run_id}" "${worker_d}.incoming.${run_id}" \
        "${worker_v}.ship.rollback.${run_id}" "${worker_d}.ship.rollback.${run_id}" \
        "${worker_v}.ship.absent.${run_id}" "${worker_d}.ship.absent.${run_id}"
    rmdir "$tmp/home/.cache/z23/ship-activation.lock" 2>/dev/null || true
}

stage_new() {
    install -m 755 "$tmp/new" "${target}.incoming.${run_id}"
    install -m 755 "$tmp/new" "${worker_v}.incoming.${run_id}"
    install -m 755 "$tmp/new" "${worker_d}.incoming.${run_id}"
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
    reset_transaction
    printf 'old identity\n' > "$dropin"
    start_old
    stage_new
    if invoke "$fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: activation unexpectedly survived $fault fault" >&2
        exit 1
    fi
    assert_rolled_back
done

# A candidate that installs cleanly, restarts cleanly, presents exactly the
# bytes and identity it promised — and then never answers `status`. Nothing in
# the transaction itself failed, so every install-time fault check above stays
# quiet; only the health verdict can catch this. It is also the exact shape a
# slow box presents for its first few minutes, which is why the verdict is
# allowed to convict on observed stillness and never on elapsed time.
stop_current
reset_transaction
printf 'old identity\n' > "$dropin"
start_old
install -m 755 "$tmp/mute" "${target}.incoming.${run_id}"
install -m 755 "$tmp/mute" "${worker_v}.incoming.${run_id}"
install -m 755 "$tmp/mute" "${worker_d}.incoming.${run_id}"
if HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" \
    ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_WANT_SOURCE="$(printf 'a%.0s' {1..64})" \
    ZCL_SHIP_TEST_WANT_COMMIT=candidate-commit \
    ZCL_SHIP_TEST_FAIL_MARKER="$tmp/fail.marker" \
    ZCL_SHIP_TEST_FAIL_ONCE="" ZCL_SHIP_TEST_FAIL_ALWAYS="" \
        bash "$tmp/activate.sh" "$target" "$mute_sha" \
            "$(printf 'a%.0s' {1..64})" candidate-commit \
            "$mute_sha" "$mute_sha" "$run_id" \
            20 6 20 6 2 2 "2 4 6" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: a candidate that never answers status was accepted" >&2
    exit 1
fi
assert_rolled_back

# A concurrent activation lock belongs to the other process. Refusal must not
# remove that lock or mutate any installed byte.
stop_current
reset_transaction
printf 'old identity\n' > "$dropin"
start_old
stage_new
mkdir -p "$tmp/home/.cache/z23/ship-activation.lock"
if invoke "" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: concurrent activation lock passed" >&2
    exit 1
fi
[ -d "$tmp/home/.cache/z23/ship-activation.lock" ] || {
    echo "check_ship_remote_transaction: foreign activation lock was removed" >&2
    exit 1
}
[ "$(sha256sum < "$target" | awk '{print $1}')" = "$old_sha" ]
rmdir "$tmp/home/.cache/z23/ship-activation.lock"

# A second-worker hash failure happens after the first worker swap. Rollback
# must already be armed so the host cannot retain a mixed worker set.
stop_current
reset_transaction
printf 'old identity\n' > "$dropin"
start_old
stage_new
printf 'corrupt\n' > "${worker_d}.incoming.${run_id}"
if invoke "" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: second-worker corruption passed" >&2
    exit 1
fi
assert_rolled_back

# A rollback restart that also fails must never print a success claim. The
# outgoing process is deliberately left alive by this injected systemctl
# failure, allowing the test to prove the files were restored while the
# transaction reports the rollback as unverified.
stop_current
reset_transaction
printf 'old identity\n' > "$dropin"
start_old
stage_new
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
reset_transaction
printf 'old identity\n' > "$dropin"
start_old
stage_new
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
    bash "$tmp/rollback.sh" "$target" "$run_id" 20 6 2 2 "2 4 6" >/dev/null
assert_rolled_back

# Re-activate new bytes, then deny the fallback restart. The fallback must
# return nonzero and call the rollback unqualified rather than claiming it.
stage_new
invoke "" >/dev/null
if out="$(HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_FAIL_ONCE="" ZCL_SHIP_TEST_FAIL_ALWAYS=restart \
    bash "$tmp/rollback.sh" "$target" "$run_id" 20 6 2 2 "2 4 6" 2>&1)"; then
    echo "check_ship_remote_transaction: fallback survived persistent restart fault" >&2
    exit 1
fi
case "$out" in
    *'CRITICAL — rollback restart'*) ;;
    *) echo "check_ship_remote_transaction: missing fallback rollback alarm" >&2; exit 1 ;;
esac

# Fleet-level anti-rot: local activation must consume the already-frozen bytes,
# ordinary status checks must address the running inode, and remote deployment
# must iterate the validated host array rather than one global endpoint.
grep -q 'ZCL_DEPLOY_FROZEN_CANDIDATE="$CANDIDATE"' "$ROOT/tools/ship.sh"
grep -q 'for host in "${DEPLOY_HOSTS\[@\]}"' "$ROOT/tools/ship.sh"
grep -q 'timeout 20 "/proc/\$pid/exe" status' "$ROOT/tools/ship.sh"

echo "check_ship_remote_transaction: PASS (four-host/frozen-byte wiring; concurrent/partial/fallback faults rollback; process-qualified)"
