#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Hermetic proof of the immutable remote release transaction. It executes the
# literal remote programs from ship.sh with a fake user service and real
# fixture processes; no network or production state is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-ship-remote-test.XXXXXX")"
pidfile="$tmp/service.pid"
cleanup() {
    [ ! -s "$pidfile" ] || kill "$(cat "$pidfile")" 2>/dev/null || true
    find "$tmp" -type d -exec chmod 700 {} + 2>/dev/null || true
    find "$tmp" -type f -exec chmod 600 {} + 2>/dev/null || true
    find "$tmp" -depth -delete
}
trap cleanup EXIT HUP INT TERM

extract() {
    local begin="$1" end="$2" dst="$3"
    awk -v begin="$begin" -v end="$end" '
        index($0, begin) { copying=1; next }
        copying && $0 == end { exit }
        copying { print }
    ' "$ROOT/tools/ship.sh" > "$dst"
}
extract "<<'REMOTE_RELEASE_CHECK'" REMOTE_RELEASE_CHECK "$tmp/release-check.sh"
extract "<<'REMOTE_SCRIPT'" REMOTE_SCRIPT "$tmp/activate.part"
extract "<<'ROLLBACK_SCRIPT'" ROLLBACK_SCRIPT "$tmp/rollback.part"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/activate.part" > "$tmp/activate.sh"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/rollback.part" > "$tmp/rollback.sh"
bash -n "$tmp/release-check.sh" "$tmp/activate.sh" "$tmp/rollback.sh"

cat > "$tmp/node.c" <<'EOF'
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0) return 0;
    for (;;) pause();
}
EOF
cc -O0 "$tmp/node.c" -o "$tmp/old"
cc -O2 "$tmp/node.c" -o "$tmp/new"
old_sha="$(sha256sum < "$tmp/old" | awk '{print $1}')"
new_sha="$(sha256sum < "$tmp/new" | awk '{print $1}')"
source_id="$(printf 'a%.0s' {1..64})"
manifest="$tmp/MANIFEST.sha256"
printf '%s  z23\n%s  zclassic23-package-verify\n%s  zclassic23-package-verify-dev\n' \
    "$new_sha" "$new_sha" "$new_sha" > "$manifest"
manifest_sha="$(sha256sum < "$manifest" | awk '{print $1}')"

home="$tmp/home"
release="$home/.local/lib/z23/releases/$manifest_sha"
incoming="${release}.incoming.test-run"
dropin="$home/.config/systemd/user/zclassic23.service.d/zzzzz-z23-ship-release.conf"
mkdir -p "$tmp/mockbin" "$(dirname "$dropin")" "$(dirname "$release")"

cat > "$tmp/mockbin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" != --user ] || shift
case "$1" in
show) cat "$ZCL_SHIP_TEST_PIDFILE" ;;
daemon-reload)
    if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = reload ] &&
       [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
        : > "$ZCL_SHIP_TEST_FAIL_MARKER"
        exit 1
    fi
    ;;
restart)
    [ "${ZCL_SHIP_TEST_FAIL_ALWAYS:-}" != restart ] || exit 1
    if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = restart ] &&
       [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
        : > "$ZCL_SHIP_TEST_FAIL_MARKER"
        exit 1
    fi
    old_pid="$(cat "$ZCL_SHIP_TEST_PIDFILE" 2>/dev/null || true)"
    [ -z "$old_pid" ] || kill "$old_pid" 2>/dev/null || true
    target="$ZCL_SHIP_TEST_OLD"
    # Model systemd's lexical drop-in precedence. The legacy zzzz selector
    # loses to ship's zzzzz selector; the last effective ExecStart wins.
    for conf in "$HOME/.config/systemd/user/zclassic23.service.d/"*.conf; do
        [ -f "$conf" ] || continue
        selected="$(sed -n 's/^ExecStart="\([^"]*\)".*/\1/p' "$conf" | tail -1)"
        [ -z "$selected" ] || target="$selected"
    done
    ZCL_AGENT_EXPECT_SOURCE_ID="$ZCL_SHIP_TEST_SOURCE" \
    ZCL_AGENT_EXPECT_BUILD_COMMIT=candidate-commit \
    ZCL_AGENT_EXPECT_BUILD_SOURCE=ship \
        "$target" -fixture-node >/dev/null 2>&1 &
    echo $! > "$ZCL_SHIP_TEST_PIDFILE"
    ;;
*) exit 2 ;;
esac
EOF
chmod 755 "$tmp/mockbin/systemctl"

start_old() {
    "$tmp/old" -fixture-node >/dev/null 2>&1 &
    echo $! > "$pidfile"
}

# Hash the executable a live pid is running. Linux answers from
# /proc/<pid>/exe; darwin has no procfs, so resolve the running binary
# through ps and hash that file (same identity assertion, weaker read).
live_exe_sha() {
    if [ -r "/proc/$1/exe" ]; then
        sha256sum < "/proc/$1/exe" | awk '{print $1}'
    else
        comm="$(ps -ww -o comm= -p "$1")" || return 1
        sha256sum < "$comm" | awk '{print $1}'
    fi
}
stage_release() {
    [ ! -d "$release" ] || chmod 700 "$release"
    [ ! -d "$incoming" ] || chmod 700 "$incoming"
    [ ! -e "$release" ] || find "$release" -depth -delete
    [ ! -e "$incoming" ] || find "$incoming" -depth -delete
    mkdir -p "$incoming"
    install -m 755 "$tmp/new" "$incoming/z23"
    install -m 755 "$tmp/new" "$incoming/zclassic23-package-verify"
    install -m 755 "$tmp/new" "$incoming/zclassic23-package-verify-dev"
    install -m 644 "$manifest" "$incoming/MANIFEST.sha256"
}
invoke_activate() {
    HOME="$home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_OLD="$tmp/old" \
    ZCL_SHIP_TEST_SOURCE="$source_id" \
    ZCL_SHIP_TEST_FAIL_MARKER="$tmp/fail.marker" \
    ZCL_SHIP_TEST_FAIL_ONCE="${1:-}" ZCL_SHIP_TEST_FAIL_ALWAYS="${2:-}" \
        bash "$tmp/activate.sh" "$tmp/old" "$release" "$manifest_sha" \
        "$new_sha" "$source_id" candidate-commit "$new_sha" "$new_sha" \
        test-run 20 6 20 6 2 2 "2 4 6"
}

reset_fixture() {
    if [ -s "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        : > "$pidfile"
    fi
    rm -f "$tmp/fail.marker" "${dropin}.ship.rollback.test-run" \
        "${dropin}.ship.absent.test-run"
    rmdir "$home/.cache/z23/ship-activation.lock" 2>/dev/null || true
    printf 'prior ship selection\n' > "$dropin"
    stage_release
    start_old
}

assert_old_selected() {
    grep -qx 'prior ship selection' "$dropin"
    live_pid="$(cat "$pidfile")"
    [ "$(live_exe_sha "$live_pid")" = "$old_sha" ]
}

# An existing immutable identity with corrupt content must be refused in place.
mkdir -p "$release"
install -m 644 "$manifest" "$release/MANIFEST.sha256"
install -m 755 "$tmp/new" "$release/z23"
install -m 755 "$tmp/new" "$release/zclassic23-package-verify"
printf corrupt > "$release/zclassic23-package-verify-dev"
if bash "$tmp/release-check.sh" "$release" "$manifest_sha" "$new_sha" "$new_sha" "$new_sha" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: mismatched immutable root passed" >&2
    exit 1
fi
[ "$(cat "$release/zclassic23-package-verify-dev")" = corrupt ]

# A foreign activation lock must refuse without mutating the running process or
# removing the lock owned by the other transaction.
printf '[Service]\nExecStart="%s"\n' "$tmp/old" > "$(dirname "$dropin")/zzzz-z23-release.conf"
reset_fixture
mkdir -p "$home/.cache/z23/ship-activation.lock"
if invoke_activate >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: concurrent activation lock passed" >&2
    exit 1
fi
[ -d "$home/.cache/z23/ship-activation.lock" ]
assert_old_selected
rmdir "$home/.cache/z23/ship-activation.lock"

# A corrupt second worker is rejected before selection changes. This preserves
# the partial-stage fault that originally motivated shipping all three files
# as one release set.
reset_fixture
printf corrupt > "$incoming/zclassic23-package-verify-dev"
if invoke_activate >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: corrupt worker passed" >&2
    exit 1
fi
assert_old_selected

# Failures after rollback is armed must restore the prior path and restart its
# exact process. Exercise both the identity reload and restart boundaries.
for fault in reload restart; do
    reset_fixture
    if invoke_activate "$fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: activation survived $fault fault" >&2
        exit 1
    fi
    assert_old_selected
done

# Ship's selector must beat the previously deployed zzzz selector.
reset_fixture
invoke_activate >/dev/null
live_pid="$(cat "$pidfile")"
[ "$(live_exe_sha "$live_pid")" = "$new_sha" ]
[ "$(sha256sum < "$release/zclassic23-package-verify" | awk '{print $1}')" = "$new_sha" ]
grep -Fq "ExecStart=\"$release/z23\"" "$dropin"

# Rollback changes only the selected path; immutable release bytes remain.
HOME="$home" PATH="$tmp/mockbin:$PATH" \
ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_OLD="$tmp/old" \
ZCL_SHIP_TEST_SOURCE="$source_id" \
    bash "$tmp/rollback.sh" "$tmp/old" test-run "$old_sha" 20 6 2 2 "2 4 6" >/dev/null
grep -qx 'prior ship selection' "$dropin"
live_pid="$(cat "$pidfile")"
[ "$(live_exe_sha "$live_pid")" = "$old_sha" ]
[ "$(sha256sum < "$release/z23" | awk '{print $1}')" = "$new_sha" ]

# A fallback restart failure is an explicit critical result, never a success
# claim; immutable candidate bytes remain unchanged for diagnosis.
reset_fixture
invoke_activate >/dev/null
if HOME="$home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_OLD="$tmp/old" \
    ZCL_SHIP_TEST_SOURCE="$source_id" \
    ZCL_SHIP_TEST_FAIL_MARKER="$tmp/fail.marker" \
    ZCL_SHIP_TEST_FAIL_ONCE="" ZCL_SHIP_TEST_FAIL_ALWAYS=restart \
        bash "$tmp/rollback.sh" "$tmp/old" test-run "$old_sha" \
        20 6 2 2 "2 4 6" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: fallback restart failure passed" >&2
    exit 1
fi
[ "$(sha256sum < "$release/z23" | awk '{print $1}')" = "$new_sha" ]

# The native Tor decision is made before deployment code can transfer bytes.
tor_line="$(grep -n 'ship_candidate_has_real_tor "$CANDIDATE"' "$ROOT/tools/ship.sh" | tail -1 | cut -d: -f1)"
deploy_line="$(grep -n '^deploy_remote()' "$ROOT/tools/ship.sh" | cut -d: -f1)"
[ "$tor_line" -lt "$deploy_line" ]

echo "check_ship_remote_transaction: PASS (Tor gate precedes transfer; immutable mismatch, lock, partial stage, reload/restart, precedence, and rollback paths proved)"
