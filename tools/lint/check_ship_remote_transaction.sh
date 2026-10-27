#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Hermetic proof of the immutable remote release transaction. It executes the
# literal remote programs from ship.sh with a fake user service and real
# fixture processes; no network or production state is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-ship-remote-test.XXXXXX")"
tmp="$(cd "$tmp" && pwd -P)"
pidfile="$tmp/service.pid"
cc -std=c2x -Wall -Wextra -Werror -O0 "$ROOT/tools/lint/ship_remote_fixture.c" -o "$tmp/old"
cc -std=c2x -Wall -Wextra -Werror -O2 "$ROOT/tools/lint/ship_remote_fixture.c" -o "$tmp/new"
"$tmp/old" init "$tmp"
cleanup() { "$tmp/old" cleanup "$tmp"; }
trap cleanup EXIT HUP INT TERM
"$tmp/old" extract "$ROOT/tools/ship.sh" "<<'REMOTE_BINDING_CHECK'" REMOTE_BINDING_CHECK > "$tmp/binding-check.sh"
"$tmp/old" extract "$ROOT/tools/ship.sh" "<<'REMOTE_RELEASE_CHECK'" REMOTE_RELEASE_CHECK > "$tmp/release-check.sh"
"$tmp/old" extract "$ROOT/tools/ship.sh" "<<'REMOTE_SCRIPT'" REMOTE_SCRIPT > "$tmp/activate.part"
"$tmp/old" extract "$ROOT/tools/ship.sh" "<<'ROLLBACK_SCRIPT'" ROLLBACK_SCRIPT > "$tmp/rollback.part"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/activate.part" > "$tmp/activate.sh"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/rollback.part" > "$tmp/rollback.sh"
bash -n "$tmp/release-check.sh" "$tmp/activate.sh" "$tmp/rollback.sh"

old_sha="$(sha256sum < "$tmp/old" | awk '{print $1}')"
new_sha="$(sha256sum < "$tmp/new" | awk '{print $1}')"
source_id="$(printf 'a%.0s' {1..64})"
manifest="$tmp/MANIFEST.sha256"
printf '%s  z23\n%s  z23-package-verify\n%s  z23-package-verify-dev\n%s  zclassic23-package-verify\n%s  zclassic23-package-verify-dev\n' \
    "$new_sha" "$new_sha" "$new_sha" "$new_sha" "$new_sha" > "$manifest"
manifest_sha="$(sha256sum < "$manifest" | awk '{print $1}')"

home="$tmp/home"
release="$home/.local/lib/z23/releases/$manifest_sha"
incoming="${release}.incoming.test-run"
node_unit=z23-node.service
dropin="$home/.config/systemd/user/${node_unit}.d/zzzzz-z23-ship-release.conf"
mkdir -p "$tmp/mockbin" "$(dirname "$dropin")" "$(dirname "$release")"

state_file="$tmp/fixture.state"
fixture_state() {
    printf '%s\n' "$tmp" "$node_unit" "${3:-}" "$source_id" \
        "${1:-}" "${2:-}" "$manifest_sha" > "$state_file"
}
fixture_state
printf '#!/bin/sh\nexec "%s" systemctl "%s" "$@"\n' \
    "$tmp/old" "$state_file" > "$tmp/mockbin/systemctl"
chmod 755 "$tmp/mockbin/systemctl"


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
stage_release() { "$tmp/old" stage "$state_file"; }
invoke_activate() {
    fixture_state "${1:-}" "${2:-}"
    HOME="$home" PATH="$tmp/mockbin:$PATH" \
        bash "$tmp/activate.sh" "$tmp/old" "$release" "$manifest_sha" \
        "$new_sha" "$source_id" candidate-commit "$new_sha" "$new_sha" \
        test-run 20 6 20 6 2 2 "2 4 6" 0 "$node_unit"
}
reset_fixture() { fixture_state; "$tmp/old" reset "$state_file"; }

assert_old_selected() {
    grep -qx 'prior ship selection' "$dropin"
    live_pid="$(cat "$pidfile")"
    [ "$(live_exe_sha "$live_pid")" = "$old_sha" ]
}

# An existing immutable identity must verify exactly when ALL four worker
# names (the z23-* primaries and the legacy zclassic23-* copies an older daemon
# resolves) are present with the frozen bytes, and must be refused in place
# when any one of them is corrupt or missing.
ship_workers="z23-package-verify z23-package-verify-dev zclassic23-package-verify zclassic23-package-verify-dev"
mkdir -p "$release"
install -m 644 "$manifest" "$release/MANIFEST.sha256"
install -m 755 "$tmp/new" "$release/z23"
for w in $ship_workers; do install -m 755 "$tmp/new" "$release/$w"; done
bash "$tmp/release-check.sh" "$release" "$manifest_sha" "$new_sha" "$new_sha" "$new_sha" >/dev/null 2>&1 || {
    echo "check_ship_remote_transaction: complete immutable root was refused" >&2
    exit 1
}
for w in $ship_workers; do
    printf corrupt > "$release/$w"
    if bash "$tmp/release-check.sh" "$release" "$manifest_sha" "$new_sha" "$new_sha" "$new_sha" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: immutable root with corrupt $w passed" >&2
        exit 1
    fi
    [ "$(cat "$release/$w")" = corrupt ]
    rm -f "$release/$w"
    if bash "$tmp/release-check.sh" "$release" "$manifest_sha" "$new_sha" "$new_sha" "$new_sha" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: immutable root missing $w passed" >&2
        exit 1
    fi
    install -m 755 "$tmp/new" "$release/$w"
done

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
printf corrupt > "$incoming/z23-package-verify-dev"
if invoke_activate >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: corrupt worker passed" >&2
    exit 1
fi
assert_old_selected

# The legacy-name copy an older daemon resolves is held to the same standard.
reset_fixture
printf corrupt > "$incoming/zclassic23-package-verify"
if invoke_activate >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: corrupt legacy-name worker passed" >&2
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

# A drop-in whose NAME sorts after the ship's own resets ExecStart= and wins
# the merge, so the unit would come back on whatever that file pins. This is
# the 2026-09-11 fleet incident: two ships in a row staged the new release,
# wrote their drop-in, restarted — and the unit ran the OLD binary each time,
# visible only as sha != want for the whole observer window. The activation
# must now refuse BEFORE the restart, name the shadowing file, restore the
# prior drop-in, and leave the running process untouched.
shadow="$(dirname "$dropin")/zzzzzz-node-first.conf"
reset_fixture
printf '[Service]\nExecStart=\nExecStart="%s"\n' "$tmp/old" > "$shadow"
before_pid="$(cat "$pidfile")"
guard_out="$tmp/guard.out"
if invoke_activate >"$guard_out" 2>&1; then
    echo "check_ship_remote_transaction: shadowed ExecStart passed activation" >&2
    exit 1
fi
grep -q 'REFUSE: the unit will not run the release this ship installed' "$guard_out" || {
    echo "check_ship_remote_transaction: shadow refusal message is missing" >&2
    sed -n '1,40p' "$guard_out" >&2; exit 1; }
grep -q 'zzzzzz-node-first.conf' "$guard_out" || {
    echo "check_ship_remote_transaction: refusal did not name the shadowing drop-in" >&2
    exit 1; }
# The ONE mutation is undone, and nothing was restarted: same pid, same bytes.
assert_old_selected
[ "$(cat "$pidfile")" = "$before_pid" ] || {
    echo "check_ship_remote_transaction: shadow refusal restarted the service" >&2
    exit 1; }
rm -f "$shadow"

# Ship's selector must beat the previously deployed zzzz selector.
reset_fixture
invoke_activate >/dev/null
live_pid="$(cat "$pidfile")"
[ "$(live_exe_sha "$live_pid")" = "$new_sha" ]
[ "$(sha256sum < "$release/z23-package-verify" | awk '{print $1}')" = "$new_sha" ]
[ "$(sha256sum < "$release/zclassic23-package-verify" | awk '{print $1}')" = "$new_sha" ]
grep -Fq "ExecStart=\"$release/z23\"" "$dropin"

# Rollback changes only the selected path; immutable release bytes remain.
HOME="$home" PATH="$tmp/mockbin:$PATH" \
    bash "$tmp/rollback.sh" "$tmp/old" test-run "$old_sha" 20 6 2 2 "2 4 6" "$node_unit" >/dev/null
grep -qx 'prior ship selection' "$dropin"
live_pid="$(cat "$pidfile")"
[ "$(live_exe_sha "$live_pid")" = "$old_sha" ]
[ "$(sha256sum < "$release/z23" | awk '{print $1}')" = "$new_sha" ]

# A fallback restart failure is an explicit critical result, never a success
# claim; immutable candidate bytes remain unchanged for diagnosis.
reset_fixture
invoke_activate >/dev/null
fixture_state "" restart
if HOME="$home" PATH="$tmp/mockbin:$PATH" \
        bash "$tmp/rollback.sh" "$tmp/old" test-run "$old_sha" \
        20 6 2 2 "2 4 6" "$node_unit" >/dev/null 2>&1; then
    echo "check_ship_remote_transaction: fallback restart failure passed" >&2
    exit 1
fi
[ "$(sha256sum < "$release/z23" | awk '{print $1}')" = "$new_sha" ]

# The native Tor decision is made before deployment code can transfer bytes.
tor_line="$(grep -n 'ship_candidate_has_real_tor "$CANDIDATE"' "$ROOT/tools/ship.sh" | tail -1 | cut -d: -f1)"
deploy_line="$(grep -n '^deploy_remote()' "$ROOT/tools/ship.sh" | cut -d: -f1)"
[ "$tor_line" -lt "$deploy_line" ]

# The same real transaction selects only the explicitly bound legacy service.
default_dropin_sha="$(sha256sum < "$dropin" | awk '{print $1}')"
default_dropin="$dropin"
node_unit=zclassic23.service
: > "$pidfile.restarts"
dropin="$home/.config/systemd/user/${node_unit}.d/zzzzz-z23-ship-release.conf"
mkdir -p "$(dirname "$dropin")"
for fault in reload restart; do
    reset_fixture
    if invoke_activate "$fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: legacy survived $fault fault" >&2; exit 1
    fi
    assert_old_selected
done
reset_fixture
invoke_activate >/dev/null
[ "$(live_exe_sha "$(cat "$pidfile")")" = "$new_sha" ]
grep -Fq "ExecStart=\"$release/z23\" \"-fixture-node\"" "$dropin"
# Restart logs name exactly the selected service; the other service is read-only.
[ -s "$pidfile.restarts" ]
! grep -vxF "$node_unit" "$pidfile.restarts"

[ "$(sha256sum < "$default_dropin" | awk '{print $1}')" = "$default_dropin_sha" ]
# Run the exact production pre-transfer check against the same service fixture.
invoke_binding() {
    fixture_state "" "" "${1:-}"
    HOME="$home" PATH="$tmp/mockbin:$PATH" \
        bash "$tmp/binding-check.sh" "$node_unit"
}
invoke_binding
for binding_fault in both missing; do
    before_pid="$(cat "$pidfile")"
    before_restarts="$(wc -l < "$pidfile.restarts")"
    if invoke_binding "$binding_fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: $binding_fault binding passed" >&2; exit 1
    fi
    [ "$(cat "$pidfile")" = "$before_pid" ]
    [ "$(wc -l < "$pidfile.restarts")" = "$before_restarts" ]
done
"$tmp/old" stop "$state_file"
"$tmp/old" stop "$state_file"
# The all-host binding barrier precedes the sole remote staging dispatcher.
binding_line="$(grep -n 'ship_remote_binding_check "$host" ||' "$ROOT/tools/ship.sh" | cut -d: -f1)"
stage_line="$(grep -n 'ship_remote_rollout stage_remote deploy_remote' "$ROOT/tools/ship.sh" | cut -d: -f1)"
[ "$binding_line" -lt "$stage_line" ]
echo "check_ship_remote_transaction: PASS (Tor gate precedes transfer; immutable mismatch, lock, partial stage, reload/restart, precedence, shadowed-ExecStart refusal, and rollback paths proved)"
