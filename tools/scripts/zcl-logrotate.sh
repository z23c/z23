#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zcl-logrotate.sh — size-threshold log rotation with NO external logrotate
# dependency (repo rule: no external deps — see CLAUDE.md "NO external
# dependencies"). Phase E2 of the approved plan: node.log grows unbounded
# under `StandardOutput=append:...node.log` (platform/deploy/zclassic23.service and
# friends never truncate it).
#
# Targets (overridable via ZCL_LOGROTATE_TARGETS, space-separated glob
# patterns): every *.log directly under any ~/.zclassic-c23* datadir
# (canonical/-dev/-soak/-test/-work/... variants) plus any mint-progress.log
# a mint producer datadir may carry. Globs that match nothing are silently
# skipped (nullglob) — a variant datadir that doesn't exist on this box is
# not an error.
#
# Safety invariants:
#   - NEVER touches a file whose basename does not end in ".log" — enforced
#     even though the default globs already end in .log, in case
#     ZCL_LOGROTATE_TARGETS is overridden with something looser.
#   - NEVER follows a symlink (skipped, logged) — a target log must be a
#     real regular file in place.
#   - copytruncate semantics: copy the file's current bytes out to the
#     ".1" generation, THEN truncate the ORIGINAL file in place (never
#     rename/delete it). The node process (systemd StandardOutput=append)
#     keeps writing through its already-open fd in append mode; truncating
#     the underlying file the fd points at is safe under POSIX append
#     semantics (the fd's write position for O_APPEND is re-resolved to
#     the file's current end-of-file on every write(2), so post-truncate
#     writes correctly resume at offset 0 rather than seeking into a hole
#     or clobbering already-copied bytes) — this is the same guarantee
#     traditional logrotate's `copytruncate` directive relies on. There is
#     a small window between the copy and the truncate where lines written
#     in that window land in the ".1" copy (harmless duplication) rather
#     than being lost; that is the documented copytruncate trade-off, not
#     a bug here.
#   - Rotation is flock-serialized per target file so an operator running
#     this by hand can never race the timer.
#   - Compresses the freshly rotated ".1" generation with gzip if
#     available (background-free, synchronous — this is a lightweight
#     oneshot, not a multi-GB archive job); falls back to plain ".1"/".2"
#     if gzip is absent on this box. Keeps exactly 2 rotated generations
#     (".1"[.gz] and ".2"[.gz]); anything older is deleted.
#
# Usage:
#   zcl-logrotate.sh                 # rotate every configured target
#   zcl-logrotate.sh --dry-run       # log what WOULD rotate, touch nothing
#   zcl-logrotate.sh --selftest      # hermetic fixture-only regression test
#
# Env overrides:
#   ZCL_LOGROTATE_TARGETS      space-separated glob list (default below)
#   ZCL_LOGROTATE_ROTATE_BYTES rotate threshold in bytes (default 512 MiB)

set -euo pipefail

ROTATE_BYTES="${ZCL_LOGROTATE_ROTATE_BYTES:-536870912}"  # 512 MiB
DRY_RUN=0

default_targets() {
    printf '%s\n' \
        "$HOME/.zclassic-c23"*/node.log \
        "$HOME/.zclassic-c23"*/mint-progress.log
}

log() { echo "zcl-logrotate: $*" >&2; }

is_log_file() {
    # NEVER touch a file that is not a *.log — enforced on the basename
    # regardless of how it was matched into the target list.
    case "$(basename -- "$1")" in
        *.log) return 0 ;;
        *) return 1 ;;
    esac
}

file_size() {
    stat -c %s -- "$1" 2>/dev/null || stat -f %z -- "$1" 2>/dev/null || echo 0
}

# rotate_generations <base>: shift base.1[.gz] -> base.2[.gz], dropping
# whatever base.2[.gz] held. Called BEFORE the new base.1 is written so a
# rotation never produces more than 2 kept generations.
rotate_generations() {
    local base="$1"
    rm -f -- "$base.2.gz" "$base.2"
    if [ -f "$base.1.gz" ]; then
        mv -f -- "$base.1.gz" "$base.2.gz"
    elif [ -f "$base.1" ]; then
        mv -f -- "$base.1" "$base.2"
    fi
}

# rotate_one <path>: copytruncate one already-validated *.log file if it is
# at/over the size threshold.
rotate_one() {
    local f="$1" size

    if [ -L "$f" ]; then
        log "SKIP symlink (never followed): $f"
        return 0
    fi
    [ -f "$f" ] || return 0
    if ! is_log_file "$f"; then
        log "REFUSE non-.log target (bug in target list, not acting): $f"
        return 1
    fi

    size="$(file_size "$f")"
    case "$size" in ''|*[!0-9]*) size=0 ;; esac
    if [ "$size" -lt "$ROTATE_BYTES" ]; then
        return 0
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log "DRY-RUN would rotate $f (size=$size >= $ROTATE_BYTES)"
        return 0
    fi

    local lockfile="$f.logrotate.lock"
    (
        flock -x -w 30 9 || { log "FAIL could not acquire rotate lock for $f within 30s"; exit 1; }

        # Re-check size under the lock — another run may have already
        # rotated this file while we waited.
        size="$(file_size "$f")"
        case "$size" in ''|*[!0-9]*) size=0 ;; esac
        if [ "$size" -lt "$ROTATE_BYTES" ]; then
            log "SKIP (already rotated under lock): $f"
            exit 0
        fi

        rotate_generations "$f"

        # copytruncate: COPY first (preserves the node's open append fd),
        # THEN truncate the original file in place.
        cp -- "$f" "$f.1"
        : > "$f"

        if command -v gzip >/dev/null 2>&1; then
            gzip -f -- "$f.1"
        fi

        log "ROTATED $f (was size=$size bytes >= $ROTATE_BYTES; kept 2 generations)"
    ) 9>>"$lockfile"
    rm -f -- "$lockfile" 2>/dev/null || true
}

run_rotation() {
    local targets=()
    if [ -n "${ZCL_LOGROTATE_TARGETS:-}" ]; then
        # shellcheck disable=SC2206
        targets=($ZCL_LOGROTATE_TARGETS)
    else
        shopt -s nullglob
        while IFS= read -r line; do
            [ -n "$line" ] && targets+=("$line")
        done < <(default_targets)
        shopt -u nullglob
    fi

    if [ "${#targets[@]}" -eq 0 ]; then
        log "no target log files found (nothing to rotate)"
        return 0
    fi

    local rc=0
    for t in "${targets[@]}"; do
        rotate_one "$t" || rc=1
    done
    return "$rc"
}

# ── selftest (hermetic; fixture datadir, never touches a real node) ──────
st_fail() { echo "selftest: FAIL $*" >&2; exit 1; }

cmd_selftest() {
    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-logrotate-selftest.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT

    mkdir -p "$tmp/.zclassic-c23" "$tmp/.zclassic-c23-dev"

    # Oversized node.log (sparse file — no need to actually write 1 MiB of
    # bytes to prove the size-threshold path).
    truncate -s 2000000 "$tmp/.zclassic-c23/node.log"
    # Small node.log in the -dev variant: must NOT rotate.
    printf 'small log, below threshold\n' > "$tmp/.zclassic-c23-dev/node.log"
    # A non-.log file sitting right next to the target: must NEVER be
    # touched even if some future glob widened to catch it.
    printf 'not a log\n' > "$tmp/.zclassic-c23/node.dat"
    # mint-progress.log variant, also oversized.
    truncate -s 2000000 "$tmp/.zclassic-c23/mint-progress.log"

    HOME="$tmp" ZCL_LOGROTATE_ROTATE_BYTES=1000000 \
        bash "$0" > "$tmp/run.out" 2>&1 \
        || st_fail "run exited nonzero: $(cat "$tmp/run.out")"

    [ -s "$tmp/.zclassic-c23/node.log.1" ] || [ -s "$tmp/.zclassic-c23/node.log.1.gz" ] \
        || st_fail "expected node.log.1[.gz] generation after rotation"
    [ "$(file_size "$tmp/.zclassic-c23/node.log")" -eq 0 ] \
        || st_fail "node.log was not truncated in place after rotation"
    [ -f "$tmp/.zclassic-c23/node.dat" ] \
        || st_fail "non-.log sibling file was removed (must never be touched)"
    [ "$(cat "$tmp/.zclassic-c23/node.dat")" = "not a log" ] \
        || st_fail "non-.log sibling file content changed"
    [ "$(cat "$tmp/.zclassic-c23-dev/node.log")" = "small log, below threshold" ] \
        || st_fail "below-threshold node.log was rotated/truncated"
    [ -s "$tmp/.zclassic-c23/mint-progress.log.1" ] || [ -s "$tmp/.zclassic-c23/mint-progress.log.1.gz" ] \
        || st_fail "expected mint-progress.log.1[.gz] generation after rotation"
    echo "selftest: ok case=first-rotation"

    # Second oversized cycle must cap generations at 2 (.1 promotes to .2,
    # oldest .2 is dropped) and never leave a .3.
    truncate -s 2000000 "$tmp/.zclassic-c23/node.log"
    HOME="$tmp" ZCL_LOGROTATE_ROTATE_BYTES=1000000 \
        bash "$0" > "$tmp/run2.out" 2>&1 \
        || st_fail "second run exited nonzero: $(cat "$tmp/run2.out")"
    [ -f "$tmp/.zclassic-c23/node.log.2" ] || [ -f "$tmp/.zclassic-c23/node.log.2.gz" ] \
        || st_fail "expected node.log.2[.gz] after second rotation"
    [ ! -e "$tmp/.zclassic-c23/node.log.3" ] && [ ! -e "$tmp/.zclassic-c23/node.log.3.gz" ] \
        || st_fail "a .3 generation exists — generation cap of 2 was not enforced"
    echo "selftest: ok case=generation-cap"

    # Symlink target must be skipped, never followed/truncated.
    printf 'sensitive\n' > "$tmp/outside.log"
    ln -s "$tmp/outside.log" "$tmp/.zclassic-c23/node.log.symlink-test"
    ZCL_LOGROTATE_TARGETS="$tmp/.zclassic-c23/node.log.symlink-test" ZCL_LOGROTATE_ROTATE_BYTES=0 \
        bash "$0" > "$tmp/run3.out" 2>&1 \
        || st_fail "symlink run exited nonzero: $(cat "$tmp/run3.out")"
    [ "$(cat "$tmp/outside.log")" = "sensitive" ] \
        || st_fail "symlink target file was modified — must never be followed"
    echo "selftest: ok case=symlink-skipped"

    # --dry-run must never modify anything.
    truncate -s 2000000 "$tmp/.zclassic-c23-dev/node.log"
    HOME="$tmp" ZCL_LOGROTATE_ROTATE_BYTES=1000000 \
        bash "$0" --dry-run > "$tmp/run4.out" 2>&1 \
        || st_fail "dry-run exited nonzero: $(cat "$tmp/run4.out")"
    [ "$(file_size "$tmp/.zclassic-c23-dev/node.log")" -eq 2000000 ] \
        || st_fail "--dry-run modified a target file"
    echo "selftest: ok case=dry-run-noop"

    trap - EXIT
    rm -rf "$tmp"
    echo "selftest: PASS"
}

main() {
    case "${1:-}" in
        --selftest) shift; cmd_selftest "$@" ;;
        --dry-run) DRY_RUN=1; run_rotation ;;
        "") run_rotation ;;
        *)
            echo "usage: zcl-logrotate.sh [--dry-run] | --selftest" >&2
            exit 64
            ;;
    esac
}

main "$@"
