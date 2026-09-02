#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Driver for `make arena-view` and `make arena-view-check`.
#
# Plays the pinned seed-7 3v3 demo (or views REPLAY=<file>). CHECK=1 never
# opens a window: it re-derives the pinned demo roots and writes a
# deterministic 1280x720 PNG from the hosted C23 framebuffer + Inter HUD.
# The optional raylib window is opened only when that binary is present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

BIN="${ZCL_BIN_DIR:-$REPO_ROOT/build/bin}"
RUNNER="$BIN/arena_runner"
VIEW="$BIN/arena_view"
FRAME="$BIN/arena_frame"
ZDOGVIEW="$BIN/zdogview"
PILOT_RED="$BIN/pilot_zdogace"
PILOT_BLUE="$BIN/pilot_zdogdrone"
REPLAY_OUT="$BIN/arena-view-demo.replay"
PNG_OUT="$BIN/arena-view.png"
PNG_OUT_B="$BIN/arena-view.b.png"

RED_LABEL="Red Ace - zdogace 0.1.1"
BLUE_LABEL="Blue Drone - zdogdrone 0.1.0"
REF_REPLAY_ROOT=05ed352dbb2213aad289cdf403d424d18d9ae075db57252a52c4e745a25e8396
REF_STATE_ROOT=e4b37a9b94547cead91a7d4ae2a63b0385b29a99bb603bd0ac3519cebd270ebd

av_die()
{
    printf 'arena-view: FAILED: %s\n' "$*" >&2
    exit 1
}

av_expect_exit()
{
    local want="$1"
    shift
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq "$want" ] || av_die "$* : exit $rc, expected $want"
}

av_play_demo()
{
    rm -f "$REPLAY_OUT"
    local rc=0
    "$RUNNER" --seed 7 --planes-per-team 3 \
        --pilot-red "$PILOT_RED" --pilot-blue "$PILOT_BLUE" \
        --replay-out "$REPLAY_OUT" || rc=$?
    if [ "$rc" -eq 3 ]; then
        printf 'arena-view: kernel cannot confine pilots; retrying unconfined\n'
        rc=0
        "$RUNNER" --no-sandbox --seed 7 --planes-per-team 3 \
            --pilot-red "$PILOT_RED" --pilot-blue "$PILOT_BLUE" \
            --replay-out "$REPLAY_OUT" || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        av_die "arena_runner failed (exit $rc)"
    fi
    [ -f "$REPLAY_OUT" ] || av_die "no replay written"
}

av_png_magic()
{
    local path="$1"
    [ -s "$path" ] || av_die "PNG was empty: $path"
    local sig
    sig="$(dd if="$path" bs=8 count=1 2>/dev/null | od -An -tx1)"
    # PNG signature 89 50 4e 47 0d 0a 1a 0a
    case "$sig" in
        *"89 50 4e 47 0d 0a 1a 0a"*) ;;
        *) av_die "not a PNG signature: $path ($sig)" ;;
    esac
}

[ -x "$FRAME" ] || av_die "missing $FRAME (build tools/arena-frame first)"
[ -x "$RUNNER" ] || av_die "missing $RUNNER"

if [ "${CHECK:-}" = 1 ]; then
    av_expect_exit 0 "$FRAME" --help
    av_expect_exit 2 "$FRAME"
    av_expect_exit 2 "$FRAME" --tick
    av_expect_exit 2 "$FRAME" --png
    av_play_demo
    if [ -x "$ZDOGVIEW" ]; then
        "$ZDOGVIEW" verify "$REPLAY_OUT" >/dev/null || av_die "zdogview verify failed"
        ppm="$BIN/arena-view-hosted.ppm"
        "$ZDOGVIEW" render "$REPLAY_OUT" --out "$ppm" || av_die "zdogview render failed"
        [ -s "$ppm" ] || av_die "hosted PPM was empty"
        [ "$(head -1 "$ppm")" = "P6" ] || av_die "hosted view is not a P6 PPM"
    fi
    rm -f "$PNG_OUT" "$PNG_OUT_B"
    report="$("$FRAME" --replay "$REPLAY_OUT" --check-only --png "$PNG_OUT" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL")"
    printf '%s\n' "$report"
    case "$report" in
        *"replay_root=$REF_REPLAY_ROOT"*) ;;
        *) av_die "replay root mismatch: $report" ;;
    esac
    case "$report" in
        *"state_root=$REF_STATE_ROOT"*) ;;
        *) av_die "state root mismatch: $report" ;;
    esac
    case "$report" in
        *"png=1280x720"*) ;;
        *) av_die "PNG size missing from report: $report" ;;
    esac
    case "$report" in
        *"fonts=inter"*) ;;
        *) av_die "Inter HUD missing from report: $report" ;;
    esac
    av_png_magic "$PNG_OUT"
    "$FRAME" --replay "$REPLAY_OUT" --png "$PNG_OUT_B" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL" >/dev/null
    av_png_magic "$PNG_OUT_B"
    cmp -s "$PNG_OUT" "$PNG_OUT_B" || av_die "1280x720 PNG was not byte-identical across two renders"
    bad_label="$(printf 'Red\200Ace')"
    rc=0
    refuse="$("$FRAME" --replay "$REPLAY_OUT" --png "$PNG_OUT_B" \
        --red-label "$bad_label" --blue-label "$BLUE_LABEL" 2>&1)" || rc=$?
    [ "$rc" -eq 4 ] || av_die "non-ASCII red label: exit $rc, expected 4"
    case "$refuse" in
        *"HUD label is not Basic Latin"*) ;;
        *) av_die "non-ASCII red label missing typed refusal: $refuse" ;;
    esac
    rm -f "$PNG_OUT_B"
    printf 'arena-view-check: ok png=%s\n' "$PNG_OUT"
    exit 0
fi

if [ -n "${REPLAY:-}" ]; then
    [ -f "$REPLAY" ] || av_die "replay not found: $REPLAY"
    "$FRAME" --replay "$REPLAY" --png "$PNG_OUT" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL"
    if [ -x "$VIEW" ]; then
        exec "$VIEW" --show --replay "$REPLAY"
    fi
    printf 'arena-view: wrote %s (1280x720 hosted C23 framebuffer + Inter HUD)\n' "$PNG_OUT"
    printf 'arena-view: optional raylib window was not built (pkg-config raylib missing).\n'
    exit 0
fi

av_play_demo
"$FRAME" --replay "$REPLAY_OUT" --png "$PNG_OUT" \
    --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL"
if [ -x "$VIEW" ]; then
    exec "$VIEW" --show --replay "$REPLAY_OUT" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL"
fi
printf 'arena-view: wrote %s (1280x720 hosted C23 framebuffer + Inter HUD)\n' "$PNG_OUT"
printf 'arena-view: optional raylib window was not built (pkg-config raylib missing).\n'
printf 'arena-view: the measured picture is that PNG; Linux software path only on this host.\n'
exit 0
