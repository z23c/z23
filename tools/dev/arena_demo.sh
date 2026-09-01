#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# arena_demo.sh — the ZCODE Arena public demo, driven by `make arena-demo`.
#
# This is the first thing a new reader runs. It must therefore need NOTHING
# but a C compiler and this checkout: no blockchain sync, no Tor, no wallet,
# no browser, no JavaScript, no Python, no network, and no running node. It
# never opens a datadir, never binds a port, and never touches the live
# production nodes that share this host.
#
# What it does, in order:
#   [1] play one match between two CONFINED pilot processes (arena_runner
#       spawns each pilot under a Landlock domain granting read+execute on
#       the pilot image alone, plus the session seccomp W^X deny-list);
#   [2] re-simulate the recorded control stream with NO pilots and require
#       the match to reach DONE at exactly the recorded tick count with a
#       byte-identical final state;
#   [3] compare the three roots against the PINNED reference — the same
#       roots tools/dev/arena_acceptance.sh proved byte-identical across two
#       independent nodes that fetched, built and ran the packages
#       themselves;
#   [4] flip one byte of the recorded control stream in a COPY and require
#       verification to refuse it with a named mismatch, so the reader sees
#       that "verified" is a real predicate and not a printed adjective.
#
# Modes (set by the make targets; default is the demo):
#   ARENA_SVG_WRITE=1   also regenerate docs/assets/zcode-arena.svg
#   ARENA_SVG_CHECK=1   regenerate to a scratch file and require the
#                       committed artwork to be byte-identical
#   ARENA_OPT_PARITY=1  rebuild the pilots at -O0 and -O2 and require the
#                       same roots as the pinned -O1 pilots
#
# The pinned roots are the acceptance. A drift here is a real regression in
# the simulation, a pilot, or the replay container — never something to
# re-pin away. Re-pin only together with the evidence that re-derived them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

BIN="${ZCL_BIN_DIR:-$REPO_ROOT/build/bin}"
RUNNER="$BIN/arena_runner"
SVG_TOOL="$BIN/arena_svg"
PILOT_RED="$BIN/pilot_zdogace"
PILOT_BLUE="$BIN/pilot_zdogdrone"

# ── The pinned match ──────────────────────────────────────────────────────
# Seed 7, three planes per team, repo-source pilots. Identical to the
# 11941-tick reference leg of tools/dev/arena_acceptance.sh.
SEED=7
PLANES=3
RED_NAME="Red Ace"
BLUE_NAME="Blue Drone"
RED_LABEL="Red Ace — zdogace 0.1.1"
BLUE_LABEL="Blue Drone — zdogdrone 0.1.0"

REF_TICKS=11941
REF_WINNER=red
REF_SCORE_RED=10
REF_SCORE_BLUE=6
REF_REPLAY_ROOT=05ed352dbb2213aad289cdf403d424d18d9ae075db57252a52c4e745a25e8396
REF_FINAL_STATE_ROOT=e4b37a9b94547cead91a7d4ae2a63b0385b29a99bb603bd0ac3519cebd270ebd
REF_STATE_ROOT_CHAIN=657cbc598e8cfff4e3a67e0b11de17a6b576be686ae924149614eca3e156f87b

SVG_OUT="docs/assets/zcode-arena.svg"

WORK=""

ad_die()
{
    printf 'arena-demo: FAILED: %s\n' "$*" >&2
    exit 1
}

ad_cleanup()
{
    # Guarded: only ever a scratch directory this script created.
    case "$WORK" in
        "$REPO_ROOT"/test-tmp/arena-demo.*) rm -rf -- "$WORK" ;;
    esac
}
trap ad_cleanup EXIT HUP INT TERM

for b in "$RUNNER" "$SVG_TOOL" "$PILOT_RED" "$PILOT_BLUE"; do
    [ -x "$b" ] || ad_die "missing $b — run: make arena-demo"
done

mkdir -p "$REPO_ROOT/test-tmp"
WORK="$(mktemp -d "$REPO_ROOT/test-tmp/arena-demo.XXXXXX")"

# Read one `key=value` field out of a runner report.
ad_field()
{
    awk -v k="$2" '
        { for (i = 1; i <= NF; i++) {
              split($i, kv, "=")
              if (kv[1] == k) { print substr($i, length(k) + 2); exit }
          } }' "$1"
}

ad_expect()
{
    [ "$2" = "$3" ] || ad_die "$1: got '$2', expected '$3'"
}

# Pilot confinement is a property of the HOST KERNEL, not of the match.
# Landlock and seccomp bound what a pilot PROCESS may do; they are not
# inputs to the simulation, so a confined and an unconfined run of the same
# pilots produce the same replay byte for byte — which is why every
# assertion below stays at full strength in either mode.
#
# arena_runner refuses to run unconfined by default and exits 3 with a named
# reason when the kernel cannot confine (no Landlock, no seccomp, a
# container or VM that blocks either). That refusal is right for a tool. It
# is wrong for a first impression: a reader on macOS under a VM, on WSL, on
# an older kernel, or inside a locked-down container would clone the repo,
# run the one command the README gives them, and get exit 3 — with nothing
# to look at and no idea their machine was fine. So fall back exactly once,
# print which mode ran in plain words, and never soften a check for it.
AD_SANDBOX="confined"
AD_SANDBOX_ARGS=()

ad_run_once()
{
    local rc=0
    "$RUNNER" --seed "$SEED" --planes-per-team "$PLANES" \
        --pilot-red "$1" --pilot-blue "$2" --replay-out "$3" \
        "${AD_SANDBOX_ARGS[@]}" > "$4" 2>"$4.err" || rc=$?
    return "$rc"
}

# Play one match with the given pilots and report file.
ad_play()
{
    local rc=0
    ad_run_once "$@" || rc=$?
    if [ "$rc" -eq 3 ] && [ "$AD_SANDBOX" = confined ]; then
        AD_SANDBOX="unconfined"
        AD_SANDBOX_ARGS=(--no-sandbox)
        rc=0
        ad_run_once "$@" || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        cat "$4.err" >&2
        ad_die "arena_runner failed (exit $rc)"
    fi
}

# Assert one report's fields and roots against the pinned reference.
ad_assert_reference()
{
    local report="$1" what="$2"
    ad_expect "$what ticks" "$(ad_field "$report" ticks)" "$REF_TICKS"
    ad_expect "$what winner" "$(ad_field "$report" winner)" "$REF_WINNER"
    ad_expect "$what score_red" "$(ad_field "$report" score_red)" \
        "$REF_SCORE_RED"
    ad_expect "$what score_blue" "$(ad_field "$report" score_blue)" \
        "$REF_SCORE_BLUE"
    ad_expect "$what replay_root" "$(ad_field "$report" replay_root)" \
        "$REF_REPLAY_ROOT"
    ad_expect "$what final_state_root" \
        "$(ad_field "$report" final_state_root)" "$REF_FINAL_STATE_ROOT"
    ad_expect "$what state_root_chain" \
        "$(ad_field "$report" state_root_chain)" "$REF_STATE_ROOT_CHAIN"
}

# ── [1] play ──────────────────────────────────────────────────────────────
REPLAY="$WORK/match.replay"
REPORT="$WORK/match.out"
ad_play "$PILOT_RED" "$PILOT_BLUE" "$REPLAY" "$REPORT"

TICKS="$(ad_field "$REPORT" ticks)"
SCORE_RED="$(ad_field "$REPORT" score_red)"
SCORE_BLUE="$(ad_field "$REPORT" score_blue)"
WINNER="$(ad_field "$REPORT" winner)"
REPLAY_ROOT="$(ad_field "$REPORT" replay_root)"
FINAL_STATE_ROOT="$(ad_field "$REPORT" final_state_root)"
STATE_ROOT_CHAIN="$(ad_field "$REPORT" state_root_chain)"

# ── [2] re-simulate and verify ────────────────────────────────────────────
VERIFY="$WORK/verify.out"
"$RUNNER" --verify-replay "$REPLAY" > "$VERIFY" 2>&1 \
    || { cat "$VERIFY" >&2; ad_die "replay verification refused the match"; }
grep -qx 'verify=ok' "$VERIFY" || ad_die "replay verification did not report ok"
ad_expect "verified replay_root" "$(ad_field "$VERIFY" replay_root)" \
    "$REPLAY_ROOT"
ad_expect "verified final_state_root" \
    "$(ad_field "$VERIFY" final_state_root)" "$FINAL_STATE_ROOT"

# ── [3] the pinned regression ─────────────────────────────────────────────
ad_assert_reference "$REPORT" "played match"

# ── [4] one altered control byte must be refused, by name ─────────────────
TAMPERED="$WORK/tampered.replay"
cp -- "$REPLAY" "$TAMPERED"
# Offset 64 lands inside the recorded control stream: the 21-byte header is
# magic(8) + version(4) + seed(8) + planes(1), so everything past it up to
# the trailing 2163-byte state block is ctl frames.
printf '\xa5' | dd of="$TAMPERED" bs=1 seek=64 count=1 conv=notrunc \
    status=none
if cmp -s -- "$REPLAY" "$TAMPERED"; then
    ad_die "the tamper leg changed nothing"
fi
TAMPER_OUT="$WORK/tampered.out"
if "$RUNNER" --verify-replay "$TAMPERED" > "$TAMPER_OUT" 2>&1; then
    ad_die "an altered replay verified — the tamper gate is hollow"
fi
TAMPER_REASON="$(sed -n 's/^verify=MISMATCH //p' "$TAMPER_OUT" | head -n1)"
[ -n "$TAMPER_REASON" ] \
    || ad_die "altered replay was refused without a named mismatch"

# ── optional: -O0/-O2 pilot parity ────────────────────────────────────────
OPT_PARITY_LINE=""
if [ "${ARENA_OPT_PARITY:-0}" = 1 ]; then
    for opt in -O0 -O2; do
        cc -std=c23 "$opt" -static -D_POSIX_C_SOURCE=200809L \
            -Icontexts/commons/packages/zdogace/include -Icontexts/commons/packages/zdogfight/include \
            -Icontexts/commons/packages/zprng/include \
            contexts/commons/packages/zdogace/app/main.c contexts/commons/packages/zdogace/src/zdogace.c \
            contexts/commons/packages/zdogfight/src/zdogfight.c \
            contexts/commons/packages/zdogfight/src/zdogfix.c contexts/commons/packages/zprng/src/zprng.c \
            -o "$WORK/red$opt" -lm || ad_die "pilot build failed at $opt"
        cc -std=c23 "$opt" -static -D_POSIX_C_SOURCE=200809L \
            -Icontexts/commons/packages/zdogdrone/include -Icontexts/commons/packages/zdogfight/include \
            -Icontexts/commons/packages/zprng/include \
            contexts/commons/packages/zdogdrone/app/main.c contexts/commons/packages/zdogdrone/src/zdogdrone.c \
            contexts/commons/packages/zdogfight/src/zdogfight.c \
            contexts/commons/packages/zdogfight/src/zdogfix.c contexts/commons/packages/zprng/src/zprng.c \
            -o "$WORK/blue$opt" -lm || ad_die "pilot build failed at $opt"
        ad_play "$WORK/red$opt" "$WORK/blue$opt" "$WORK/replay$opt" \
            "$WORK/report$opt"
        ad_assert_reference "$WORK/report$opt" "pilots built at $opt"
        cmp -s -- "$REPLAY" "$WORK/replay$opt" \
            || ad_die "pilots built at $opt produced a different replay"
    done
    OPT_PARITY_LINE="Pilot -O0/-O1/-O2 parity:  IDENTICAL"
fi

# ── optional: artwork ─────────────────────────────────────────────────────
SVG_LINE=""
if [ "${ARENA_SVG_WRITE:-0}" = 1 ]; then
    mkdir -p "$(dirname "$SVG_OUT")"
    "$SVG_TOOL" --replay "$REPLAY" --out "$SVG_OUT" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL" >/dev/null \
        || ad_die "arena_svg refused to render the verified replay"
    SVG_LINE="Wrote $SVG_OUT"
elif [ "${ARENA_SVG_CHECK:-0}" = 1 ]; then
    [ -f "$SVG_OUT" ] || ad_die "$SVG_OUT is missing — run: make arena-svg"
    "$SVG_TOOL" --replay "$REPLAY" --out "$WORK/fresh.svg" \
        --red-label "$RED_LABEL" --blue-label "$BLUE_LABEL" >/dev/null \
        || ad_die "arena_svg refused to render the verified replay"
    cmp -s -- "$SVG_OUT" "$WORK/fresh.svg" \
        || ad_die "$SVG_OUT is STALE — regenerate it with: make arena-svg"
    SVG_LINE="$SVG_OUT is current"
fi

# ── report ────────────────────────────────────────────────────────────────
# Human-readable result first, roots after: a reader should learn what
# happened before being asked to check it.
if [ "$WINNER" = red ]; then
    HEADLINE="$RED_NAME defeated $BLUE_NAME $SCORE_RED-$SCORE_BLUE"
elif [ "$WINNER" = blue ]; then
    HEADLINE="$BLUE_NAME defeated $RED_NAME $SCORE_BLUE-$SCORE_RED"
else
    HEADLINE="$RED_NAME drew with $BLUE_NAME $SCORE_RED-$SCORE_BLUE"
fi

# Thousands separators without a locale: printf's %'d groups according to
# LC_NUMERIC, which would make this script's output host-dependent.
TICKS_PRETTY="$(printf '%s' "$TICKS" | sed -e ':a' -e 's/\B[0-9]\{3\}\>/,&/;ta')"

printf '\n'
printf 'ZCODE ARENA\n'
printf '%s\n' "$HEADLINE"
printf '%s deterministic ticks\n' "$TICKS_PRETTY"
printf '\n'
printf 'Replay verification:       MATCH\n'
printf 'Result vs pinned roots:    MATCH\n'
printf 'Altered control byte:      REFUSED (%s)\n' "$TAMPER_REASON"
if [ "$AD_SANDBOX" = confined ]; then
    printf 'Pilot confinement:         Landlock + seccomp\n'
else
    printf 'Pilot confinement:         UNAVAILABLE on this kernel — pilots ran\n'
    printf '                           unconfined. The match is unaffected:\n'
    printf '                           confinement bounds a pilot process, it\n'
    printf '                           is not an input to the simulation.\n'
fi
if [ -n "$OPT_PARITY_LINE" ]; then printf '%s\n' "$OPT_PARITY_LINE"; fi
printf '\n'
printf 'Seed:                      %s (%sv%s)\n' "$SEED" "$PLANES" "$PLANES"
printf 'Red pilot:                 %s\n' "$RED_LABEL"
printf 'Blue pilot:                %s\n' "$BLUE_LABEL"
printf 'Replay root:               %s\n' "$REPLAY_ROOT"
printf 'Final-state root:          %s\n' "$FINAL_STATE_ROOT"
printf 'State-root chain:          %s\n' "$STATE_ROOT_CHAIN"
if [ -n "$SVG_LINE" ]; then printf '\n%s\n' "$SVG_LINE"; fi
printf '\n'
printf 'Any node that builds these exact sources reproduces these exact\n'
printf 'roots. See docs/ARENA.md.\n'
