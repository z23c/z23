#!/usr/bin/env bash
# Gate — ONE fixed-width byte-order codec (ratchet, shrink-only file list).
#
# What it enforces
# ----------------
# Loading and storing a 16/32/64-bit integer at a byte address in a declared
# byte order lives in exactly one place: platform/modules/base/include/base/serialize_le.h
# (zcl_write_u{16,32,64}_le / zcl_read_u{16,32,64}_le, the i32/i64 forms, and
# the u32/u64 big-endian pair). No production file outside platform/modules/base may carry
# its own — including via core/modules/crypto/include/crypto/common.h, which now
# forwards ReadLE/WriteLE to the canonical header rather than defining them.
#
# Why
# ---
# A canonical set already existed in crypto/common.h and only SEVEN files
# used it. Everyone else re-wrote the shift ladder as a file-private static:
# 23 hand-rolled helpers at the time this gate was written, across 11 files,
# under 18 different names for the same 8 lines. Two symptoms are worth
# naming, because they are what a codec pile actually costs:
#
#   - contexts/wallet/modules/zid defined the family THREE times inside ONE module, under three
#     prefixes (put_le64, zdesc_put_le64, zendp_put_le64) — three chances
#     for one module to disagree with itself about its own wire format.
#   - consensus_state_snapshot_candidate.c wrote a persisted 8-byte field
#     with `le64_encode` and consensus_state_snapshot_candidate_validate.c
#     read it back with `le64_decode`: the encoder and decoder for ONE field,
#     in two files, under two names, with nothing but a reader's memory
#     tying them together. Nothing would have failed at compile time if one
#     of them had been edited.
#
# Byte order is a wire and disk contract, so a disagreement between two
# copies is not a style regression, it is a corruption bug.
#
# Unit of measurement
# -------------------
# Per FILE, by three independent shape detectors, any of which marks the
# file as carrying a codec:
#
#   LADDER_LOOP  — an indexed shift loop over a byte array, i.e. a shift by
#                  `8 * i` / `8u * i` in either direction. This is the
#                  dominant form (14 of the 23).
#   LADDER_FLAT  — an unrolled ladder: a shift by 24 or 56 (the top byte of
#                  a 32- or 64-bit width) appearing with a byte-array
#                  subscript on the same line. Bare `>> 24` is NOT enough —
#                  it is ordinary bit work — so the subscript is required.
#   BSWAP        — a hand-rolled byte-swap: the 0x00FF00FF-family masks that
#                  only appear in one.
#
# File granularity, not per-function: a shell scan cannot reliably bound a C
# function, and a gate that guesses is a gate that lies.
#
# Excluded from the scan, with reasons:
#   platform/modules/base/  — the canonical home. It IS the codec.
#   tests/harness/include/test/  — a test MUST hold an independent implementation of what it
#                checks. test_byte_order_codec.c deliberately carries a
#                verbatim copy of all 23 replaced helpers and asserts the
#                canonical functions agree with them byte for byte; that is
#                the proof nothing on disk moved, and it only works because
#                the copies are still there.
#   core/      — byte-sealed (core/MANIFEST.sha3). Not editable by this
#                gate's audience, so flagging it would be noise that can
#                never be actioned. core/math/serialize.h is the stream
#                codec, a different shape, and core's two callers of the
#                fixed-width form reach it through crypto/common.h.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches must be DELETED, or the ratchet
# rusts shut at a stale list. That is reported as a failure too.
#
# --selftest plants a fresh helper of each detected shape in a sandbox and
# requires a FAIL on each, then plants innocent files (a bare `>> 24`, a
# loop with no shift) and a canonical caller and requires a PASS — so a gate
# whose regexes have quietly stopped matching cannot keep reporting PASS.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/repo_shape.sh
. tools/lint/repo_shape.sh

GATE=check_byte_order_codec_single
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_BYTE_ORDER_BASELINE:-tools/lint/byte_order_codec_baseline.txt}"

SCAN_ROOTS_DEFAULT="$(repo_shape_dirs app | tr '\n' ' ')${ZCL_MODULE_DIRS[*]} engine/composition engine/entry tools"
SCAN_ROOTS_REDUCED="${SCAN_ROOTS_DEFAULT% tools}"
read -r -a SCAN_ROOTS <<< "${ZCL_BYTE_ORDER_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

# An indexed shift loop: `>> (8 * i)`, `<< (8u * i)`, `>> (i * 8)`, ...
RE_LADDER_LOOP='(>>|<<) *\( *8u? *\* *[a-z_][a-z_0-9]* *\)|(>>|<<) *\( *[a-z_][a-z_0-9]* *\* *8u? *\)'
# An unrolled ladder: a top-byte shift AND a byte-array subscript, same line.
RE_LADDER_FLAT='\[[^]]*\][^;]*(>>|<<) *(24|56)\b|(>>|<<) *(24|56)[^;]*\[[^]]*\]'
# A hand-rolled byte swap.
RE_BSWAP='0x00FF00FF|0x00ff00ff|0x00FF000000FF0000|0xFF00FF00FF00FF00'

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/engine/services/src"
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    plant() { printf '%s\n' "$1" > "$tmp/engine/services/src/selftest_le.c"; }

    run_sandbox() {
        ZCL_BYTE_ORDER_SCAN_ROOTS="$tmp/engine" \
        ZCL_BYTE_ORDER_COVERAGE=0 \
        ZCL_BYTE_ORDER_FILE_FLOOR=1 \
        ZCL_BYTE_ORDER_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = fail|pass, $2 = message, $3 = file body
        local want="$1" msg="$2" rc=0
        plant "$3"
        run_sandbox || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    # ── negative controls: each detected shape must FAIL ──
    expect fail "a fresh private LE store written as a shift loop did not fail" \
'static void my_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}'

    expect fail "a fresh private LE load written as a shift loop did not fail" \
'static uint64_t my_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}'

    expect fail "the reversed operand order (i * 8) did not fail" \
'static void my_put(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}'

    expect fail "an UNROLLED private LE store did not fail" \
'static void my_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}'

    expect fail "an UNROLLED private LE load did not fail" \
'static uint32_t my_get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}'

    expect fail "a hand-rolled byte swap did not fail" \
'static uint32_t my_bswap32(uint32_t x)
{
    return ((x >> 24) & 0xFFu) | ((x >> 8) & 0x0000FF00u) |
           ((x << 8) & 0x00FF00FF) | ((x << 24) & 0xFF000000u);
}'

    # ── positive controls: innocent code must PASS, or the gate is noise ──
    expect pass "a bare top-byte shift with no byte array was flagged" \
'static uint32_t high_octet(uint32_t v)
{
    return (v >> 24) & 0xFFu;
}'

    expect pass "an ordinary indexed loop with no shift was flagged" \
'static uint32_t checksum(const uint8_t *p, size_t n)
{
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc += p[i];
    return acc;
}'

    expect pass "a file calling the canonical codec was flagged" \
'#include "base/serialize_le.h"
static void emit(uint8_t *p, uint64_t height)
{
    zcl_write_u64_le(p, height);
}'

    # COVERAGE, three answers not two. The floor above is calibrated to
    # detect "nothing happened"; these three prove the coverage check
    # detects "less happened than should have", which no file count can.
    # Each case re-invokes this gate for real against the true tree (no
    # --selftest arg, so no recursion) and settles at the coverage check
    # before the detectors run.
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL
        local want="$1" msg="$2" rc=0
        shift 2
        env "$@" "$self" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "$GATE: SELFTEST FAILED — $msg (wanted exit $want, got $rc)" >&2
            exit 2
        fi
    }
    # (a) the complete scan clears its own expectation.
    cov_case 0 "the complete scan did not pass its coverage expectation" \
        ZCL_LINT_MODE=FAIL
    # (b) a scan deliberately reduced below the expectation (one declared
    #     root dropped) is UNPROVEN exit 2 — never 0, never 1. The floor
    #     cannot see this: the reduced set still towers over 800.
    cov_case 2 "a scan missing a whole declared root was not UNPROVEN" \
        ZCL_BYTE_ORDER_SCAN_ROOTS="$SCAN_ROOTS_REDUCED" ZCL_BYTE_ORDER_FILE_FLOOR=1
    # (c) a shortfall SMALLER than the recorded allowance is a stale
    #     ratchet, exit 1 — an allowance that may only rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_BYTE_ORDER_COVERAGE_ALLOWANCE=1

    echo "[$GATE] SELFTEST PASS (shift-loop, reversed-operand, unrolled store, unrolled load and hand-rolled bswap all fail; bare shift, plain loop and canonical caller pass; a full scan clears coverage, a scan short one declared root is UNPROVEN exit 2, a stale allowance is exit 1)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" \( -name '*.c' -o -name '*.h' \) -type f \
            ! -path 'platform/modules/base/*' \
            ! -path 'contexts/commons/packages/*' \
            ! -path 'tests/harness/include/test/*' \
            2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files | sort)
gate_require_scanned "${#scan_files[@]}" "${ZCL_BYTE_ORDER_FILE_FLOOR:-800}" "$GATE" \
    "no production .c/.h under: ${SCAN_ROOTS[*]}"

# ── Coverage: did the scan reach everything it claims to cover? ──────────
# The floor above answers "did the scan produce anything at all". It cannot
# answer "did it produce everything it should have", and here the two are
# nowhere near each other: the realized set is 3598 .c/.h files against a
# floor of 800 — measured 2026-08-30, this gate could silently lose 2797
# files, 78% of its own surface, and still report clean. That is not a floor
# doing its job badly; it is a floor answering a different question.
#
# The expectation is derived from the git index, which knows nothing about
# the find above — the two cannot fail together, which is the whole point of
# an independent oracle. It is derived from SCAN_ROOTS_DEFAULT and the same
# platform/modules/base + lib/test carve-outs the find applies, never from the
# (overridable) SCAN_ROOTS actually in use, so aiming this gate at a subset
# reads as a shortfall rather than as a quiet redefinition of "covered".
#
# Scope, unchanged. platform/modules/base is carved out because it DEFINES the canonical
# codec this gate requires callers to use, lib/test because a fixture may
# legitimately hand-roll one. Tracked sources outside SCAN_ROOTS_DEFAULT
# (core/, domain/, platform/adapters/, contexts/commons/packages/, examples/) were never in this
# gate's declared surface and are not added here — widening the roots is a
# separate, riskier change needing its own clean-tree proof.
#
# Allowance 0, shrink-only: the find reaches every tracked file the oracle
# names today (measured: expected 3598, scanned 3598, missing 0), so any
# shortfall at all is UNPROVEN.
BYTE_ORDER_COVERAGE_ALLOWANCE="${ZCL_BYTE_ORDER_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_BYTE_ORDER_COVERAGE:-1}" = "1" ]; then
    cov_specs=()
    for cov_root in $SCAN_ROOTS_DEFAULT; do
        cov_specs+=("$cov_root/*.c" "$cov_root/*.h")
    done
    cov_specs+=(':!:platform/modules/base/*' ':!:contexts/commons/packages/*' ':!:tests/harness/include/test/*')
    gate_require_git_coverage - "$BYTE_ORDER_COVERAGE_ALLOWANCE" "$GATE" \
        ZCL_BYTE_ORDER_COVERAGE_ALLOWANCE \
        "Re-run from a clean checkout. A named file that genuinely left this gate's surface belongs outside $SCAN_ROOTS_DEFAULT or in an explicit carve-out beside platform/modules/base and lib/test — not in a raised allowance." \
        -- "${cov_specs[@]}" < <(printf '%s\n' "${scan_files[@]}")
fi

# ── Detect ───────────────────────────────────────────────────────────────
# One grep pass per pattern over the whole scan set (not one grep per file).
# The three detectors are a union: any one of them marks the file.
mapfile -t FOUND < <(
    gate_grep -lE -e "$RE_LADDER_LOOP" -e "$RE_LADDER_FLAT" -e "$RE_BSWAP" \
        -- "${scan_files[@]}" | sed '/^$/d' | sort -u
)

declare -A BASELINED=()
gate_load_list_file "$BASELINE" BASELINED baseline_count

declare -A HIT=()
violations=()
for path in "${FOUND[@]}"; do
    if [ -n "${BASELINED[$path]+x}" ]; then
        HIT["$path"]=1
    else
        violations+=("$path")
    fi
done

stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path")
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — production files that still pack or unpack a"
        echo "# fixed-width integer by hand instead of calling"
        echo "# platform/modules/base/include/base/serialize_le.h."
        echo "# One path per line. THE LIST MAY ONLY SHRINK."
        echo "#"
        echo "# Fix a row by deleting the private helper and calling:"
        echo "#   zcl_write_u16_le/u32_le/u64_le(p, v)   store, LSB at p[0]"
        echo "#   zcl_read_u16_le/u32_le/u64_le(p)       load, LSB at p[0]"
        echo "#   zcl_write_i32_le/i64_le, zcl_read_i32_le/i64_le"
        echo "#   zcl_write_u32_be/u64_be, zcl_read_u32_be/u64_be"
        echo "# then delete the line here. Adding a row is not a fix."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        printf '%s\n' "${FOUND[@]}" | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} file(s) pack or unpack a fixed-width"
    echo "        integer by hand outside platform/modules/base:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Delete it and include \"base/serialize_le.h\" instead:"
    echo "    zcl_write_u16_le(p, v)  zcl_read_u16_le(p)"
    echo "    zcl_write_u32_le(p, v)  zcl_read_u32_le(p)"
    echo "    zcl_write_u64_le(p, v)  zcl_read_u64_le(p)"
    echo "    zcl_write_i32_le/i64_le, zcl_read_i32_le/i64_le  (two's"
    echo "                            complement bits, no extra encoding)"
    echo "    zcl_write_u32_be/u64_be, zcl_read_u32_be/u64_be  (network"
    echo "                            order: PNG, BIP32, the SHA/AES cores)"
    echo "  Unaligned addresses are fine — every access goes through memcpy."
    echo "  Adding a row to $BASELINE is NOT a fix; the list may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer"
    echo "        packs an integer by hand. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files scanned, ${#FOUND[@]} still packing by hand, all $baseline_count baselined)"
