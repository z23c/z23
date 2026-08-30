#!/usr/bin/env bash
# Gate — ONE hex codec (ratchet, shrink-only file list).
#
# What it enforces
# ----------------
# Base-16 encode/decode of a byte buffer lives in exactly one place:
# lib/base/include/base/hex.h (zcl_hex_encode / zcl_hex_decode /
# zcl_hex_decode_lower / zcl_hex_decode_n / zcl_hex_nibble). No production
# file outside lib/base may carry its own.
#
# Why
# ---
# lib/encoding exported only the raw `p_util_hexdigit` lookup table, never a
# bytes<->hex function, so every module that needed one wrote it again.
# Measured when this gate was written: 56 files. They did not agree —
# some validated the input length, some did not; some accepted A-F, some
# silently rejected it; one used sscanf("%2x") and so accepted " 1" and
# "+1"; several left the caller's buffer half-written on a failed decode,
# and native_zcode_reward_command.c then read an uninitialised 32-byte root
# out of one of them. A codec pile is not a style problem: each copy is an
# independent chance to disagree about what a valid input is.
#
# Unit of measurement
# -------------------
# Per FILE, by two independent shape detectors, either of which marks the
# file as carrying a codec:
#
#   ENCODER — a lowercase/uppercase hex-digit TABLE ("0123456789abcdef")
#             anywhere in the file, AND a high-nibble index somewhere in the
#             file (">> 4)" or ">> 4]"). Both together, because either alone
#             is common and innocent: the table is also a charset validator
#             and a random-id alphabet, and ">> 4" is ordinary bit work.
#   DECODER — nibble-ladder arithmetic ("- 'a' + 10" / "- 'A' + 10") or a
#             two-digit hex scanf ("%2x").
#
# File granularity, not per-function: a shell scan cannot reliably bound a C
# function, and a gate that guesses is a gate that lies. Over-attribution is
# harmless here — a file with no codec matches neither detector.
#
# Excluded from the scan, with reasons:
#   lib/base/  — the canonical home. It IS the codec.
#   lib/test/  — a test fixture must parse its known-answer vectors with an
#                implementation independent of the one under test. Checking
#                zcl_hex_decode with zcl_hex_decode proves nothing.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches must be DELETED, or the ratchet
# rusts shut at a stale list. That is reported as a failure too.
#
# --selftest plants a fresh encoder and a fresh decoder in a sandbox and
# requires a FAIL on each, then a file that calls the canonical helpers and
# requires a PASS — so a gate whose regexes have quietly stopped matching
# cannot keep reporting PASS.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_hex_codec_single
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_HEX_CODEC_BASELINE:-tools/lint/hex_codec_baseline.txt}"

SCAN_ROOTS_DEFAULT="app config lib src tools"
read -r -a SCAN_ROOTS <<< "${ZCL_HEX_CODEC_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

RE_TABLE="0123456789(abcdef|ABCDEF)"
RE_NIBBLE_HI=">> *4[])]"
RE_LADDER="- *'[aA]' *\+ *10"
RE_SCANF='"%2x"'

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/app/services/src"
    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    plant() { printf '%s\n' "$1" > "$tmp/app/services/src/selftest_hex.c"; }

    run_sandbox() {
        ZCL_HEX_CODEC_SCAN_ROOTS="$tmp/app" \
        ZCL_HEX_CODEC_COVERAGE=0 \
        ZCL_HEX_CODEC_FILE_FLOOR=1 \
        ZCL_HEX_CODEC_BASELINE="$tmp/empty_baseline.txt" \
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

    expect fail "a fresh private hex ENCODER did not fail the gate" \
'static void my_hex(const unsigned char *in, size_t n, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * n] = 0;
}'

    expect fail "a fresh private hex DECODER (nibble ladder) did not fail the gate" \
"static int my_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}"

    expect fail "a fresh private hex DECODER (sscanf %2x) did not fail the gate" \
'static int my_decode(const char *hex, unsigned char *out, int n)
{
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    return 1;
}'

    # The table ALONE is not a codec — a charset validator and a random-id
    # alphabet both carry it, and failing those would make the gate noise.
    expect pass "a bare hex-digit alphabet with no nibble work was flagged" \
'static int is_hexish(char c)
{
    static const char alphabet[] = "0123456789abcdef";
    return strchr(alphabet, c) != NULL;
}'

    expect pass "a file calling the canonical codec was flagged" \
'#include "base/hex.h"
static void emit(const unsigned char id[32], char out[65])
{
    zcl_hex_encode(id, 32, out);
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
        ZCL_HEX_CODEC_SCAN_ROOTS="app config lib src" ZCL_HEX_CODEC_FILE_FLOOR=1
    # (c) a shortfall SMALLER than the recorded allowance is a stale
    #     ratchet, exit 1 — an allowance that may only rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_HEX_CODEC_COVERAGE_ALLOWANCE=1

    echo "[$GATE] SELFTEST PASS (private encoder, nibble ladder and %2x decode all fail; bare alphabet and canonical caller pass; a full scan clears coverage, a scan short one declared root is UNPROVEN exit 2, a stale allowance is exit 1)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" \( -name '*.c' -o -name '*.h' \) -type f \
            ! -path 'lib/base/*' \
            ! -path 'lib/test/*' \
            2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files | sort)
gate_require_scanned "${#scan_files[@]}" "${ZCL_HEX_CODEC_FILE_FLOOR:-800}" "$GATE" \
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
# lib/base + lib/test carve-outs the find applies, never from the
# (overridable) SCAN_ROOTS actually in use, so aiming this gate at a subset
# reads as a shortfall rather than as a quiet redefinition of "covered".
#
# Scope, unchanged. lib/base is carved out because it DEFINES the canonical
# codec this gate requires callers to use, lib/test because a fixture may
# legitimately hand-roll one. Tracked sources outside SCAN_ROOTS_DEFAULT
# (core/, domain/, adapters/, packages/, examples/) were never in this
# gate's declared surface and are not added here — widening the roots is a
# separate, riskier change needing its own clean-tree proof.
#
# Allowance 0, shrink-only: the find reaches every tracked file the oracle
# names today (measured: expected 3598, scanned 3598, missing 0), so any
# shortfall at all is UNPROVEN.
HEX_CODEC_COVERAGE_ALLOWANCE="${ZCL_HEX_CODEC_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_HEX_CODEC_COVERAGE:-1}" = "1" ]; then
    cov_specs=()
    for cov_root in $SCAN_ROOTS_DEFAULT; do
        cov_specs+=("$cov_root/*.c" "$cov_root/*.h")
    done
    cov_specs+=(':!:lib/base/*' ':!:lib/test/*')
    gate_require_git_coverage - "$HEX_CODEC_COVERAGE_ALLOWANCE" "$GATE" \
        ZCL_HEX_CODEC_COVERAGE_ALLOWANCE \
        "Re-run from a clean checkout. A named file that genuinely left this gate's surface belongs outside $SCAN_ROOTS_DEFAULT or in an explicit carve-out beside lib/base and lib/test — not in a raised allowance." \
        -- "${cov_specs[@]}" < <(printf '%s\n' "${scan_files[@]}")
fi

# ── Detect ───────────────────────────────────────────────────────────────
# One grep pass per pattern over the whole scan set (not one grep per file):
# the decoder list is a union, the encoder list is an intersection.
mapfile -t DEC_FILES < <(gate_grep -lE -e "$RE_LADDER" -e "$RE_SCANF" -- "${scan_files[@]}" | sort -u)
mapfile -t TBL_FILES < <(gate_grep -lE -e "$RE_TABLE" -- "${scan_files[@]}" | sort -u)
mapfile -t NIB_FILES < <(gate_grep -lE -e "$RE_NIBBLE_HI" -- "${scan_files[@]}" | sort -u)

mapfile -t FOUND < <(
    {
        printf '%s\n' ${DEC_FILES[@]+"${DEC_FILES[@]}"}
        comm -12 <(printf '%s\n' ${TBL_FILES[@]+"${TBL_FILES[@]}"}) \
                 <(printf '%s\n' ${NIB_FILES[@]+"${NIB_FILES[@]}"})
    } | sed '/^$/d' | sort -u
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
        echo "# $GATE baseline — production files that still carry their own"
        echo "# hex encode/decode instead of lib/base/include/base/hex.h."
        echo "# One path per line. THE LIST MAY ONLY SHRINK."
        echo "#"
        echo "# Fix a row by deleting the private codec and calling:"
        echo "#   zcl_hex_encode(in, len, out)          lowercase, NUL-terminated"
        echo "#   zcl_hex_decode(hex, out, want)        exact length, [0-9a-fA-F]"
        echo "#   zcl_hex_decode_lower(hex, out, want)  canonical form only"
        echo "#   zcl_hex_decode_n(hex, out, cap, &n)   1..cap bytes"
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
    echo "[$GATE] ${#violations[@]} file(s) carry a private hex encoder or"
    echo "        decoder outside lib/base:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Delete it and include \"base/hex.h\" instead:"
    echo "    zcl_hex_encode(in, len, out)          lowercase, NUL-terminated"
    echo "    zcl_hex_decode(hex, out, want)        exact length, [0-9a-fA-F]"
    echo "    zcl_hex_decode_lower(hex, out, want)  canonical (lowercase) only,"
    echo "                                          for on-disk names"
    echo "    zcl_hex_decode_n(hex, out, cap, &n)   1..cap bytes"
    echo "    zcl_hex_nibble(c, allow_upper)        one character, for parsing"
    echo "                                          a length-delimited slice"
    echo "  Adding a row to $BASELINE is NOT a fix; the list may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer"
    echo "        carries a private hex codec. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files scanned, ${#FOUND[@]} still carrying a private codec, all $baseline_count baselined)"
