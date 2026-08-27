#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_module_imports.sh — a hot-swap module may import only what
# config/hotswap_module_imports.def allows.
#
# ── THE INVARIANT ──────────────────────────────────────────────────────────
# A Tier-2 hot-swap module is a .so compiled from ONE shape-leaf TU and
# dlopen'd into the LIVE node's address space. Every body it does not define
# itself is resolved out of the resident image at load time. So the module's
# UNDEFINED dynamic-symbol set IS its complete interface to the node — a
# device-driver contract, mechanically derivable from the artifact, and until
# this gate existed, enforced nowhere.
#
# That absence was reachable. None of the existing hot-swap gates looks at
# what a module LINKS AGAINST: check-hotswap-swappable-shape checks the TU's
# PATH and its leaves' READY/read-only spec, check-hotswap-static-state checks
# mutable file-scope statics, check-core-seal-root-mirror checks the sealed
# consensus pin, check-hotswap-package-receipt-is-not-authority checks that
# admission re-derives its facts. A controller edit that added one `#include`
# and one call would acquire a door into the reducer, the coins view, the
# wallet spend path or chain state, pass all of them, and mount — with no diff
# a reviewer could read as a reach change, because the change is an #include.
#
# ── WHAT IS ASSERTED ───────────────────────────────────────────────────────
# Leg 1 (CONTRACT — always runs, needs no build artifacts, fail-closed):
#   * config/hotswap_module_imports.def exists and parses to >= IMPORT_FLOOR
#     rows. A gutted or unparseable allowlist is exit 2, never a pass: an
#     empty allowlist would make every module's import set "not allowed" and
#     an empty PARSE would make it "all allowed" depending on which way the
#     bug fell, and neither is something to guess at.
#   * No duplicate symbol rows.
#   * Every row's group is in the closed set declared in the .def header. A
#     row with an invented group is a row nobody classified.
#
# Leg 2 (ARTIFACTS): every `*.so` under build/hotswap is read with
#   `nm -D --undefined-only`, the `@GLIBC_x.y.z` version suffix is stripped
#   (a glibc bump is a toolchain fact, not a widening of reach), and any name
#   absent from the allowlist FAILS, naming the module and the symbol.
#
# ── ZERO MODULES IS NOT A PASS — the deliberate choice, and why ────────────
# build/hotswap is a BUILD OUTPUT directory and is not tracked. Making a
# missing directory FATAL would make `make lint` red on every fresh clone and
# on every CI job that lints without building modules — a gate that cries wolf
# gets deleted, and then the invariant is enforced nowhere again. Making it a
# silent exit 0 is the failure mode this whole file exists to prevent.
#
# So the two cases are split on a sharp line:
#
#   build/hotswap DOES NOT EXIST  -> UNOBSERVED. Exit 0, but the word OK is
#       never printed for the artifact leg and the output says in full what
#       was and was not proven. Nothing was built, so there is nothing to
#       judge. This is honest, not vacuous: leg 1 still ran and still proved
#       the contract file itself is well-formed and non-empty, so the gate
#       never reports success without having checked something real.
#   build/hotswap EXISTS BUT HOLDS NO *.so  -> FATAL, exit 2. The producer
#       ran and emptied, or the artifact naming changed under us. That is
#       exactly the hollow-scan shape (see tools/lint/gate_lib.sh) and it must
#       be loud.
#
# In sandbox (--selftest) mode there is no UNOBSERVED path at all: the
# selftest always plants at least one clean module of its own, so an empty
# sandbox is FATAL and the trip/recover proof can never be vacuous.
#
# ── SHELL DISCIPLINE ───────────────────────────────────────────────────────
# `set -uo pipefail`, no `set -e`. A status-carrying `cmd | grep -q` INVERTS
# under pipefail in this tree (grep -q exits at the first match, the producer
# takes SIGPIPE, pipefail reports 141) — for a lint gate that means a FOUND
# VIOLATION reads as CLEAN. See tools/scripts/sh_str.sh. Every decision below
# either greps a FILE directly or captures output with `$(...)` and tests the
# captured STRING. `nm` is invoked un-piped so its own exit status is real.
# LC_ALL=C on every grep/sort.
#
# Usage:
#   tools/lint/check_hotswap_module_imports.sh
#   tools/lint/check_hotswap_module_imports.sh --selftest
#
# Env (selftest only; refused otherwise):
#   ZCL_HOTSWAP_IMPORTS_SELFTEST     marker naming this gate
#   ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR  module directory to scan instead of
#                                    build/hotswap; must live under $SCRATCH
#
# Exit: 0 clean (or UNOBSERVED artifact leg), 1 on a forbidden import or a
# malformed allowlist row, 2 when the gate could not look.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

GATE="check_hotswap_module_imports"
DEF="config/hotswap_module_imports.def"
SO_DIR="build/hotswap"
SCRATCH="$HOME/.local/state/zclassic23/scratch/lane-imports"

# The closed set of rationale groups. A row outside it is a row nobody
# classified, which is the same as an unreviewed widening.
VALID_GROUPS=" TOOLCHAIN LIBC JSON LOG NODE_COMMAND NODE_STATUS NODE_DB NODE_UTIL NODE_HOTSWAP NODE_APP "

# A floor, not a count. The allowlist was derived from 93 real artifacts and
# holds 282 rows; shrinking it is always legitimate (it is a ceiling), but a
# drop below this means the file was gutted or the parser stopped matching,
# and neither may be reported as clean.
IMPORT_FLOOR=100

SANDBOX=0
if [ -n "${ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR:-}" ]; then
    # Honored ONLY for a re-invocation from run_selftest, which sets the
    # marker. Without this check a stray environment variable would redirect a
    # REAL `make lint` scan at a directory of the setter's choosing — the
    # "green gate that checked nothing" shape this file exists to prevent.
    if [ "${ZCL_HOTSWAP_IMPORTS_SELFTEST:-}" != "$GATE" ]; then
        echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR is set outside --selftest; refusing to scan anywhere but $SO_DIR" >&2
        exit 2
    fi
    case "$ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR" in
        "$SCRATCH"/*) ;;
        *)
            echo "$GATE: FATAL — sandbox dir must live under $SCRATCH, got: $ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR" >&2
            exit 2
            ;;
    esac
    SO_DIR="$ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR"
    SANDBOX=1
    echo "$GATE: SANDBOX module dir (selftest only): $SO_DIR"
fi

fail=0
bad() { printf '%s: FAIL — %s\n' "$GATE" "$1" >&2; fail=1; }
note() { printf '  %s\n' "$1"; }

# ── leg 1: the contract file itself ────────────────────────────────────────
declare -A ALLOWED=()
declare -A GROUP_OF=()
ALLOWED_N=0

load_allowlist() {
    if [ ! -f "$DEF" ]; then
        echo "$GATE: FATAL — allowlist $DEF does not exist. The import contract cannot be checked against a file that is not there; refusing to report clean." >&2
        exit 2
    fi

    # grep a FILE directly (no pipe carrying a decision), capture the STRING.
    local rows rc
    rows="$(LC_ALL=C grep -oE '^[[:space:]]*HOTSWAP_MODULE_IMPORT\("[^"]+"[[:space:]]*,[[:space:]]*"[^"]+"\)' "$DEF" 2>/dev/null)"
    rc=$?
    if [ "$rc" -ge 2 ]; then
        echo "$GATE: FATAL — grep failed (exit $rc) reading $DEF; refusing to report clean off a broken scan." >&2
        exit 2
    fi
    if [ -z "${rows//[[:space:]]/}" ]; then
        echo "$GATE: FATAL — $DEF parsed to ZERO HOTSWAP_MODULE_IMPORT rows." >&2
        echo "  Either the file was gutted or its row shape changed and this" >&2
        echo "  parser no longer matches it. An empty parse is not an empty" >&2
        echo "  contract; it is an unreadable one." >&2
        exit 2
    fi

    local line sym grp rest dupes=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        rest="${line#*\"}"          # sym", "GRP")
        sym="${rest%%\"*}"
        rest="${line#*,}"           #  , "GRP")
        rest="${rest#*\"}"
        grp="${rest%%\"*}"
        if [ -z "$sym" ] || [ -z "$grp" ]; then
            bad "unparseable allowlist row in $DEF: $line"
            continue
        fi
        case "$VALID_GROUPS" in
            *" $grp "*) ;;
            *)
                bad "allowlist row for '$sym' carries group '$grp', which is not one of the declared groups ($VALID_GROUPS). A row nobody classified is an unreviewed widening."
                continue
                ;;
        esac
        if [ -n "${ALLOWED[$sym]:-}" ]; then
            dupes="$dupes $sym"
            continue
        fi
        ALLOWED["$sym"]=1
        GROUP_OF["$sym"]="$grp"
        ALLOWED_N=$((ALLOWED_N + 1))
    done <<< "$rows"

    if [ -n "${dupes// /}" ]; then
        bad "duplicate symbol row(s) in $DEF:$dupes"
    fi

    if [ "$ALLOWED_N" -lt "$IMPORT_FLOOR" ]; then
        echo "$GATE: FATAL — allowlist holds $ALLOWED_N row(s), below the floor of $IMPORT_FLOOR." >&2
        echo "  $DEF was derived from the real undefined-symbol union of every" >&2
        echo "  built module; a drop this far means it was gutted or the parser" >&2
        echo "  stopped matching. Refusing to judge modules against it." >&2
        exit 2
    fi

    [ "$fail" -eq 0 ] || return 1
    note "contract  : OK — $ALLOWED_N allowlisted import(s) in $DEF, all classified, no duplicates"
    return 0
}

# ── leg 2: the artifacts ───────────────────────────────────────────────────
# Returns 0 clean, 1 violation, 3 UNOBSERVED (nothing built). Exits 2 itself
# on a hollow scan.
SCANNED_SO=0
declare -A SEEN_IMPORT=()

scan_modules() {
    if [ ! -d "$SO_DIR" ]; then
        if [ "$SANDBOX" -eq 1 ]; then
            echo "$GATE: FATAL — sandbox module dir $SO_DIR does not exist" >&2
            exit 2
        fi
        return 3
    fi

    local sos=()
    local f
    for f in "$SO_DIR"/*.so; do
        [ -f "$f" ] || continue
        sos+=("$f")
    done

    if [ "${#sos[@]}" -eq 0 ]; then
        # The directory EXISTS and holds no module. The producer ran and
        # emptied, or the artifact naming changed. Hollow scan: loud, never a
        # quiet pass. (A never-built tree has no directory at all and takes
        # the UNOBSERVED path above.)
        echo "$GATE: FATAL — $SO_DIR exists but contains no *.so module." >&2
        echo "  A module directory that is present and empty is a producer that" >&2
        echo "  ran and emitted nothing, or an artifact name this gate no longer" >&2
        echo "  matches. Either way the import contract would be 'proven' against" >&2
        echo "  zero artifacts. Refusing." >&2
        exit 2
    fi

    local nm_out nm_rc line sym mod bad_rows=""
    if ! command -v nm >/dev/null 2>&1; then
        echo "$GATE: FATAL — nm(1) is not on PATH; the undefined-symbol set cannot be read" >&2
        exit 2
    fi

    for f in "${sos[@]}"; do
        mod="$(basename "$f")"
        # nm is NOT in a pipeline: its exit status is a real decision here.
        nm_out="$(nm -D --undefined-only "$f" 2>&1)"
        nm_rc=$?
        if [ "$nm_rc" -ne 0 ]; then
            bad "cannot read dynamic symbols of $mod (nm exit $nm_rc): $nm_out"
            continue
        fi
        SCANNED_SO=$((SCANNED_SO + 1))
        while IFS= read -r line; do
            [ -n "${line//[[:space:]]/}" ] || continue
            sym="${line##* }"      # trailing field is the symbol name
            sym="${sym%%@*}"       # drop the @GLIBC_x.y.z version half
            [ -n "$sym" ] || continue
            SEEN_IMPORT["$sym"]=1
            if [ -z "${ALLOWED[$sym]:-}" ]; then
                bad_rows="$bad_rows
    $mod  imports  $sym"
            fi
        done <<< "$nm_out"
    done

    if [ "$SCANNED_SO" -eq 0 ]; then
        echo "$GATE: FATAL — found ${#sos[@]} module file(s) but read the symbols of none of them" >&2
        exit 2
    fi

    if [ -n "${bad_rows//[[:space:]]/}" ]; then
        bad "module(s) import symbol(s) that are NOT on the declared contract:$bad_rows"
        {
            echo ""
            echo "  A hot-swap module runs inside the live node. Its UNDEFINED symbol set"
            echo "  is its whole reach into the resident image, so an import that nobody"
            echo "  declared is reach that nobody reviewed."
            echo ""
            echo "  If the new call is legitimate: add a row to $DEF under the group that"
            echo "  explains WHY it is allowed, and say in the commit message which door"
            echo "  you opened and why the leaf behind it still cannot misreport or mutate"
            echo "  anything a reader trusts."
            echo "  If the honest answer is that it can: do not import it. Move the call"
            echo "  into the resident and reach it through an existing NODE_COMMAND door."
        } >&2
        return 1
    fi
    return 0
}

# Informational only. A declared-but-unimported row is dead widening, not a
# violation — it grants reach nothing currently takes. Worth surfacing so the
# ceiling can be trimmed; never worth failing on, because a legitimate module
# rebuild routinely drops symbols.
report_unused() {
    local unused=0 sym
    for sym in "${!ALLOWED[@]}"; do
        [ -n "${SEEN_IMPORT[$sym]:-}" ] || unused=$((unused + 1))
    done
    if [ "$unused" -gt 0 ]; then
        note "unused    : $unused allowlisted import(s) are not taken by any built module (dead ceiling; safe to trim, not a violation)"
    fi
}

run_checks() {
    fail=0
    load_allowlist
    local contract_fail="$fail"

    local art_rc=0
    scan_modules || art_rc=$?

    if [ "$contract_fail" -ne 0 ]; then
        echo "$GATE: the import contract file is malformed; module imports were not judged against it." >&2
        return 1
    fi

    if [ "$art_rc" -eq 3 ]; then
        echo "$GATE: UNOBSERVED (artifact leg) — $SO_DIR does not exist, so no module .so was examined."
        note "This is NOT a clean bill of health for any module. Nothing was built,"
        note "so nothing was judged. The contract leg above DID run and did prove"
        note "$DEF is well-formed and holds $ALLOWED_N classified rows."
        note "Build modules (make hotswap ...) and re-run to exercise the artifact leg."
        echo "$GATE: contract OK, artifacts UNOBSERVED"
        return 0
    fi

    if [ "$art_rc" -ne 0 ] || [ "$fail" -ne 0 ]; then
        return 1
    fi

    report_unused
    note "artifacts : OK — $SCANNED_SO module .so in $SO_DIR, every undefined symbol declared"
    echo "$GATE: OK — $SCANNED_SO module(s) checked against $ALLOWED_N declared imports in $DEF; no undeclared reach into the node"
    return 0
}

# ── self-test: prove the gate trips, then recovers ────────────────────────
# Nothing is written into the repository. `make lint` runs ~156 gates
# concurrently under -j24 and several of them glob the tree; a fixture that
# exists in build/hotswap for the length of two scans races them, and a
# concurrent build would try to consume it. So the selftest builds its OWN
# module directory in scratch and points the gate at the COPY.
run_selftest() {
    mkdir -p "$SCRATCH" || {
        echo "$GATE: selftest FATAL — cannot create scratch dir $SCRATCH" >&2
        exit 2
    }
    # Unique per run: a fixed path plus rm -rf means two concurrent --selftest
    # runs (two lanes, or two worktrees sharing $HOME) delete each other's
    # sandbox mid-scan.
    local sandbox
    sandbox="$(mktemp -d "$SCRATCH/sandbox.XXXXXX")" || {
        echo "$GATE: selftest FATAL — cannot create sandbox under $SCRATCH" >&2
        exit 2
    }

    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        echo "$GATE: selftest FATAL — no C compiler on PATH; cannot build the fixture modules" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    local CC; CC="$(command -v cc || command -v gcc)"

    # A CLEAN module of our own, so the sandbox is never empty regardless of
    # whether this checkout has ever built a real one. Its imports are all
    # allowlisted (LIBC + JSON), so a clean baseline is meaningful.
    cat > "$sandbox/clean_fixture.c" <<'CLEANEOF'
/* Built ONLY by check_hotswap_module_imports.sh --selftest, into a scratch
 * sandbox — never into build/hotswap and never into the repo. Its imports are
 * deliberately all on the declared contract so the sandbox baseline is clean. */
#include <stdlib.h>
#include <string.h>
extern void *json_init(void);
void *zcl_selftest_clean_leaf(const char *s);
void *zcl_selftest_clean_leaf(const char *s) {
    if (s == NULL || strlen(s) == 0u) { return NULL; }
    char *copy = (char *)malloc(strlen(s) + 1u);
    if (copy == NULL) { return NULL; }
    memcpy(copy, s, strlen(s) + 1u);
    free(copy);
    return json_init();
}
CLEANEOF
    # A module that reaches somewhere nobody declared.
    cat > "$sandbox/violating_fixture.c" <<'BADEOF'
/* Built ONLY by check_hotswap_module_imports.sh --selftest, into a scratch
 * sandbox. It imports an undeclared node entry point on purpose and is
 * deleted before this script returns. It must never survive a run. */
extern int zcl_selftest_undeclared_node_reach(int height);
int zcl_selftest_violating_leaf(void);
int zcl_selftest_violating_leaf(void) { return zcl_selftest_undeclared_node_reach(1); }
BADEOF

    local clean_so="$sandbox/zcl_selftest_clean.so"
    local bad_so="$sandbox/zcl_selftest_violating.so"
    local cc_out
    cc_out="$("$CC" -shared -fPIC -O0 -o "$clean_so" "$sandbox/clean_fixture.c" 2>&1)"
    if [ ! -f "$clean_so" ]; then
        echo "$GATE: selftest FATAL — could not build the clean fixture module: $cc_out" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    cc_out="$("$CC" -shared -fPIC -O0 -o "$bad_so" "$sandbox/violating_fixture.c" 2>&1)"
    if [ ! -f "$bad_so" ]; then
        echo "$GATE: selftest FATAL — could not build the violating fixture module: $cc_out" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    mv "$bad_so" "$sandbox/violating.so.parked"

    # Mirror the real modules in too when this checkout has them, so the
    # sandbox exercises the same shapes the real scan does.
    local mirrored=0 f
    if [ -d "build/hotswap" ]; then
        for f in build/hotswap/*.so; do
            [ -f "$f" ] || continue
            cp "$f" "$sandbox/" 2>/dev/null && mirrored=$((mirrored + 1))
        done
    fi

    local present=0
    for f in "$sandbox"/*.so; do
        [ -f "$f" ] || continue
        present=$((present + 1))
    done
    if [ "$present" -lt 1 ]; then
        # An empty sandbox would make the baseline vacuously clean and the
        # "planted fixture trips the gate" proof meaningless.
        echo "$GATE: selftest FATAL — sandbox holds no module .so; refusing to prove anything against an empty scan set" >&2
        rm -rf "$sandbox"
        exit 2
    fi

    local baseline_out="$sandbox/baseline.out"
    local tripped_out="$sandbox/tripped.out"
    local recovered_out="$sandbox/recovered.out"

    cleanup() { rm -rf "$sandbox"; }
    trap cleanup EXIT

    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$baseline_out" 2>&1
    local baseline_rc=$?
    if [ "$baseline_rc" -ne 0 ]; then
        echo "$GATE: selftest FATAL — sandbox baseline is not clean (rc=$baseline_rc); the trip/recover comparison would prove nothing" >&2
        cat "$baseline_out" >&2
        exit 2
    fi
    if LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$baseline_out"; then
        echo "$GATE: selftest FATAL — baseline already names the forbidden symbol before the fixture was planted" >&2
        cat "$baseline_out" >&2
        exit 2
    fi

    mv "$sandbox/violating.so.parked" "$bad_so"
    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$tripped_out" 2>&1
    local tripped_rc=$?

    rm -f "$bad_so"
    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$recovered_out" 2>&1
    local recovered_rc=$?

    # Two more legs that need no artifacts: the override is refused without
    # the marker, and refused for a path outside scratch.
    local stray_out stray_rc
    stray_out="$(ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" "$SELF" 2>&1)"
    stray_rc=$?
    local outside_out outside_rc
    outside_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="/etc" "$SELF" 2>&1)"
    outside_rc=$?

    local ok=1
    if [ "$tripped_rc" -eq 0 ]; then
        echo "$GATE: selftest FAIL — the module importing an undeclared symbol did not trip the gate (rc=0)" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$tripped_out"; then
        echo "$GATE: selftest FAIL — gate did not name the forbidden symbol; it may have failed for an unrelated reason" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'zcl_selftest_violating.so' "$tripped_out"; then
        echo "$GATE: selftest FAIL — gate did not name the offending module file" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if [ -e "$bad_so" ]; then
        echo "$GATE: selftest FAIL — violating fixture was not removed" >&2
        ok=0
    fi
    if LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$recovered_out"; then
        echo "$GATE: selftest FAIL — gate still names the forbidden symbol after cleanup" >&2
        cat "$recovered_out" >&2
        ok=0
    fi
    if [ "$recovered_rc" -ne "$baseline_rc" ]; then
        echo "$GATE: selftest FAIL — gate did not return to its baseline exit code (baseline=$baseline_rc recovered=$recovered_rc)" >&2
        ok=0
    fi
    if [ "$stray_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — sandbox override without the selftest marker was accepted (rc=$stray_rc); a stray env var could redirect a real lint scan" >&2
        printf '%s\n' "$stray_out" >&2
        ok=0
    fi
    if [ "$outside_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — sandbox override pointing outside $SCRATCH was accepted (rc=$outside_rc)" >&2
        printf '%s\n' "$outside_out" >&2
        ok=0
    fi

    trap - EXIT
    rm -rf "$sandbox"

    if [ "$ok" -ne 1 ]; then
        echo "$GATE: selftest FAILED" >&2
        exit 1
    fi
    echo "$GATE: selftest PASS — a sandbox module importing an undeclared node symbol tripped the gate (rc=$tripped_rc; module and symbol both named); removing it restored the baseline verdict (rc=$baseline_rc) over $present sandbox module(s) ($mirrored mirrored from build/hotswap); the sandbox override is refused without the marker and refused outside $SCRATCH"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

run_checks
exit $?
