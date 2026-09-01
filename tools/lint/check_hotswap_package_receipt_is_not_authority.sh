#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_package_receipt_is_not_authority.sh — the package manifest is
# a LABEL, never a KEY.
#
# We are adding a "package manifest": a sidecar record beside a built
# hot-swap module .so that records its SHA3-256 digest, the consensus seal
# root it was compiled against, and its source TU/leaf set. Think of the .so
# as a disk and the manifest as the label glued to it: the label records what
# was tested, it does not decide what gets mounted.
#
# The single most dangerous thing that could happen to this design is the
# loader growing a "helpful" fast path that trusts the label instead of
# re-deriving the truth itself. The moment engine/modules/hotswap/ reads a manifest FILE
# off disk, forging that file becomes equivalent to mounting arbitrary code —
# the label would be authorizing the disk. Every real admission decision in
# this tree (hotswap_manifest_v2_validate in hotswap_loader.c, the seal-root
# pin in hotswap_activate.c) works from a COMPILED-IN symbol resolved by
# dlsym() against the .so itself, never from a sidecar file path. That
# distinction — dlsym'd data symbol vs. filesystem read — is exactly what
# this gate polices, because it is invisible to a human diff that only checks
# "does this still call hotswap_manifest_v2_validate somewhere".
#
# DISCRIMINATION RULE (how legitimate "manifest" mentions are told apart from
# a forbidden one): engine/modules/hotswap/src/hotswap_loader.c legitimately says
# "manifest" ~40 times — `zcl_hotswap_manifest_v2`, `MANIFEST_REJECT`,
# `manifest_copy`, `k_service_manifest` — all identifiers naming the OLD
# Tier-1 GENERATION manifest, a struct exported as a data symbol and read via
# dlsym(), never a file. None of those occurrences is a quoted string literal
# containing ".manifest", and none of them is the argument to a real
# filesystem call (fopen/open/openat/stat/lstat/access/opendir/readlink).
# This gate therefore does NOT ban the bare word "manifest" — it bans the
# three concrete shapes a file-backed manifest read would actually take:
#
#   1. A quoted string literal containing ".manifest" anywhere under
#      engine/modules/hotswap/src/ or engine/modules/hotswap/include/hotswap/ (a real path suffix
#      always shows up as a quoted literal; `prep.manifest->self_test`, a
#      bare struct-member access with no surrounding quotes, does not match).
#   2. A quoted string literal containing the new package-manifest schema
#      name "zcl.hotswap_package" anywhere in the same trees.
#   3. Any fopen/open/openat/stat/lstat/access/opendir/readlink call whose
#      own source line also mentions "manifest" (case-insensitive) — this
#      catches a path assembled into a variable (e.g. `manifest_path`) and
#      then opened, even without a literal ".manifest" suffix on that line.
#      dlsym() is deliberately NOT in this list: resolving the compiled-in
#      `zcl_hotswap_manifest_v2` data symbol is the legitimate mechanism this
#      gate exists to protect, not the thing it forbids.
#
# A fourth, separate leg proves the packaging tool that MINTS a package
# manifest (tools/dev/hotswap-package.sh, built by a different lane) is a
# DEV-ONLY tool: it lives under tools/dev/, no second copy of it exists
# anywhere the node compiles from, and no node source (lib/, app/, core/,
# src/) shells out to it. A build tool that writes labels is harmless; a node
# that can be made to exec one at runtime is not.
#
# NO SKIP PATH. If tools/dev/hotswap-package.sh does not exist yet (another
# lane owns it and may not have landed), that leg is FATAL — loud, exit 2 —
# never a silent pass. A gate that reports "clean" because its input hasn't
# shown up yet is a gate nobody can trust once it does.
#
# `set -uo pipefail`, no `set -e`: a status-carrying `cmd | grep -q` inverts
# under pipefail in this tree (see tools/scripts/sh_str.sh), so every
# decision below either greps a FILE directly (no pipe) or captures a
# pipeline's stdout via `$(...)` and tests the captured STRING, never the
# pipeline's raw exit code.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

GATE="check_hotswap_package_receipt_is_not_authority"

SRC_DIR="engine/modules/hotswap/src"
INC_DIR="engine/modules/hotswap/include/hotswap"
PACKAGE_TOOL="tools/dev/hotswap-package.sh"
SCRATCH="$HOME/.local/state/zclassic23/scratch/lane-c"

# SANDBOX MODE (--selftest only). The selftest must prove this gate trips on a
# manifest-file read, which means a violating TU has to exist somewhere the
# scan can see it. Planting that TU in the LIVE engine/modules/hotswap/src/ is not an
# option: `make -j24 lint` runs ~156 gates concurrently and many of them glob
# lib/**/src/*.c, so a fixture that exists for the length of two grep passes
# is a race — one gate enumerates the tree, the fixture is deleted, and that
# gate dies on "No such file or directory" in a file nobody wrote (observed:
# check-log-macro-return-type, and the Makefile's exact-source capture, both
# failed this way). A concurrent BUILD is worse: LIB_SRCS is a wildcard over
# lib/$(m)/src/*.c, so the fixture would be handed to the compiler.
#
# So the selftest scans a COPY. It mirrors the two real directories into its
# scratch dir, plants the fixture in the mirror, and re-invokes this script
# pointed at the mirror. The override is accepted ONLY for a path under
# $SCRATCH — it cannot be aimed at an empty directory inside the repo to
# manufacture a vacuous pass — and the run announces itself as a sandbox so a
# sandbox line appearing in a real lint log is unmistakable.
if [ -n "${ZCL_RECEIPT_GATE_SANDBOX_ROOT:-}" ]; then
    # The override is honored ONLY for a re-invocation from run_selftest, which
    # sets this marker. Without it a stray environment variable would silently
    # redirect a REAL `make lint` scan at a directory of someone's choosing —
    # the "green gate that checked nothing" shape this file exists to prevent.
    if [ "${ZCL_RECEIPT_GATE_SELFTEST:-}" != "$GATE" ]; then
        echo "$GATE: FATAL — ZCL_RECEIPT_GATE_SANDBOX_ROOT is set outside --selftest; refusing to scan anywhere but the real tree" >&2
        exit 2
    fi
    case "$ZCL_RECEIPT_GATE_SANDBOX_ROOT" in
        "$SCRATCH"/*) ;;
        *)
            echo "$GATE: FATAL — sandbox root must live under $SCRATCH, got: $ZCL_RECEIPT_GATE_SANDBOX_ROOT" >&2
            exit 2
            ;;
    esac
    SRC_DIR="$ZCL_RECEIPT_GATE_SANDBOX_ROOT/src"
    INC_DIR="$ZCL_RECEIPT_GATE_SANDBOX_ROOT/include/hotswap"
    echo "$GATE: SANDBOX scan roots (selftest only): $SRC_DIR $INC_DIR"
fi

fail=0
SCANNED_SRC=0
SCANNED_INC=0
bad() { printf '%s: FAIL — %s\n' "$GATE" "$1" >&2; fail=1; }
note() { printf '  %s\n' "$1"; }

# ── leg 1+2: the runtime never reads a manifest FILE ────────────────────────
check_no_manifest_file_reads() {
    local before="$fail"

    for d in "$SRC_DIR" "$INC_DIR"; do
        if [ ! -d "$d" ]; then
            bad "$d does not exist — cannot scan (a renamed/moved hotswap tree?)"
        fi
    done
    [ "$fail" -eq 0 ] || return 1

    # A scan of an EMPTY tree finds no violations and would report "clean".
    # That is the failure mode this whole file is about, so the counts are a
    # precondition, not a diagnostic: refuse to prove anything against a tree
    # with no sources in it. Applies in every mode — a sandbox mirror gets the
    # same floor the real tree does.
    SCANNED_SRC="$(find "$SRC_DIR" -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \) | wc -l)"
    SCANNED_INC="$(find "$INC_DIR" -maxdepth 1 -type f -name '*.h' | wc -l)"
    if [ "$SCANNED_SRC" -eq 0 ] || [ "$SCANNED_INC" -eq 0 ]; then
        bad "nothing to scan (src=$SCANNED_SRC inc=$SCANNED_INC under $SRC_DIR, $INC_DIR) — refusing to report a clean tree that contains no sources"
        return 1
    fi

    local suffix_hits
    suffix_hits="$(grep -rIn --include='*.c' --include='*.h' \
        -E '"[^"]*\.manifest[^"]*"' "$SRC_DIR" "$INC_DIR" 2>/dev/null || true)"
    if [ -n "$suffix_hits" ]; then
        bad "a \".manifest\" path suffix appears in a string literal:"
        printf '%s\n' "$suffix_hits" >&2
    fi

    local schema_hits
    schema_hits="$(grep -rIn --include='*.c' --include='*.h' \
        -E '"[^"]*zcl\.hotswap_package[^"]*"' "$SRC_DIR" "$INC_DIR" 2>/dev/null || true)"
    if [ -n "$schema_hits" ]; then
        bad "the package-manifest schema string \"zcl.hotswap_package\" appears in source:"
        printf '%s\n' "$schema_hits" >&2
    fi

    local open_hits
    open_hits="$(grep -rIn --include='*.c' --include='*.h' \
        -E '\b(fopen64?|openat?|stat64?|lstat64?|access|opendir|readlink)[[:space:]]*\(' \
        "$SRC_DIR" "$INC_DIR" 2>/dev/null | grep -i 'manifest' || true)"
    if [ -n "$open_hits" ]; then
        bad "a filesystem open/stat/read call mentions \"manifest\" on its own line (a manifest FILE read):"
        printf '%s\n' "$open_hits" >&2
    fi

    if [ "$fail" -eq "$before" ]; then
        note "no-file-read : OK — no \".manifest\" suffix, no \"zcl.hotswap_package\" schema string, no open/stat/read call mentions a manifest, under $SRC_DIR or $INC_DIR"
        return 0
    fi
    return 1
}

# ── leg 3: the packaging tool is a DEV tool, never reachable from the node ──
# Returns 0 (proven safe), 1 (proven UNSAFE), or 2 (cannot be proven: the
# packaging tool has not landed yet — FATAL, not a skip).
check_package_tool_is_dev_only() {
    if [ ! -e "$PACKAGE_TOOL" ]; then
        {
            echo "$GATE: FATAL — $PACKAGE_TOOL does not exist yet."
            echo "  This leg proves the tool that MINTS a package manifest lives under a"
            echo "  dev-only path and is never reachable from the node's own runtime load"
            echo "  path. That cannot be proven with the tool itself absent, and reporting"
            echo "  a pass anyway would go quietly vacuous the instant it lands somewhere"
            echo "  unsafe. Refusing: FATAL, not a skip, until another lane adds it here."
        } >&2
        return 2
    fi

    case "$PACKAGE_TOOL" in
        tools/dev/*) note "tool location  : OK — $PACKAGE_TOOL is a dev-only tool" ;;
        *)
            bad "$PACKAGE_TOOL is not under tools/dev/"
            return 1
            ;;
    esac

    local base stray
    base="$(basename "$PACKAGE_TOOL")"
    stray="$(find core engine contexts cognition platform -type f -name "$base" 2>/dev/null || true)"
    if [ -n "$stray" ]; then
        bad "a second copy of the packaging tool exists outside tools/: $stray"
        return 1
    fi

    local exec_candidates exec_hits
    exec_candidates="$(grep -rIln --include='*.c' --include='*.h' \
        -E '\b(popen|system|execl[pe]?|execvp?)[[:space:]]*\(' \
        lib app core src 2>/dev/null || true)"
    exec_hits=""
    if [ -n "$exec_candidates" ]; then
        exec_hits="$(printf '%s\n' "$exec_candidates" | xargs -r grep -lF "$base" 2>/dev/null || true)"
    fi
    if [ -n "$exec_hits" ]; then
        bad "node source spawns the packaging tool at runtime: $exec_hits"
        return 1
    fi
    note "tool reach     : OK — no node source (lib/, app/, core/, src/) execs, popens, or systems the packaging tool"
    return 0
}

run_checks() {
    fail=0
    check_no_manifest_file_reads
    local core_fail="$fail"

    local pkg_rc=0
    check_package_tool_is_dev_only || pkg_rc=$?

    if [ "$pkg_rc" -eq 2 ]; then
        return 2
    fi
    if [ "$pkg_rc" -ne 0 ] || [ "$core_fail" -ne 0 ]; then
        echo "$GATE: the package manifest can still become an authority." >&2
        echo "  It must stay a record of what was tested, never an input to the" >&2
        echo "  load decision — that inversion turns forging a label into mounting" >&2
        echo "  arbitrary code." >&2
        return 1
    fi
    echo "$GATE: OK — no-file-read proven over $SCANNED_SRC file(s) in $SRC_DIR and $SCANNED_INC file(s) in $INC_DIR; packaging tool confined to tools/dev/ and unreached by node source"
    return 0
}

# ── self-test: prove the gate actually trips, then recovers ────────────────
run_selftest() {
    mkdir -p "$SCRATCH" || {
        echo "$GATE: selftest FATAL — cannot create scratch dir $SCRATCH" >&2
        exit 2
    }

    # Mirror the two scanned directories into scratch and plant the violating
    # TU in the MIRROR. Nothing is ever written into the repository: see the
    # SANDBOX MODE note above for the concurrency races that caused.
    # Unique per run: a fixed path plus rm -rf means two concurrent
    # --selftest runs (two lanes, or two worktrees sharing $HOME) delete
    # each other's mirror mid-scan.
    local sandbox
    sandbox="$(mktemp -d "$SCRATCH/sandbox.XXXXXX")" || {
        echo "$GATE: selftest FATAL — cannot create sandbox under $SCRATCH" >&2
        exit 2
    }
    mkdir -p "$sandbox/src" "$sandbox/include/hotswap" || {
        echo "$GATE: selftest FATAL — cannot create sandbox under $SCRATCH" >&2
        exit 2
    }
    local copied_src copied_inc
    cp "$SRC_DIR"/*.c "$SRC_DIR"/*.h "$sandbox/src/" 2>/dev/null
    cp "$INC_DIR"/*.h "$sandbox/include/hotswap/" 2>/dev/null
    copied_src="$(find "$sandbox/src" -type f -name '*.[ch]' | wc -l)"
    copied_inc="$(find "$sandbox/include/hotswap" -type f -name '*.h' | wc -l)"
    if [ "$copied_src" -eq 0 ] || [ "$copied_inc" -eq 0 ]; then
        # An empty mirror would make every leg vacuously clean and the
        # "planted fixture trips the gate" proof meaningless.
        echo "$GATE: selftest FATAL — mirror is empty (src=$copied_src inc=$copied_inc); refusing to prove anything against an empty tree" >&2
        exit 2
    fi

    local fixture="$sandbox/src/__selftest_manifest_receipt_violation.c"
    local baseline_out="$SCRATCH/selftest_baseline.out"
    local tripped_out="$SCRATCH/selftest_tripped.out"
    local recovered_out="$SCRATCH/selftest_recovered.out"

    if [ -e "$fixture" ]; then
        echo "$GATE: selftest FATAL — fixture path already exists, refusing to clobber: $fixture" >&2
        exit 2
    fi

    cleanup() { rm -f "$fixture"; }
    trap cleanup EXIT

    ZCL_RECEIPT_GATE_SELFTEST="$GATE" ZCL_RECEIPT_GATE_SANDBOX_ROOT="$sandbox" "$SELF" >"$baseline_out" 2>&1
    local baseline_rc=$?

    if grep -q "$fixture" "$baseline_out"; then
        echo "$GATE: selftest FATAL — baseline output already mentions the fixture path before it was planted" >&2
        cat "$baseline_out" >&2
        exit 2
    fi
    if [ "$baseline_rc" -ne 0 ]; then
        # The mirror is a faithful copy of a tree that must be clean; if the
        # baseline is already red the trip/recover comparison proves nothing.
        echo "$GATE: selftest FATAL — sandbox baseline is not clean (rc=$baseline_rc); the mirror does not reflect a passing tree" >&2
        cat "$baseline_out" >&2
        exit 2
    fi

    cat > "$fixture" <<'FIXEOF'
/* Planted ONLY by check_hotswap_package_receipt_is_not_authority.sh
 * --selftest, into a scratch MIRROR of engine/modules/hotswap — never into the repo.
 * It exercises the manifest-file-read prohibition on purpose and is deleted
 * before this script returns. It must never survive a run. */
#include <stdio.h>

static FILE *__selftest_open_package_manifest(const char *so_path) {
    (void)so_path;
    return fopen("build/hotswap/example.manifest", "r");
}
FIXEOF

    ZCL_RECEIPT_GATE_SELFTEST="$GATE" ZCL_RECEIPT_GATE_SANDBOX_ROOT="$sandbox" "$SELF" >"$tripped_out" 2>&1
    local tripped_rc=$?

    rm -f "$fixture"

    ZCL_RECEIPT_GATE_SELFTEST="$GATE" ZCL_RECEIPT_GATE_SANDBOX_ROOT="$sandbox" "$SELF" >"$recovered_out" 2>&1
    local recovered_rc=$?

    trap - EXIT
    rm -rf "$sandbox"

    local ok=1
    if [ "$tripped_rc" -eq 0 ]; then
        echo "$GATE: selftest FAIL — planted manifest-file-read fixture did not trip the gate (rc=0)" >&2
        ok=0
    fi
    if ! grep -q "$fixture" "$tripped_out"; then
        echo "$GATE: selftest FAIL — gate did not name the planted fixture; it may have failed for an unrelated reason" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if ! grep -qE '"\.manifest"|\\.manifest' "$tripped_out" 2>/dev/null; then
        # Secondary corroboration only; the fixture-path check above is load-bearing.
        :
    fi
    if [ -e "$fixture" ]; then
        echo "$GATE: selftest FAIL — fixture file was not removed" >&2
        ok=0
    fi
    if grep -q "$fixture" "$recovered_out"; then
        echo "$GATE: selftest FAIL — gate still mentions the fixture after cleanup" >&2
        cat "$recovered_out" >&2
        ok=0
    fi
    if [ "$recovered_rc" -ne "$baseline_rc" ]; then
        echo "$GATE: selftest FAIL — gate did not return to its baseline exit code after cleanup (baseline=$baseline_rc recovered=$recovered_rc)" >&2
        ok=0
    fi

    if [ "$ok" -ne 1 ]; then
        echo "$GATE: selftest FAILED" >&2
        exit 1
    fi
    echo "$GATE: selftest PASS — a planted manifest-file-read fixture tripped the gate (rc=$tripped_rc, fixture named in the failure); removing it restored the baseline verdict (rc=$baseline_rc)"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

run_checks
exit $?
