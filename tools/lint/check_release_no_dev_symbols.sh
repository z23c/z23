#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_release_no_dev_symbols.sh — prove the RELEASE binary contains none of
# the dev-only mutation entry points. The dev command dispatcher, the
# hot-swap/reload cycle, the persistent watcher, the subprocess runner, and
# the native dev-lane activation engine live in DEV_ONLY_SRCS (Makefile) or
# are self-guarded by `#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)`
# and are compiled ONLY into the DEV/TEST binaries; the release binary must
# link none of them. See docs/NATIVE_COMMAND_INTERFACE.md §20 ("Release
# builds contain no dev mutation or loader command path").
#
# Two layers, so the gate is authoritative from source AND from the artifact:
#   1. STRUCTURAL (always): main.c has no legacy devloop dispatch, the
#      Makefile excludes the devloop executors from ALL_SRCS, and every
#      dev-activation engine source file carries its dev/test compile guard.
#      These facts guarantee absence in any fresh release build while the
#      registry can still expose honest COMPAT metadata for dev-only commands.
#   2. ARTIFACT (when a fresh release binary exists): the exported extern
#      symbol set must not contain any forbidden dev-executor symbol. The
#      release binary is stripped, but -rdynamic keeps extern symbols in
#      .dynsym, so the read is definitive. The read is per-host: ELF (Linux)
#      exports via -rdynamic into .dynsym, read with `nm -D --defined-only`;
#      a Mach-O executable has NO dynamic symbol table at all — Apple's nm
#      refuses it with "File format has no dynamic symbol table" (exit 1) —
#      and the exported externs are its defined global symbols, read with
#      `nm -gU`.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

BIN="${1:-build/bin/zclassic23}"

# The extern dev-mutation entry points that must never reach the release binary.
FORBIDDEN=(
    zcl_devloop_cli_main
    zcl_devloop_is_method
    zcl_devloop_run_cycle
    zcl_devloop_run_sim
    zcl_devloop_watch
    zcl_devloop_process_run
    zcl_devloop_print_status
    dev_activation_run
    dev_activation_activate_generation
    dev_activation_default_ops
)

echo "══ LINT: release binary contains no dev-only mutation symbols ══"

rc=0

# ── layer 1: structural (source-level, always runs) ──────────────────────
# main.c must not bypass the registry through the retired devloop dispatcher.
if gate_grep -qE 'zcl_devloop_(cli_main|is_method)' engine/entry/main.c >/dev/null; then
    echo "FAIL: engine/entry/main.c still bypasses the native registry for dev commands" >&2
    rc=1
fi

# Makefile must place the executors in DEV_ONLY_SRCS and exclude them from
# ALL_SRCS (via the filter-out into DEVLOOP_SRCS).
mk_dev_only="$(gate_grep -A2 '^DEV_ONLY_SRCS' Makefile || true)"
mk_filter="$(gate_grep -E '^DEVLOOP_SRCS[[:space:]]*=.*filter-out.*DEV_ONLY_SRCS' Makefile || true)"
scanned=0
for f in devloop_cli.c devloop_cycle.c devloop_watch.c devloop_process.c; do
    scanned=$((scanned + 1))
    if ! printf '%s' "$mk_dev_only" | gate_grep -q "tools/dev/$f" >/dev/null; then
        echo "FAIL: tools/dev/$f is not in the Makefile DEV_ONLY_SRCS group" >&2
        rc=1
    fi
done
gate_require_scanned "$scanned" 4 "check-release-no-dev-symbols" \
    "the DEV_ONLY_SRCS executor list changed shape unexpectedly"
if [ -z "$mk_filter" ]; then
    echo "FAIL: DEVLOOP_SRCS must filter-out DEV_ONLY_SRCS so the release ALL_SRCS excludes them" >&2
    rc=1
fi

# The native dev-lane activation engine (tools/dev/dev_activation*.c) stays in
# ALL_SRCS (unlike the DEV_ONLY_SRCS executors above) but self-guards: the
# whole TU body sits inside `#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)`,
# and the real process-exec ops (dev_activation_ops.c) sit inside a further
# `#ifdef ZCL_DEV_BUILD`, so a release compile (neither macro defined) yields
# an object with none of these symbols. Prove every engine source file still
# carries its guard.
DEV_ACTIVATION_OR_GUARD_SRCS="tools/dev/dev_activation.c tools/dev/dev_activation_internal.h tools/dev/dev_activation_stage.c tools/dev/dev_activation_verify.c"
DEV_ACTIVATION_STRICT_GUARD_SRCS="tools/dev/dev_activation_ops.c"
scanned_activation=0
for f in $DEV_ACTIVATION_OR_GUARD_SRCS; do
    scanned_activation=$((scanned_activation + 1))
    if [ ! -r "$f" ]; then
        echo "FAIL: $f is missing (dev-activation engine file set changed shape)" >&2
        rc=1
        continue
    fi
    if ! gate_grep -qE '#if[[:space:]]+defined\(ZCL_DEV_BUILD\)[[:space:]]*\|\|[[:space:]]*defined\(ZCL_TESTING\)' "$f" >/dev/null; then
        echo "FAIL: $f is missing the '#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)' compile guard" >&2
        rc=1
    fi
done
for f in $DEV_ACTIVATION_STRICT_GUARD_SRCS; do
    scanned_activation=$((scanned_activation + 1))
    if [ ! -r "$f" ]; then
        echo "FAIL: $f is missing (dev-activation engine file set changed shape)" >&2
        rc=1
        continue
    fi
    if ! gate_grep -qE '#ifdef[[:space:]]+ZCL_DEV_BUILD' "$f" >/dev/null; then
        echo "FAIL: $f is missing the '#ifdef ZCL_DEV_BUILD' compile guard" >&2
        rc=1
    fi
done
gate_require_scanned "$scanned_activation" 5 "check-release-no-dev-symbols" \
    "the dev_activation engine source-file set changed shape unexpectedly"

# ── layer 2: artifact (nm on a FRESH release binary, when present) ────────
if [ -x "$BIN" ] && [ "$BIN" -nt engine/entry/main.c ] && [ "$BIN" -nt Makefile ]; then
    # The symbol read is per-host (see the header). Linux keeps the exact
    # ELF contract it always had; only Darwin switches read.
    if [ "$(uname -s)" = "Darwin" ]; then
        nm_read=(nm -gU)
    else
        nm_read=(nm -D --defined-only)
    fi
    # The read's exit status is captured EXPLICITLY, never left inside a bare
    # `$( )` assignment. This script starts `set -uo pipefail` with NO `-e`,
    # but every gate_grep call above re-arms errexit (gate_lib.sh's gate_grep
    # ends in a bare `set -e` and shell options are not function-scoped), so
    # the whole script has been running under errexit from the first grep on.
    # With `nm -D` failing on a Mach-O binary (exit 1, stderr discarded by the
    # 2>/dev/null inside the substitution) that assignment killed the gate
    # dead: rc=1, zero output — the silent red. Same discipline as
    # check_hotswap_module_imports.sh: a tool failure is a decision, made out
    # loud, never a pipeline accident.
    syms="$("${nm_read[@]}" "$BIN" 2>/dev/null | awk '{print $NF}')" && nm_rc=0 || nm_rc=$?
    if [ "$nm_rc" -ne 0 ]; then
        nm_err="$("${nm_read[@]}" "$BIN" 2>&1 >/dev/null)" || true
        echo "FAIL: cannot read the exported symbols of $BIN with '${nm_read[*]}' (exit $nm_rc)" >&2
        [ -n "$nm_err" ] && echo "      nm says: $(printf '%s' "$nm_err" | head -1)" >&2
        echo "      the artifact-level proof did NOT run; the structural proof above" >&2
        echo "      is the only evidence this gate can offer for this artifact." >&2
        rc=1
    elif [ -z "$syms" ]; then
        echo "NOTE: ${nm_read[*]} exported no symbols from $BIN (unexpected for -rdynamic);" >&2
        echo "      relying on the structural proof above." >&2
    else
        # The verdict is a string test on the EXTRACTED match, never the exit
        # status of a `printf | gate_grep -qx` pipeline. `$syms` is the whole
        # .dynsym name list — measured 555 KB / 21,859 lines on this tree —
        # so under `set -o pipefail` a `-qx` that MATCHED exited at the first
        # hit, printf took SIGPIPE, and the pipeline reported 141 instead of 0.
        # `if 141` is false, so a release binary that really did export a
        # dev-only mutation symbol was read as clean: measured 20/20 hollow
        # PASSes with a forbidden symbol planted on line 6 of the real nm
        # output. Dropping `-q` makes grep consume all of stdin, so printf
        # always completes; the regex itself is unchanged.
        # Mach-O spells every extern C symbol with one leading underscore
        # (_zcl_devloop_cli_main); FORBIDDEN is written in plain C names. The
        # audit's intent is "this name is absent", not "this spelling is
        # absent", so probe the stripped form on this host — otherwise the
        # negative match can never fire on Darwin (same rule as
        # check_hotswap_module_imports.sh). Linux names carry no underscore,
        # so this is a no-op there and the read above already is ELF-native.
        if [ "$(uname -s)" = "Darwin" ]; then
            # one underscore: Mach-O prefixes exactly one; BSD sed has no \+
            syms="$(printf '%s\n' "$syms" | sed 's/^_//')"
        fi
        for sym in "${FORBIDDEN[@]}"; do
            sym_hit="$(printf '%s\n' "$syms" | gate_grep -x "$sym" || true)"
            if [ -n "$sym_hit" ]; then
                echo "FAIL: release binary $BIN exports dev-only symbol '$sym'" >&2
                rc=1
            fi
        done
        # An `if`, not `[ ... ] && echo`: gate_grep leaves errexit armed, and
        # a bare `[ 1 -eq 0 ] && echo` failing as a standalone statement would
        # kill the gate right after a FAIL was printed, dropping the final
        # summary line.
        if [ "$rc" -eq 0 ]; then
            echo "  ${nm_read[*]} $BIN: all ${#FORBIDDEN[@]} dev-executor symbols ABSENT ✓"
        fi
    fi
else
    echo "NOTE: no fresh release binary at $BIN — structural proof above is authoritative."
    echo "      (build it with 'make zclassic23' for the artifact-level nm proof.)"
fi

if [ "$rc" -ne 0 ]; then
    echo "check-release-no-dev-symbols: FAIL" >&2
    exit 1
fi
echo "check-release-no-dev-symbols: OK"
exit 0
