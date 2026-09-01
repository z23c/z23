#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_eligible_scope.sh — every TU in the Tier-1 hot-swap
# eligibility manifest (engine/composition/hotswap_eligible.def) must be an app-layer
# surface. Consensus / validation / storage / net / coins / reducer-stage
# code is NEVER hot-swappable, not even in a dev build: a dlopen'd generation
# of any of those could silently diverge the node's consensus state or the
# reducer fold. This gate refuses any manifest path under a forbidden root.
#
# Manifest path is overridable via ZCL_HOTSWAP_MANIFEST so the lint-gate
# self-test can point it at a seeded-violation manifest.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

MANIFEST="${ZCL_HOTSWAP_MANIFEST:-engine/composition/hotswap_eligible.def}"
PROBE_CASES="${ZCL_HOTSWAP_PROBE_CASES:-engine/composition/hotswap_probe_cases.def}"

echo "══ LINT: hot-swap eligibility manifest scope (app-layer only) ══"

if [ ! -r "$MANIFEST" ]; then
    echo "check_hotswap_eligible_scope: FATAL — manifest '$MANIFEST' missing/unreadable." >&2
    echo "  Refusing to report 'clean' with no manifest to scan." >&2
    exit 2
fi
if [ ! -r "$PROBE_CASES" ]; then
    echo "check_hotswap_eligible_scope: FATAL — probe cases '$PROBE_CASES' missing/unreadable." >&2
    exit 2
fi

# Extract the quoted path from each HOTSWAP_ELIGIBLE("...") invocation.
mapfile -t PATHS < <(gate_grep -oE 'HOTSWAP_ELIGIBLE\("[^"]+"\)' "$MANIFEST" \
    | sed -E 's/HOTSWAP_ELIGIBLE\("([^"]+)"\)/\1/')
mapfile -t PAIRS < <(sed -n \
    's/^[[:space:]]*HOTSWAP_ELIGIBLE("\([^"]*\)")[[:space:]]*HOTSWAP_PROBE("\([^"]*\)").*/\1\t\2/p' \
    "$MANIFEST")

# Fail-loud: a manifest that parses to zero entries means the format drifted
# (renamed macro, mangled quoting). Do not pass 'clean' off an empty parse.
gate_require_scanned "${#PATHS[@]}" 1 check_hotswap_eligible_scope \
    "no HOTSWAP_ELIGIBLE(\"...\") entries parsed from $MANIFEST"
if [ "${#PAIRS[@]}" -ne "${#PATHS[@]}" ]; then
    echo "FAIL: every HOTSWAP_ELIGIBLE row must carry exactly one HOTSWAP_PROBE on the same line" >&2
    exit 1
fi

FORBIDDEN='^(core|lib/consensus|lib/validation|lib/storage|lib/net|lib/coins|app/jobs)/'

violations=""
declare -A seen_paths=() seen_probes=()
for pair in "${PAIRS[@]}"; do
    p="${pair%%$'\t'*}"
    probe="${pair#*$'\t'}"
    probe_key="$probe"
    case "$probe" in
        # '.' is allowed: native.leaves probes are dotted canonical command
        # paths (e.g. "core.status"), not removed route identifiers
        # (e.g. "z23 status").
        ""|*[!A-Za-z0-9_.]*)
            violations="${violations}  $p (invalid canonical probe '$probe')"$'\n'
            ;;
    esac
    case_count="$(grep -Fc "\"$probe\"," "$PROBE_CASES" || true)"
    if [ "$case_count" -ne 1 ]; then
        violations="${violations}  $p (probe '$probe' resolves to $case_count resident cases, expected exactly one)"$'\n'
    fi
    [ -n "$probe_key" ] || probe_key="__empty__:$p"
    if [ -n "${seen_paths[$p]:-}" ]; then
        violations="${violations}  $p (duplicate eligibility row)"$'\n'
    fi
    if [ -n "${seen_probes[$probe_key]:-}" ]; then
        violations="${violations}  $p (probe '$probe' is already assigned to ${seen_probes[$probe_key]})"$'\n'
    fi
    seen_paths[$p]=1
    seen_probes[$probe_key]="$p"
done
for p in "${PATHS[@]}"; do
    if printf '%s\n' "$p" | grep -qE "$FORBIDDEN"; then
        violations="${violations}  $p (under a forbidden consensus/state root)"$'\n'
        continue
    fi
    case "$p" in
        *.c) ;;
        *) violations="${violations}  $p (not a .c translation unit)"$'\n'; continue ;;
    esac
    if [ ! -f "$p" ]; then
        violations="${violations}  $p (manifest references a nonexistent file)"$'\n'
        continue
    fi
    # Genuinely-exportable: an eligible TU MUST invoke
    # ZCL_HOTSWAP_EXPORT_LEAVES, or `make hotswap-so` would build a .so with no
    # zcl_hotswap_gen_init / zcl_hotswap_manifest_v2 and the loader would
    # reject it at the manifest stage — a silently-unswapabble entry. Guards
    # the multi-TU expansion.
    # Either spelling counts: the explicit emitter, or ZCL_HOTSWAP_LEAVES_END
    # from hotswap_register.h, which expands to it. The property being checked
    # is that the TU exports leaves, not which macro it typed to do so.
    if ! grep -qE '(^|[^_])(ZCL_HOTSWAP_EXPORT_LEAVES|ZCL_HOTSWAP_LEAVES_END)[[:space:]]*\(' "$p"; then
        violations="${violations}  $p (eligible TU exports no leaves: neither ZCL_HOTSWAP_EXPORT_LEAVES nor ZCL_HOTSWAP_LEAVES_END)"$'\n'
    fi
done

if [ -n "${violations//[[:space:]]/}" ]; then
    printf '%s' "$violations"
    echo "FAIL: hot-swap eligibility manifest lists an out-of-scope TU."
    echo "  Eligible TUs must be app-layer .c files that invoke"
    echo "  ZCL_HOTSWAP_EXPORT_LEAVES, NEVER under core, lib/consensus,"
    echo "  core/modules/validation, engine/modules/storage, core/modules/net, core/modules/coins, or app/jobs."
    exit 1
fi

echo "  OK: ${#PATHS[@]} eligible TU(s), all app-layer surfaces"
exit 0
