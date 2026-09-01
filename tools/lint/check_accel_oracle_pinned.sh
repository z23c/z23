#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_accel_oracle_pinned.sh — every ISA-dispatched implementation file the
# sealed consensus core reaches must be pinned by a differential oracle in the
# test suite (Makefile gate `check-accel-oracle-pinned`).
#
# THE GAP THIS CLOSES
# `make core-seal` freezes core/{consensus,chainparams,params,math} against
# core/MANIFEST.sha3 and check-core-seal fails the build on any drift. That
# seal covers the TEXT of the consensus predicates and nothing below them.
# Confirmed call edges out of the sealed text:
#     core/math/src/hash.c            -> core/modules/crypto/src/sha256.c
#     core/consensus/src/script_interp.c -> core/modules/crypto/src/sha256.c
#     core/consensus/src/equihash.c   -> core/modules/crypto/src/blake2b_avx2.c
#     core/ -> coins/coins.h -> sapling/incremental_merkle_tree.h
#                                     -> core/modules/sapling/src/fr_avx512.c
#                                     -> core/modules/sapling/src/bn254_accel.c
# Editing any of those changes what a sealed predicate DOES — which block is
# valid — without moving a byte inside core/. Proven: appending a comment to
# core/modules/crypto/src/sha256.c leaves `make lint` fully green.
#
# WHAT THIS GATE PROTECTS
# Not the bytes — the PROPERTY. These files exist to get faster and must stay
# editable; what must never lapse is that each one is pinned, by a test that
# actually runs, to a portable reference producing identical output. Expanding
# the core/ seal to swallow core/modules/crypto would freeze the optimisation surface
# and force the owner unseal ritual for every speedup; that is the wrong trade
# and is deliberately not what this does.
#
# FOUR LEGS
#   1. DISCOVERY. Recompute, from the source, the include-closure of sealed
#      core/ over lib/*/src/*.c, then keep the members that carry an ISA
#      dispatch (immintrin.h / cpuid.h / x86intrin.h / __builtin_cpu_supports /
#      __attribute__((target(...)))), scanning each file plus its private
#      same-directory headers. Every survivor must appear in the registry.
#      A new accelerator, or a new #include edge from core/ that reaches an
#      existing one, fails HERE — the registry cannot silently fall behind.
#   2. NO STALE ROWS. Every registry row must name a file that still exists,
#      is still ISA-dispatched, and is still in the closure. Deleting an
#      accelerator therefore has to be a deliberate registry edit.
#   3. ORACLE PRESENT AND RUNNING. The named oracle file must exist, must
#      carry `ACCEL-ORACLE: <impl path>`, and its group must be registered in
#      the canonical test group catalog. A compiled-but-
#      never-dispatched oracle proves nothing (see check_test_registration.sh).
#   4. ORACLE STILL WIRED TO THE CODE. The oracle must reference at least one
#      function the implementation exports, so renaming the accelerated entry
#      point cannot leave a green oracle testing a symbol that no longer runs.
#
# Anti-hollow: the closure, the ISA set, and the registry all carry known
# floors; a scan that collapses is a LOUD exit 2, never a quiet pass.
#
# KNOWN LIMIT, stated so nobody mistakes it for coverage: the closure walks
# `#include "…"` edges through PUBLIC headers (lib/<x>/include/<inc>/<stem>.h ->
# lib/<x>/src/<stem>*.c). An accelerator reached only through a private
# same-directory header is invisible to the discovery leg. One exists today —
# core/modules/crypto/src/keccak_x4.c, the AVX-512 Keccak permutation behind
# keccak_x4_internal.h. It is pinned in practice, because the sha3_256_x4 and
# sha3_512_x4 oracles drive their AVX-512 tier through it, but the gate would
# not notice a NEW private-header accelerator of the same shape. Give a new
# accelerator a public header, or add its row by hand.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. "$SCRIPT_DIR/gate_lib.sh"

GATE="check-accel-oracle-pinned"
REGISTRY="tools/lint/accel_oracle_registry.txt"
TEST_CATALOG="tools/dev/test_group_catalog.def"

# Floors: the tree has had these since the seal landed. A collapse below them
# means the scan broke, not that the tree got simpler.
CLOSURE_FLOOR=30
ISA_FLOOR=4
REGISTRY_FLOOR=4

fail=0
note() { echo "  $*"; }
bad()  { echo "FAIL: $*" >&2; fail=1; }

[ -f "$REGISTRY" ] || { echo "$GATE: FATAL — missing $REGISTRY" >&2; exit 2; }
[ -f "$TEST_CATALOG" ] || { echo "$GATE: FATAL — missing $TEST_CATALOG" >&2; exit 2; }
# shellcheck source=tools/lint/repo_shape.sh
. tools/lint/repo_shape.sh

# ── header -> implementation index ────────────────────────────────────────
# lib/<x>/include/<inc>/<stem>.h  maps to  lib/<x>/src/<stem>*.c, which is how
# this tree names every primitive and its ISA variants (sha3.c/sha3_avx512.c,
# blake2b.c/blake2b_avx2.c, fr.c/fr_avx512.c, bn254.c/bn254_accel.c).
declare -A HDR2IMPL
hdr_count=0
while IFS= read -r h; do
    case "$h" in */modules/*/include/*) ;; *) continue ;; esac
    libdir="${h%%/include/*}"
    stem="$(basename "$h" .h)"
    key="${h#*/include/}"
    impls=""
    for c in "$libdir"/src/"$stem"*.c; do
        [ -f "$c" ] && impls="$impls $c"
    done
    HDR2IMPL["$key"]="$impls"
    hdr_count=$((hdr_count + 1))
done < <(for d in "${ZCL_MODULE_DIRS[@]}"; do git ls-files "$d/include/*.h" "$d/include/**/*.h"; done)
gate_require_scanned "$hdr_count" 100 "$GATE" \
    "expected >=100 reusable-module headers; the include tree moved."

# ── leg 1a: include-closure of core/ over lib/*/src ───────────────────────
declare -A SEEN
work=()
while IFS= read -r inc; do
    [ -n "${HDR2IMPL[$inc]+x}" ] || continue
    for c in ${HDR2IMPL[$inc]}; do work+=("$c"); done
done < <(git grep -hoE '#include[[:space:]]+"[^"]+"' -- core/ \
         | sed 's/.*"\(.*\)"/\1/' | sort -u)

gate_require_scanned "${#work[@]}" 5 "$GATE" \
    "core/ resolved to almost no lib implementation files; core/ moved or emptied."

while [ ${#work[@]} -gt 0 ]; do
    f="${work[0]}"; work=("${work[@]:1}")
    [ -n "${SEEN[$f]+x}" ] && continue
    SEEN["$f"]=1
    while IFS= read -r inc; do
        [ -n "${HDR2IMPL[$inc]+x}" ] || continue
        for c in ${HDR2IMPL[$inc]}; do
            [ -n "${SEEN[$c]+x}" ] || work+=("$c")
        done
    done < <(grep -oE '#include[[:space:]]+"[^"]+"' "$f" 2>/dev/null \
             | sed 's/.*"\(.*\)"/\1/' | sort -u)
done
gate_require_scanned "${#SEEN[@]}" "$CLOSURE_FLOOR" "$GATE" \
    "the core/ include closure collapsed; the resolver or the tree layout moved."

# ── leg 1b: which closure members carry an ISA dispatch ───────────────────
ISA_RE='<(immintrin|x86intrin|cpuid)\.h>|__builtin_cpu_supports|__attribute__[[:space:]]*\(\([[:space:]]*target[[:space:]]*\('
declare -A ISA
for f in "${!SEEN[@]}"; do
    # Hardware-profile discovery chooses among separately pinned
    # implementations; it does not implement consensus arithmetic itself.
    [ "$f" = "platform/modules/util/src/hw_profile.c" ] && continue
    scan=("$f")
    d="$(dirname "$f")"
    # Private same-directory headers count: sha3_avx512.c keeps its intrinsics
    # in keccak_x4_internal.h.
    while IFS= read -r inc; do
        [ -f "$d/$inc" ] && scan+=("$d/$inc")
    done < <(grep -oE '#include[[:space:]]+"[^"/]+"' "$f" 2>/dev/null \
             | sed 's/.*"\(.*\)"/\1/')
    if gate_grep -qE "$ISA_RE" "${scan[@]}"; then
        ISA["$f"]=1
    fi
done
gate_require_scanned "${#ISA[@]}" "$ISA_FLOOR" "$GATE" \
    "no ISA-dispatched file found under sealed core/ — the detector regex broke."

# ── registry ──────────────────────────────────────────────────────────────
declare -A REG_ORACLES     # impl -> "oracle:group oracle:group"
rows=0
while IFS= read -r line; do
    line="${line%%#*}"
    # shellcheck disable=SC2086
    set -- $line
    [ $# -eq 0 ] && continue
    if [ $# -ne 3 ]; then
        bad "$REGISTRY: malformed row (want '<impl.c> <oracle.c> <group>'): $line"
        continue
    fi
    REG_ORACLES["$1"]="${REG_ORACLES[$1]:-} $2:$3"
    rows=$((rows + 1))
done < "$REGISTRY"
gate_require_scanned "$rows" "$REGISTRY_FLOOR" "$GATE" \
    "$REGISTRY lost rows; the registry may only shrink when an accelerator is deleted."

# ── leg 1c: every ISA file must be registered ─────────────────────────────
for f in "${!ISA[@]}"; do
    if [ -z "${REG_ORACLES[$f]+x}" ]; then
        bad "$f is ISA-dispatched and reachable from sealed core/, but has no
      row in $REGISTRY. Editing it changes what a sealed consensus predicate
      computes while check-core-seal stays green. Write a differential oracle
      that pins it to a portable reference and add the row."
    fi
done

# ── leg 2: no stale rows ──────────────────────────────────────────────────
for f in "${!REG_ORACLES[@]}"; do
    if [ ! -f "$f" ]; then
        bad "$REGISTRY names '$f', which does not exist. Delete the row if the
      accelerator is gone."
        continue
    fi
    if [ -z "${SEEN[$f]+x}" ]; then
        bad "$REGISTRY names '$f', which sealed core/ no longer reaches.
      Delete the row deliberately (and say why in the commit) rather than
      leaving the registry describing a path that is not there."
        continue
    fi
    if [ -z "${ISA[$f]+x}" ]; then
        bad "$REGISTRY names '$f', which no longer carries an ISA dispatch.
      Either the accelerator was removed (delete the row) or the detector
      needs updating for a new intrinsic form."
    fi
done

# ── legs 3 and 4: the oracles are present, dispatched, and still wired ────
for f in "${!REG_ORACLES[@]}"; do
    [ -f "$f" ] || continue

    # Exported (non-static) function names defined by the implementation.
    exports="$(grep -oE '^[A-Za-z_][A-Za-z0-9_ *]*[ *]([a-z_][a-z0-9_]*)\(' "$f" 2>/dev/null \
               | grep -vE '^(static|typedef)' \
               | sed 's/.*[ *]\([a-z_][a-z0-9_]*\)($/\1/' \
               | sort -u || true)"

    for pair in ${REG_ORACLES[$f]}; do
        oracle="${pair%%:*}"
        group="${pair##*:}"

        if [ ! -f "$oracle" ]; then
            bad "$f is pinned by '$oracle', which does not exist. An
      accelerator under sealed core/ with no oracle is unprotected: nothing
      else in the tree checks it against a portable reference."
            continue
        fi
        if ! gate_grep -q "ACCEL-ORACLE: $f" "$oracle"; then
            bad "$oracle does not carry the marker line 'ACCEL-ORACLE: $f'.
      The marker is what makes the pin visible from the test file itself."
        fi
        if ! gate_grep -qE "ZCL_TEST_GROUP\\($group\\)" "$TEST_CATALOG"; then
            bad "test group '$group' (oracle $oracle) is not registered as
      ZCL_TEST_GROUP($group) in $TEST_CATALOG, so it never runs. A compiled-but-undispatched
      oracle proves nothing."
        fi

        if [ -n "$exports" ]; then
            hit=0
            while IFS= read -r sym; do
                [ -n "$sym" ] || continue
                if gate_grep -q "\\b$sym\\b" "$oracle"; then hit=1; break; fi
            done <<< "$exports"
            if [ "$hit" -eq 0 ]; then
                bad "$oracle references no function exported by $f. The pin is
      nominal only — a renamed entry point would leave this oracle green while
      testing code the node no longer calls."
            fi
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo "" >&2
    echo "The consensus-core seal (core/MANIFEST.sha3) covers the predicate" >&2
    echo "TEXT, not the accelerated arithmetic beneath it. This gate is what" >&2
    echo "covers the arithmetic. See docs/CONSENSUS_PARITY_DOCTRINE.md." >&2
    exit 1
fi

note "OK: ${#ISA[@]} ISA-dispatched file(s) reachable from sealed core/" \
     "(closure ${#SEEN[@]} files), each pinned by a dispatched differential oracle."
