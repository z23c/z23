#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_denied_leaves.sh — no command leaf named in
# config/hotswap_denied_leaves.def may appear in ANY hot-swap manifest.
#
# ── WHY THIS GATE IS NOT check-hotswap-eligible-scope ──────────────────────
# That gate is PATH-based: it refuses a manifest row whose translation unit
# sits under core/, lib/consensus/, lib/validation/, lib/storage/, lib/net/,
# lib/coins/ or app/jobs/. It structurally cannot express the owner rule this
# gate enforces, because the TU that owns core.chain.block.get and
# core.chain.transaction.get is app/controllers/src/chain_native_handlers.c —
# an app-layer controller that is legitimately eligible and ALREADY admitted
# (probe core.consensus.utxo.audit). What must be denied is two LEAF NAMES
# inside an otherwise-eligible file.
#
# Nor is "READY + read-only" the right test: both leaves are
# ZCL_COMMAND_READY_READ and pass every existing eligibility check cleanly.
# They RENDER BLOCK AND TRANSACTION BYTES, so a swapped generation misreports
# the chain to every RPC reader while validation and the node's own consensus
# state stay untouched and self-consistent. The reason for each denial lives
# in the .def next to the name, never in this script.
#
# ── FAIL-CLOSED CONTRACT ───────────────────────────────────────────────────
# Every "I could not look" path is exit 2, never exit 0:
#   * denylist missing / unreadable            → exit 2
#   * denylist parses to zero entries          → exit 2 (gate_require_scanned)
#   * a denied leaf is not declared in the config/commands catalog → exit 1
#     (a typo'd row denies NOTHING; that is a hollow denial, so it is a
#     violation, not a pass)
#   * an entry carries no reason               → exit 1
#   * zero manifests found to scan             → exit 2
#   * zero translation units parsed from them  → exit 2
# A denied leaf found in a manifest is exit 1.
#
# The scan set is DERIVED, not enumerated: every config/hotswap*.def plus
# config/hotfork_capsules.def, so a hot-swap manifest added after this gate
# was written is covered on the day it lands rather than on the day somebody
# remembers to widen a list here.
#
# ── THE MANIFEST THAT IS WRITTEN IN C ──────────────────────────────────────
# Scanning config/ alone would have been a rail around an open door. The
# Tier-1 generation path stages whatever a TU's ZCL_HOTSWAP_EXPORT_LEAVES
# table exports, and hotswap_leaf_stage_thunk() in
# lib/hotswap/src/hotswap_loader.c applies NO per-leaf allowlist — it accepts
# every row. When this gate was written, app/controllers/src/
# chain_native_handlers.c staged core.chain.block.get and
# core.chain.transaction.get in exactly that table, so a recompiled
# generation re-pointed both of them although neither leaf was named in any
# .def file. (The Tier-2 module path was never exposed: hotswap_module_admit()
# checks each leaf against config/hotswap_swappable.def.) So the
# `#ifdef ZCL_HOTSWAP_GEN` / `#ifdef ZCL_HOTSWAP_MODULE_GEN` blocks of every
# TU either manifest can recompile are scanned as manifests too. Resident code
# outside those blocks is NOT scanned — a controller may name its own leaf.
#
# Overrides (test isolation only; unset in production):
#   ZCL_HOTSWAP_DENYLIST        path to the denylist .def
#   ZCL_HOTSWAP_DENY_SCAN_DIR   directory whose hot-swap manifests are scanned
#   ZCL_HOTSWAP_DENY_CATALOG    config/commands catalog directory
#   ZCL_HOTSWAP_DENY_TU_ROOT    base dir manifest TU paths resolve against
#
# --selftest is 9 cases: an unmodified sandbox copy passes (so a later "it
# tripped" means something), a denied leaf trips as an eligibility PROBE, as
# one entry of a space-separated swappable LEAF LIST, as a resident PROBE
# CASE, and inside a C ZCL_HOTSWAP_GEN leaf table; the same leaf named only in
# a COMMENT or only in RESIDENT code does not trip; a missing denylist and an
# empty denylist are both exit 2; and the real tree is exit 0. A gate that has
# never been shown to fire is not evidence of anything.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

DENYLIST="${ZCL_HOTSWAP_DENYLIST:-config/hotswap_denied_leaves.def}"
SCAN_DIR="${ZCL_HOTSWAP_DENY_SCAN_DIR:-config}"
CATALOG="${ZCL_HOTSWAP_DENY_CATALOG:-config/commands}"
TU_ROOT="${ZCL_HOTSWAP_DENY_TU_ROOT:-.}"

# Quote-aware C-comment stripper. Prose in a .def header that mentions a
# denied leaf (this repo's manifests document their own rules at length) must
# not read as a manifest entry, and a leaf name inside a string must survive.
strip_c_comments() {
    awk '
    BEGIN { inc = 0; inq = 0 }
    {
        out = ""; n = length($0)
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1); d = substr($0, i, 2)
            if (inc) { if (d == "*/") { inc = 0; i++ } ; continue }
            if (inq) {
                out = out c
                if (c == "\\") { out = out substr($0, i + 1, 1); i++; continue }
                if (c == "\"") { inq = 0 }
                continue
            }
            if (d == "/*") { inc = 1; i++; continue }
            if (d == "//") { break }
            if (c == "\"") { inq = 1; out = out c; continue }
            out = out c
        }
        print out
    }' "$@"
}

# Emit one "<leaf>\t<reason>" line per HOTSWAP_DENIED_LEAF invocation.
#
# The scan is QUOTE-AWARE and does not anchor to line shape: a reason may be
# split across as many adjacent string literals as it needs (they concatenate,
# exactly as the C preprocessor would) and may itself contain parentheses.
# A `[^)]*` regex over the invocation looked simpler and was wrong — it
# truncated the very first committed reason at "(header + transactions)" and
# reported that row as unexplained.
parse_denylist() {
    strip_c_comments "$1" | awk '
    { buf = buf $0 " " }
    END {
        n = length(buf); i = 1
        while (1) {
            p = index(substr(buf, i), "HOTSWAP_DENIED_LEAF")
            if (p == 0) break
            i = i + p - 1 + length("HOTSWAP_DENIED_LEAF")
            while (i <= n && substr(buf, i, 1) != "(") i++
            i++
            leaf = ""; reason = ""; k = 0
            while (i <= n) {
                c = substr(buf, i, 1)
                if (c == ")") { i++; break }
                if (c == "\"") {
                    i++; s = ""
                    while (i <= n) {
                        ch = substr(buf, i, 1)
                        if (ch == "\\") { s = s substr(buf, i + 1, 1); i += 2; continue }
                        if (ch == "\"") { i++; break }
                        s = s ch; i++
                    }
                    if (k == 0) leaf = s; else reason = reason s
                    k++
                    continue
                }
                i++
            }
            printf "%s\t%s\n", leaf, reason
        }
    }'
}

# Emit the body of every `#ifdef ZCL_HOTSWAP_GEN` / `#ifdef
# ZCL_HOTSWAP_MODULE_GEN` block in a translation unit, nesting-aware.
#
# Those blocks are the Tier-1 / Tier-2 manifests that are written in C rather
# than in config/: ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, ...) is what a
# generation .so actually stages, and hotswap_loader.c's staging thunk applies
# NO per-leaf allowlist — it accepts every row the table exports. A leaf can
# therefore be re-pointed by a dlopen'd generation while appearing in no .def
# file at all. Scanning only config/ would have missed exactly that, so the
# leaf tables are scanned too. Resident code outside these blocks is NOT
# scanned: a controller may legitimately name a leaf in its own dispatch.
extract_gen_blocks() {
    awk '
    BEGIN { on = 0; depth = 0 }
    /^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef)/ {
        if (!on) {
            if ($0 ~ /ZCL_HOTSWAP_GEN/ || $0 ~ /ZCL_HOTSWAP_MODULE_GEN/) {
                on = 1; depth = 1
            }
            next
        }
        depth++
        next
    }
    /^[[:space:]]*#[[:space:]]*endif/ {
        if (on) { depth--; if (depth == 0) on = 0 }
        next
    }
    { if (on) print }
    ' "$1"
}

run_gate() {
    echo "══ LINT: hot-swap leaf denylist (never-swappable command leaves) ══"

    if [ ! -r "$DENYLIST" ]; then
        echo "check_hotswap_denied_leaves: FATAL — denylist '$DENYLIST' missing/unreadable." >&2
        echo "  An absent denylist does NOT mean 'nothing is denied'. Refusing" >&2
        echo "  to report 'clean' with no owner decision to enforce." >&2
        return 2
    fi
    if [ ! -d "$CATALOG" ]; then
        echo "check_hotswap_denied_leaves: FATAL — command catalog '$CATALOG' missing." >&2
        return 2
    fi
    if [ ! -d "$SCAN_DIR" ]; then
        echo "check_hotswap_denied_leaves: FATAL — scan dir '$SCAN_DIR' missing." >&2
        return 2
    fi

    # ── parse the denylist ────────────────────────────────────────────────
    local -a entries=()
    mapfile -t entries < <(parse_denylist "$DENYLIST")

    gate_require_scanned "${#entries[@]}" 1 check_hotswap_denied_leaves \
        "no HOTSWAP_DENIED_LEAF(\"leaf\", \"reason\") entries parsed from $DENYLIST"

    local violations="" entry leaf reason
    local -a leaves=()
    for entry in "${entries[@]}"; do
        leaf="${entry%%$'\t'*}"
        reason="${entry#*$'\t'}"

        case "$leaf" in
            ""|*[!A-Za-z0-9_.]*)
                violations="${violations}  denylist row '$entry' has no valid dotted leaf"$'\n'
                continue ;;
        esac
        if [ "${#reason}" -lt 20 ]; then
            violations="${violations}  $leaf (denylist row carries no usable reason — the reason must live beside the name)"$'\n'
        fi
        # A denied leaf that no longer exists in the catalog denies nothing.
        if ! grep -rqF "\"$leaf\"," "$CATALOG"; then
            violations="${violations}  $leaf (not declared in $CATALOG — a denial of a nonexistent leaf is hollow)"$'\n'
        fi
        leaves+=("$leaf")
    done

    gate_require_scanned "${#leaves[@]}" 1 check_hotswap_denied_leaves \
        "every denylist row failed to yield a leaf name"

    # ── enumerate the manifests ───────────────────────────────────────────
    local deny_real
    deny_real="$(cd "$(dirname "$DENYLIST")" && pwd)/$(basename "$DENYLIST")"
    local -a manifests=()
    local f fr
    for f in "$SCAN_DIR"/hotswap*.def "$SCAN_DIR"/hotfork_capsules.def; do
        [ -f "$f" ] || continue
        fr="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
        [ "$fr" = "$deny_real" ] && continue
        manifests+=("$f")
    done
    gate_require_scanned "${#manifests[@]}" 1 check_hotswap_denied_leaves \
        "no hot-swap manifests found under $SCAN_DIR — the scan producer emptied"

    # ── the scan ──────────────────────────────────────────────────────────
    # Tokens are every whitespace-separated word inside every string literal,
    # so both a bare "core.chain.block.get" argument and a space-separated
    # leaf list ("a b c") are covered by one comparison.
    local tokens tok
    for f in "${manifests[@]}"; do
        tokens="$(strip_c_comments "$f" \
            | grep -oE '"[^"]*"' | tr -d '"' | tr ' \t' '\n\n' | sort -u)"
        local -A present=()
        while IFS= read -r tok; do
            [ -n "$tok" ] || continue
            present["$tok"]=1
        done <<< "$tokens"
        for leaf in "${leaves[@]}"; do
            if [ -n "${present[$leaf]:-}" ]; then
                violations="${violations}  $f names denied leaf '$leaf'"$'\n'
            fi
        done
        unset present
    done

    # ── the C-side leaf tables ────────────────────────────────────────────
    # Union of every TU either manifest can recompile into a .so. Its
    # ZCL_HOTSWAP_GEN / ZCL_HOTSWAP_MODULE_GEN blocks are manifests too.
    local -a tus=()
    local -A seen_tu=()
    local tu
    while IFS= read -r tu; do
        [ -n "$tu" ] || continue
        [ -n "${seen_tu[$tu]:-}" ] && continue
        seen_tu["$tu"]=1
        tus+=("$tu")
    done < <(
        for f in "${manifests[@]}"; do
            case "$(basename "$f")" in
                hotswap_eligible.def)
                    sed -n 's/^[[:space:]]*HOTSWAP_ELIGIBLE("\([^"]*\)").*/\1/p' "$f" ;;
                hotswap_swappable.def)
                    sed -n 's/^[[:space:]]*HOTSWAP_SWAPPABLE("\([^"]*\)".*/\1/p' "$f" ;;
            esac
        done
    )
    gate_require_scanned "${#tus[@]}" 1 check_hotswap_denied_leaves \
        "no hot-swappable translation units parsed from the manifests"

    local tu_path
    for tu in "${tus[@]}"; do
        tu_path="$TU_ROOT/$tu"
        [ -f "$tu_path" ] || continue
        tokens="$(extract_gen_blocks "$tu_path" | strip_c_comments \
            | grep -oE '"[^"]*"' | tr -d '"' | tr ' \t' '\n\n' | sort -u)"
        local -A gpresent=()
        while IFS= read -r tok; do
            [ -n "$tok" ] || continue
            gpresent["$tok"]=1
        done <<< "$tokens"
        for leaf in "${leaves[@]}"; do
            if [ -n "${gpresent[$leaf]:-}" ]; then
                violations="${violations}  $tu stages denied leaf '$leaf' in a ZCL_HOTSWAP_*_GEN leaf table"$'\n'
            fi
        done
        unset gpresent
    done

    if [ -n "${violations//[[:space:]]/}" ]; then
        printf '%s' "$violations" >&2
        echo "FAIL: a hot-swap manifest names a leaf the owner ruled never swappable." >&2
        echo "  These leaves render block/transaction bytes: a swapped generation" >&2
        echo "  misreports the chain to every RPC reader without touching" >&2
        echo "  validation. 'Read-only' is not the test on a rendering path." >&2
        echo "  The rule and its per-leaf reason live in $DENYLIST." >&2
        echo "  Removing a row there is an OWNER decision, not a lane's." >&2
        return 1
    fi

    echo "  OK: ${#leaves[@]} denied leaf/leaves absent from ${#manifests[@]} hot-swap manifest(s)"
    return 0
}

# ── selftest ──────────────────────────────────────────────────────────────
selftest_dir=""
selftest_cleanup() {
    [ -n "$selftest_dir" ] && [ -d "$selftest_dir" ] && rm -rf -- "$selftest_dir"
}

# Run this script in a subshell with a scrubbed environment override set.
# Never judge through a pipe: redirect to a file, capture $? on the next line.
run_case() {
    local scan="$1" deny="$2" out="$3" turoot="${4:-.}" rc
    ZCL_HOTSWAP_DENY_SCAN_DIR="$scan" ZCL_HOTSWAP_DENYLIST="$deny" \
        ZCL_HOTSWAP_DENY_TU_ROOT="$turoot" \
        bash "$SCRIPT_PATH" >"$out" 2>&1
    rc=$?
    return "$rc"
}

run_selftest() {
    local scratch="${ZCL_SCRATCH_DIR:-$HOME/.local/state/zclassic23/scratch}"
    mkdir -p "$scratch" 2>/dev/null || scratch="."
    selftest_dir="$(mktemp -d "$scratch/zcl-hotswap-deny-selftest.XXXXXX")" || {
        echo "check_hotswap_denied_leaves selftest: FATAL — no scratch dir" >&2
        exit 2
    }
    trap selftest_cleanup EXIT HUP INT TERM

    local sandbox="$selftest_dir/config"
    mkdir -p "$sandbox"
    cp config/hotswap*.def "$sandbox/" 2>/dev/null
    cp config/hotfork_capsules.def "$sandbox/" 2>/dev/null
    rm -f "$sandbox/$(basename "$DENYLIST")"
    local deny="$ROOT/$DENYLIST"
    local log="$selftest_dir/out.txt" rc=0

    # Case 0: the sandbox copy is a faithful copy — it must PASS untouched, or
    # every later "it tripped" verdict would be meaningless.
    run_case "$sandbox" "$deny" "$log"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "selftest: FAIL — an unmodified sandbox copy did not pass (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi

    # Case 1: denied leaf as an eligibility PROBE.
    cp "$sandbox/hotswap_eligible.def" "$selftest_dir/eligible.orig"
    printf '%s\n' \
        'HOTSWAP_ELIGIBLE("app/controllers/src/chain_native_handlers.c") HOTSWAP_PROBE("core.chain.block.get")' \
        >>"$sandbox/hotswap_eligible.def"
    run_case "$sandbox" "$deny" "$log"
    rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "selftest: FAIL — a denied leaf planted as a HOTSWAP_PROBE did not trip the gate (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi
    if str_lacks "$(cat "$log")" "core.chain.block.get"; then
        echo "selftest: FAIL — the failure did not name the denied leaf" >&2
        cat "$log" >&2
        exit 1
    fi
    cp "$selftest_dir/eligible.orig" "$sandbox/hotswap_eligible.def"

    # Case 2: denied leaf inside a swappable-module LEAF LIST (space-separated
    # inside ONE string literal — the shape a token-per-argument scan misses).
    cp "$sandbox/hotswap_swappable.def" "$selftest_dir/swappable.orig"
    printf '%s\n' \
        'HOTSWAP_SWAPPABLE("app/controllers/src/chain_native_handlers.c",' \
        '                  "core.consensus.utxo.audit core.chain.transaction.get")' \
        >>"$sandbox/hotswap_swappable.def"
    run_case "$sandbox" "$deny" "$log"
    rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "selftest: FAIL — a denied leaf inside a swappable leaf LIST did not trip the gate (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi
    cp "$selftest_dir/swappable.orig" "$sandbox/hotswap_swappable.def"

    # Case 3: denied leaf as a resident PROBE CASE operation.
    cp "$sandbox/hotswap_probe_cases.def" "$selftest_dir/probe.orig"
    printf '%s\n' \
        'HOTSWAP_PROBE_CASE("command.chain.block.get.v1", "command",' \
        '    "core.chain.block.get", "{}", "zcl.block.v1", 4096)' \
        >>"$sandbox/hotswap_probe_cases.def"
    run_case "$sandbox" "$deny" "$log"
    rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "selftest: FAIL — a denied leaf planted as a probe CASE did not trip the gate (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi
    cp "$selftest_dir/probe.orig" "$sandbox/hotswap_probe_cases.def"

    # Case 4: a leaf name that appears only in PROSE (a .def header comment)
    # is not a manifest entry — the gate must not fire on documentation.
    printf '%s\n' '/* core.chain.block.get is denied; see hotswap_denied_leaves.def */' \
        >>"$sandbox/hotswap_eligible.def"
    run_case "$sandbox" "$deny" "$log"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "selftest: FAIL — a denied leaf mentioned only in a COMMENT tripped the gate (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi
    cp "$selftest_dir/eligible.orig" "$sandbox/hotswap_eligible.def"

    # Case 4b: the C-side leaf table. A generation .so stages whatever
    # ZCL_HOTSWAP_EXPORT_LEAVES exports and the Tier-1 loader applies no
    # per-leaf allowlist, so a denied leaf can be re-pointed while appearing in
    # no .def at all — this leg is what caught the real one in
    # app/controllers/src/chain_native_handlers.c. The fixture TU is resolved
    # under ZCL_HOTSWAP_DENY_TU_ROOT so nothing is planted in the real tree.
    local turoot="$selftest_dir/turoot"
    mkdir -p "$turoot"
    {
        printf '%s\n' '#ifdef ZCL_HOTSWAP_GEN'
        printf '%s\n' 'static const struct zcl_hotswap_leaf_replacement k_leaves[] = {'
        printf '%s\n' '    { "core.chain.block.get", tramp_getblock },'
        printf '%s\n' '};'
        printf '%s\n' 'ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, 1)'
        printf '%s\n' '#endif'
        printf '%s\n' '/* resident code may name "core.chain.transaction.get" freely */'
        printf '%s\n' 'static const char *k_resident = "core.chain.transaction.get";'
    } >"$turoot/gen_fixture.c"
    printf '%s\n' \
        'HOTSWAP_ELIGIBLE("gen_fixture.c") HOTSWAP_PROBE("core.status")' \
        >>"$sandbox/hotswap_eligible.def"
    run_case "$sandbox" "$deny" "$log" "$turoot"
    rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "selftest: FAIL — a denied leaf in a ZCL_HOTSWAP_GEN leaf table did not trip the gate (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi
    if str_lacks "$(cat "$log")" "gen_fixture.c stages denied leaf"; then
        echo "selftest: FAIL — the C-table failure did not name the TU" >&2
        cat "$log" >&2
        exit 1
    fi
    # ...and resident code OUTSIDE the GEN block is not a violation: the same
    # fixture with only the resident mention must pass.
    if str_contains "$(cat "$log")" "core.chain.transaction.get"; then
        echo "selftest: FAIL — a leaf named only in RESIDENT code was reported" >&2
        cat "$log" >&2
        exit 1
    fi
    cp "$selftest_dir/eligible.orig" "$sandbox/hotswap_eligible.def"

    # Case 5: FAIL CLOSED — a missing denylist is exit 2, never a quiet pass.
    run_case "$sandbox" "$selftest_dir/does-not-exist.def" "$log"
    rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "selftest: FAIL — a missing denylist did not fail closed (rc=$rc, wanted 2)" >&2
        cat "$log" >&2
        exit 1
    fi

    # Case 6: FAIL CLOSED — a denylist that parses to zero entries is exit 2.
    printf '%s\n' '/* every row commented out */' >"$selftest_dir/empty.def"
    run_case "$sandbox" "$selftest_dir/empty.def" "$log"
    rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "selftest: FAIL — an empty denylist did not fail closed (rc=$rc, wanted 2)" >&2
        cat "$log" >&2
        exit 1
    fi

    # Case 7: recovery — the REAL tree still passes.
    ZCL_HOTSWAP_DENY_SCAN_DIR="config" ZCL_HOTSWAP_DENYLIST="$DENYLIST" \
        bash "$SCRIPT_PATH" >"$log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "selftest: FAIL — the real tree does not pass (rc=$rc)" >&2
        cat "$log" >&2
        exit 1
    fi

    echo "check_hotswap_denied_leaves selftest: PASS — 9 cases (probe, leaf list, C leaf table," \
         "probe case, comment-only, missing denylist, empty denylist, clean copy, real tree)"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

run_gate
exit $?
