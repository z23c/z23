#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check-no-stale-pinned-facts — forbid ROT-PRONE PINNED FACTS in the docs.
#
# Owner directive (2026-07-17): "don't ever rely on stale documents — build
# tools that make staleness impossible." A numeric fact that has a LIVE SOURCE
# (the built binary's size; the node's current H*) must be DERIVED or GATED,
# never hand-pinned into prose. Hand-pinning is exactly how a stale "~15 MB
# binary" claim survived long after the real binary grew to ~20 MB.
#
# This gate greps the present-tense docs (CLAUDE.md + README.md + docs/**/*.md)
# for two classes of pinned fact and FAILS with a de-pin pointer:
#
#   (A) BINARY-SIZE CLAIM  [HARD — never grandfathered]
#       A line stating a "<N> MB" / "<N>MB" size AND the word "binary".
#       The binary's size has a live source (the built artifact — see
#       tools/scripts/binary_size.sh) and must NOT be hand-pinned. Fix by
#       rewriting to size-agnostic language ("compact self-contained C23
#       binary") or by quoting the derived value from binary_size.sh. This is
#       the owner's named failure class, so it is NEVER baseline-exemptible.
#
#   (B) LIVE-STATE HEIGHT PIN  [RATCHET — shrinking baseline]
#       A line asserting the node's *current* chain state at a specific height
#       — a live-state trigger ("H*=", "wedged at", "held at", "currently
#       …at/wedged/held", "live tip", "stuck at", "pinned at") next to a
#       height-shaped number. Live state belongs on the ONE live-state page,
#       docs/agent/HANDOFF.md; every other doc must point there, not pin a height
#       that rots the moment the node moves. New pins FAIL; the pre-existing
#       corpus is grandfathered in tools/lint/stale_pinned_facts_baseline.txt
#       (shrink-only — the concurrent doc-hygiene lane drains it).
#
# ── Precision / allowlisting ────────────────────────────────────────────────
# Scope is deliberately narrow to keep false positives near zero:
#   * docs/agent/HANDOFF.md is EXEMPT — it is the one sanctioned live-state page.
#   * docs/work/archive/** is EXEMPT — frozen historical narratives; pinning a
#     past height is their whole point (git history is the archaeology).
# Per-line escape hatch: a trailing `<!-- stale-ok: <reason> -->` marker
# exempts a line that legitimately pins a constant or records a dated
# measurement (a benchmark log row, an immutable ADR positioning statement).
# The reason must be non-empty.
#
# This is a FORBID gate (like tools/lint/lintc/gate_tree_walk.c): it need not
# scan a non-empty set to be meaningful, but it MUST exit non-zero on a
# violation and zero when clean. It is standalone-runnable and build-free
# (filesystem + grep only).
#
#   ZCL_STALE_FACTS_SCAN_FILES="a.md b.md"   override the scan set (selftest)
#   ZCL_STALE_FACTS_EMIT_BASELINE=1          print current height-pin keys to
#                                            stdout and exit 0 (regenerate the
#                                            baseline: `... >baseline.txt`)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

BASELINE="$SCRIPT_DIR/stale_pinned_facts_baseline.txt"
EMIT="${ZCL_STALE_FACTS_EMIT_BASELINE:-0}"

# ── Scan set ────────────────────────────────────────────────────────────────
# CLAUDE.md + README.md + every tracked docs/**/*.md, MINUS the live-state page
# (HANDOFF.md) and the frozen historical archive (docs/work/archive/**).
if [[ -n "${ZCL_STALE_FACTS_SCAN_FILES:-}" ]]; then
    read -r -a scan_files <<< "$ZCL_STALE_FACTS_SCAN_FILES"
    FLOOR=1   # selftest override may point at a single fixture
else
    mapfile -t scan_files < <(
        { printf '%s\n' CLAUDE.md README.md; git ls-files 'docs/'; } \
        | grep -E '\.md$' \
        | grep -vE '^docs/HANDOFF\.md$|^docs/work/archive/' \
        | sort -u
    )
    FLOOR=3   # CLAUDE.md + README.md + at least one docs/*.md must be present
fi

# Keep only files that actually exist (a tracked-but-deleted path would break
# grep); this also makes the override forgiving.
existing=()
for f in "${scan_files[@]}"; do [[ -f "$f" ]] && existing+=("$f"); done
scan_files=("${existing[@]}")

gate_require_scanned "${#scan_files[@]}" "$FLOOR" check-no-stale-pinned-facts \
    "CLAUDE.md/README.md/docs missing — run from repo root inside the worktree?"

# ── Patterns ────────────────────────────────────────────────────────────────
# (A) binary size: a "<N> MB" token ADJACENT to the word "binary" (either
#     order), so it qualifies THE BINARY — not a bystander like "512 MB RAM;
#     the binary handles …". MB is case-sensitive (uppercase) so "Mbps"/"Mb"
#     never match. Forward: "<N> MB <≤4 filler words> binary". Reverse:
#     "binary <≤25 non-period chars> <N> MB" (e.g. "binary is 20 MB",
#     "binary size | 14.6 MB").
BINSIZE_FWD='[0-9]+(\.[0-9]+)?[[:space:]]*MB[[:space:]]+([-A-Za-z0-9,()$]+[[:space:]]+){0,4}[Bb]inar(y|ies)'
BINSIZE_REV='[Bb]inar(y|ies)[^.]{0,25}[0-9]+(\.[0-9]+)?[[:space:]]*MB'
BINSIZE_RE="($BINSIZE_FWD)|($BINSIZE_REV)"
# (B) live-state trigger + height-shaped number.
HEIGHT_TRIGGER_RE='(H\\?\*[[:space:]]*=)|(wedged[[:space:]]+at)|(held[[:space:]]+at)|(currently[[:space:]]+(wedged|held|at|stuck|pinned))|(live[[:space:]]+tip)|(stuck[[:space:]]+at)|(pinned[[:space:]]+at)'
HEIGHT_NUM_RE='([0-9]{1,3}(,[0-9]{3})+)|([0-9]{6,})'
# per-line escape hatch
STALE_OK_RE='<!--[[:space:]]*stale-ok:[[:space:]]*[^[:space:]].*-->'

has_stale_ok() { grep -qE "$STALE_OK_RE" <<<"$1"; }

# Normalize a matched line into a line-number-independent baseline key so the
# grandfather list survives edits/reflows elsewhere in the file.
norm() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"           # ltrim
    s="${s%"${s##*[![:space:]]}"}"           # rtrim
    printf '%s' "$s" | tr -s '[:space:]' ' ' # squeeze internal whitespace
}

# ── Load baseline (height pins only) ────────────────────────────────────────
declare -A ALLOWED=()
if [[ -f "$BASELINE" ]]; then
    while IFS= read -r line; do
        # A baseline data line is `path|normtext`; its normtext may itself
        # contain (or begin with) '#', so ONLY a whole-line comment — first
        # non-whitespace char '#' — is stripped, never an inline '#'. Data
        # lines always start with the path, so this never eats a real key.
        line="${line#"${line%%[![:space:]]*}"}"   # ltrim
        line="${line%"${line##*[![:space:]]}"}"   # rtrim
        [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
        ALLOWED["$line"]=1
    done < "$BASELINE"
fi

# ── Detect ──────────────────────────────────────────────────────────────────
# grep -Hn always emits `path:lineno:text` (‑H forces the filename even for a
# single-file scan); md paths contain no ':' so path/lineno parse cleanly and
# any ':' inside the matched TEXT (e.g. "stale-ok:") stays in the text field.
bin_raw=$(grep -HnIE "$BINSIZE_RE" "${scan_files[@]}" 2>/dev/null || true)
hgt_raw=$(grep -HnI -iE "$HEIGHT_TRIGGER_RE" "${scan_files[@]}" 2>/dev/null \
            | grep -E "$HEIGHT_NUM_RE" || true)

# --emit-baseline: dump every current height-pin key (ignoring the baseline),
# so the shrink-only file can be regenerated deterministically.
if [[ "$EMIT" == "1" ]]; then
    if [[ -n "${hgt_raw//[[:space:]]/}" ]]; then
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            path="${entry%%:*}"; rest="${entry#*:}"; text="${rest#*:}"
            has_stale_ok "$text" && continue
            printf '%s|%s\n' "$path" "$(norm "$text")"
        done <<< "$hgt_raw" | sort -u
    fi
    exit 0
fi

bin_violations=0
hgt_violations=0
grandfathered=0
stale_ok_skips=0

if [[ -n "${bin_raw//[[:space:]]/}" ]]; then
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        path="${entry%%:*}"; rest="${entry#*:}"; lineno="${rest%%:*}"; text="${rest#*:}"
        if has_stale_ok "$text"; then stale_ok_skips=$((stale_ok_skips+1)); continue; fi
        bin_violations=$((bin_violations+1))
        echo "STALE BINARY-SIZE PIN  $path:$lineno" >&2
        echo "    ${text#"${text%%[![:space:]]*}"}" >&2
    done <<< "$bin_raw"
fi

if [[ -n "${hgt_raw//[[:space:]]/}" ]]; then
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        path="${entry%%:*}"; rest="${entry#*:}"; lineno="${rest%%:*}"; text="${rest#*:}"
        if has_stale_ok "$text"; then stale_ok_skips=$((stale_ok_skips+1)); continue; fi
        key="$path|$(norm "$text")"
        if [[ -n "${ALLOWED[$key]:-}" ]]; then grandfathered=$((grandfathered+1)); continue; fi
        hgt_violations=$((hgt_violations+1))
        echo "NEW LIVE-STATE HEIGHT PIN  $path:$lineno" >&2
        echo "    ${text#"${text%%[![:space:]]*}"}" >&2
    done <<< "$hgt_raw"
fi

# ── Report ──────────────────────────────────────────────────────────────────
total=$((bin_violations + hgt_violations))
echo "[check_no_stale_pinned_facts] scanned ${#scan_files[@]} doc(s); $total violation(s) (binary-size=$bin_violations, height-pin=$hgt_violations)"
(( grandfathered > 0 )) && echo "[check_no_stale_pinned_facts] $grandfathered grandfathered height-pin(s) tolerated via baseline (shrink-only)"
(( stale_ok_skips > 0 )) && echo "[check_no_stale_pinned_facts] $stale_ok_skips line(s) exempt via <!-- stale-ok: … --> marker"

if (( total > 0 )); then
    echo "" >&2
    echo "FAIL: docs hand-pin a fact with a live source." >&2
    if (( bin_violations > 0 )); then
        echo "  binary-size: use size-agnostic language (\"compact self-contained C23 binary\")" >&2
        echo "               or quote the derived value from tools/scripts/binary_size.sh." >&2
        echo "               (NOT baseline-exemptible — this is the owner's named case.)" >&2
    fi
    if (( hgt_violations > 0 )); then
        echo "  height-pin:  live state lives in docs/agent/HANDOFF.md — point there, don't pin a height." >&2
        echo "               Verify the live H* (z23 dumpstate reducer_frontier) before writing." >&2
        echo "               A legitimately-constant/dated line may add a trailing" >&2
        echo "               <!-- stale-ok: <reason> --> marker." >&2
    fi
    exit 1
fi

echo "[check_no_stale_pinned_facts] clean — no stale pinned binary-size or live-state height facts"
exit 0
