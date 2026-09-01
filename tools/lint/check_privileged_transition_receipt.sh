#!/usr/bin/env bash
# Gate — privileged transitions require an independent authority receipt
# (Law 7, docs/work/os/A1-authority-receipt-idiom.md). MECHANIZED:
#
#   Every native command leaf whose spec is ZCL_COMMAND_AUTH_OWNER AND effect
#   ZCL_COMMAND_EFFECT_MUTATE or ZCL_COMMAND_EFFECT_DESTRUCTIVE is a candidate
#   privileged transition. Each such leaf MUST carry a disposition in
#   tools/lint/privileged_transition_receipt_baseline.txt — `receipt:<file>`
#   (the handler binds an authority_receipt verifier) or `exempt:<reason>` (not
#   an artifact-install transition). A NEW owner-mutating leaf with no
#   disposition FAILS, forcing a conscious Law-7 review before it can ship.
#
# For each `receipt:<file>` line the gate additionally asserts <file> contains a
# call to authority_receipt_.*_available( OR the pre-generalized
# consensus_state_replay_receipt_authority_available( — a positive check that
# the wired consumer actually gates on the contract (so a future edit cannot
# silently drop the gate).
#
# RATCHET: today's population is grandfathered as `exempt`; the gate fails only
# when a NEW undispositioned owner-mutating leaf appears. This gate does not
# require the contract be present today (no current leaf calls it) — it ratchets
# the ones to come (bundle ACTIVATE, hot-swap Phase-3 reopen, deploy generation
# publish, App cartridge activation).
#
# Fail-loud: an empty enumeration (no *.def / broken scan) exits 2, never a
# hollow "clean" exit 0.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# Test-isolation overrides (default to the real tree). The gate scans only the
# command .def files and specific receipt handler files — no broad source walk —
# so there is no self-match to exclude.
DEFDIR="${ZCL_PRIV_RECEIPT_DEF_DIR:-engine/composition/commands}"
BASELINE="${ZCL_PRIV_RECEIPT_BASELINE:-$SCRIPT_DIR/privileged_transition_receipt_baseline.txt}"

# ── Enumerate owner-mutating leaves from the command catalog (build-free) ──
# Walk each ZCL_COMMAND_{READY,PLANNED,COMPAT,DEV}_COMMAND( invocation by paren
# depth (string-literal aware); a spec qualifies iff its text contains
# ZCL_COMMAND_AUTH_OWNER and (ZCL_COMMAND_EFFECT_MUTATE | _EFFECT_DESTRUCTIVE);
# the leaf path is the first "…" token. READ-form macros hard-code EFFECT_READ
# and are excluded by construction.
ENUM_AWK='
{ buf = buf $0 "\n" }
END {
    n = length(buf)
    ntok = split("ZCL_COMMAND_READY_COMMAND( ZCL_COMMAND_PLANNED_COMMAND( ZCL_COMMAND_COMPAT_COMMAND( ZCL_COMMAND_DEV_COMMAND(", toks, " ")
    i = 1
    while (i <= n) {
        matched = 0
        for (t = 1; t <= ntok; t++) {
            L = length(toks[t])
            if (substr(buf, i, L) == toks[t]) { matched = t; break }
        }
        if (!matched) { i++; continue }
        j = i + length(toks[matched])
        depth = 1; in_str = 0; esc = 0; spec = ""
        while (j <= n && depth > 0) {
            c = substr(buf, j, 1)
            if (in_str) {
                if (esc) { esc = 0 }
                else if (c == "\\") { esc = 1 }
                else if (c == "\"") { in_str = 0 }
            } else {
                if (c == "\"") { in_str = 1 }
                else if (c == "(") { depth++ }
                else if (c == ")") { depth-- }
            }
            if (depth > 0) spec = spec c
            j++
        }
        path = ""
        if (match(spec, /"[^"]*"/)) path = substr(spec, RSTART + 1, RLENGTH - 2)
        owner = (spec ~ /ZCL_COMMAND_AUTH_OWNER/)
        mutate = (spec ~ /ZCL_COMMAND_EFFECT_MUTATE/ || spec ~ /ZCL_COMMAND_EFFECT_DESTRUCTIVE/)
        if (owner && mutate && path != "") print path
        i = j
    }
}'

def_count=0
leaves=""
if [[ -d "$DEFDIR" ]]; then
    shopt -s nullglob
    for f in "$DEFDIR"/*.def; do
        def_count=$((def_count + 1))
        leaves+="$(awk "$ENUM_AWK" "$f")"$'\n'
    done
    shopt -u nullglob
fi
leaves="$(printf '%s' "$leaves" | grep -v '^[[:space:]]*$' | sort -u || true)"

if [[ "$def_count" -eq 0 || -z "${leaves//[[:space:]]/}" ]]; then
    echo "check_privileged_transition_receipt: FATAL — no owner-mutating leaves enumerated from $DEFDIR/*.def (broken scan; refusing a hollow clean)." >&2
    exit 2
fi

# ── Load baseline dispositions ──
declare -A disp
if [[ -f "$BASELINE" ]]; then
    while read -r leaf rest || [[ -n "$leaf" ]]; do
        [[ -z "$leaf" || "$leaf" == \#* ]] && continue
        disp["$leaf"]="$rest"
    done < "$BASELINE"
fi

# ── (1) Every enumerated leaf must be dispositioned ──
violations=()
n_receipt=0
n_exempt=0
n_total=0
while IFS= read -r leaf; do
    [[ -z "$leaf" ]] && continue
    n_total=$((n_total + 1))
    d="${disp[$leaf]:-}"
    if [[ -z "$d" ]]; then
        violations+=("$leaf")
        continue
    fi
    case "$d" in
        receipt:*) n_receipt=$((n_receipt + 1)) ;;
        exempt:*)  n_exempt=$((n_exempt + 1)) ;;
        *) violations+=("$leaf (malformed disposition: '$d' — must start receipt: or exempt:)") ;;
    esac
done <<< "$leaves"

# ── (2) Every `receipt:<file>` consumer must still gate on the contract ──
receipt_lost=()
for leaf in "${!disp[@]}"; do
    d="${disp[$leaf]}"
    [[ "$d" == receipt:* ]] || continue
    spec="${d#receipt:}"
    file="${spec%%[[:space:]]*}"
    if [[ ! -f "$file" ]]; then
        receipt_lost+=("$leaf -> $file (file not found)")
        continue
    fi
    if ! grep -qE 'authority_receipt_[a-z_]*_available\(|consensus_state_replay_receipt_authority_available\(' "$file"; then
        receipt_lost+=("$leaf -> $file (no authority_receipt verify call)")
    fi
done

fail=0
if [[ "${#violations[@]}" -gt 0 ]]; then
    fail=1
    echo "check_privileged_transition_receipt: owner-mutating leaf/leaves with NO Law-7 disposition in $BASELINE:" >&2
    for v in "${violations[@]}"; do echo "  $v" >&2; done
    echo "" >&2
    echo "Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned. Add ONE line:" >&2
    echo "  <leaf.path>  receipt:<relative_handler_file>   # if it installs a privileged artifact — bind authority_receipt_header_* (or the replay-receipt verifier) over {artifact digest, context anchor, running binary}" >&2
    echo "  <leaf.path>  exempt:<one-line reason>          # if it is not an artifact-install transition" >&2
fi
if [[ "${#receipt_lost[@]}" -gt 0 ]]; then
    fail=1
    echo 'check_privileged_transition_receipt: a receipt: consumer no longer gates on an authority receipt:' >&2
    for v in "${receipt_lost[@]}"; do echo "  $v" >&2; done
    echo "  A wired privileged transition must keep calling authority_receipt_*_available( before mutating." >&2
fi
[[ "$fail" -ne 0 ]] && exit 1

echo "check_privileged_transition_receipt: clean — $n_total owner-mutating leaves, all dispositioned ($n_receipt receipt, $n_exempt exempt)"
exit 0
