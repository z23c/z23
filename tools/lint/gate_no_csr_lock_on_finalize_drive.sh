#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — LOCK-ORDER LAW: the post-finalize reducer DRIVE callgraph must
# never acquire csr->lock or run the chain-evidence DRAIN machinery.
#
# WHY (highest-severity never-stuck; prior live deadlock 873ba9955 / 2026-06-12)
# ------------------------------------------------------------------------------
# The reducer/ingest drive holds the coins_kv AUTHORITY mutex for the whole
# drive. The health/evidence DRAIN path takes csr->lock THEN coins_kv
# (csr_snapshot -> coins_kv_is_proven_authority). If anything ON the drive
# takes csr->lock (directly, or by calling a drain/record/snapshot/init helper
# that does), the two acquire orders invert — a classic ABBA cycle that is a
# LIVE TOTAL-NODE DEADLOCK at tip (net thread in record_finalized_tip wanting
# csr->lock; an RPC healthcheck holding csr->lock wanting coins_kv).
#
# The safe split is note+drain: the drive only NOTES the published tip via a
# LEAF mutex (chain_evidence_note_finalized_tip, engine/services/src/
# chain_evidence_live_advance.c:80, called from engine/jobs/src/
# tip_finalize_post_step.c:53). A SEPARATE thread DRAINS in the correct
# csr->lock-then-coins_kv order (node_health_service.c:476 ->
# chain_evidence_drain_pending_tip). This gate freezes that boundary.
#
# WHAT IS SCANNED (the drive callgraph ONLY — comments stripped)
# --------------------------------------------------------------
#   A) ALL of engine/jobs/src/tip_finalize_post_step.c — entirely the drive
#      post-finalize side-effect path.
#   B) ONLY the chain_evidence_note_finalized_tip() function body in
#      engine/services/src/chain_evidence_live_advance.c. The OTHER functions in
#      that file ARE the drain path and legitimately take csr->lock / call the
#      record + snapshot helpers — they must NOT be scanned, so we extract just
#      the note function (the single drive-side entry; its only caller is the
#      drive at tip_finalize_post_step.c:53).
#
# Comments are stripped first so the explanatory "csr->lock" mentions in those
# files (e.g. tip_finalize_post_step.c:47) do not false-trip the gate; only
# real code tokens count.
#
# FORBIDDEN TOKENS (any one = the ABBA edge)
# ------------------------------------------
#   csr->lock                                        direct acquire of the csr mutex
#   csr_snapshot                                     takes csr->lock
#   csr_align_coins_best_block                       writes under csr->lock
#   chain_evidence_drain_pending_tip                 the drain (csr->lock + node.db)
#   chain_evidence_controller_record_finalized_tip   the record (csr->lock + node.db)
#   chain_evidence_controller_snapshot               reads under csr->lock
#   chain_evidence_controller_init                   constructs the drain controller
#
# PASSES on the current tree by construction; FAILS the instant a drive-side
# function gains any of the above. Exit 0 = pass; non-zero + message = fail.
#
# If a NEW drive-side helper legitimately needs to be on this scan, add it to
# the SCAN set below — never silence the gate by weakening the token list.
set -euo pipefail

# Repo root: argv[1], or the dir this script is wired into, or CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" != "" ] && [ -d "$1/app" ]; then
    ROOT="$1"
elif [ -d "$SCRIPT_DIR/../../app" ]; then
    ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
cd "$ROOT" || { echo "gate_no_csr_lock_on_finalize_drive: bad root '$ROOT'" >&2; exit 2; }

DRIVE_FILE="engine/jobs/src/tip_finalize_post_step.c"
NOTE_FILE="engine/services/src/chain_evidence_live_advance.c"
NOTE_FN="chain_evidence_note_finalized_tip"

for f in "$DRIVE_FILE" "$NOTE_FILE"; do
    if [ ! -f "$f" ]; then
        echo "gate_no_csr_lock_on_finalize_drive: MISSING tracked file: $f" >&2
        echo "  A drive/note source moved or was renamed — update this gate deliberately" >&2
        echo "  (and re-verify the LOCK-ORDER LAW boundary)." >&2
        exit 1
    fi
done

# Confirm the note function still exists where we scope to it; a rename here
# would silently shrink scope B to nothing.
if ! grep -qE "^void[[:space:]]+${NOTE_FN}\(" "$NOTE_FILE"; then
    echo "gate_no_csr_lock_on_finalize_drive: could not find 'void ${NOTE_FN}(' in $NOTE_FILE" >&2
    echo "  The drive-side note entry was renamed — update NOTE_FN in this gate." >&2
    exit 1
fi

FORBIDDEN='csr->lock|csr_snapshot|csr_align_coins_best_block|chain_evidence_drain_pending_tip|chain_evidence_controller_record_finalized_tip|chain_evidence_controller_snapshot|chain_evidence_controller_init'

# Dependency-free comment strip: an awk state machine removes /* ... */ block
# comments (including multi-line), then sed removes // line comments. No gcc
# dependency; hermetic.
strip_comments() {
    awk '
    {
        line=$0; out=""
        while (length(line) > 0) {
            if (inblk) {
                p=index(line, "*/")
                if (p == 0) { line=""; break }
                line=substr(line, p+2); inblk=0
            } else {
                p=index(line, "/*")
                if (p == 0) { out=out line; line="" }
                else { out=out substr(line, 1, p-1); line=substr(line, p+2); inblk=1 }
            }
        }
        print out
    }' | sed 's://.*$::'
}

# Extract only the note function body (from its definition line through the
# first column-0 closing brace).
extract_note_fn() {
    # Match the definition line "void <NOTE_FN>(" — the open paren is written
    # as the character class [(] so the dynamic awk regex needs no backslash
    # escaping (a literal \( is a fatal "Unmatched (" in gawk/mawk).
    awk -v fn="^void[[:space:]]+${NOTE_FN}[(]" '
        $0 ~ fn { f=1 }
        f { print }
        f && /^}/ { exit }
    ' "$NOTE_FILE"
}

fail=0
hits=""

# Scope A: the whole drive file.
a_hits="$(strip_comments < "$DRIVE_FILE" | grep -nE "$FORBIDDEN" || true)"
if [ -n "$a_hits" ]; then
    fail=1
    while IFS= read -r h; do
        [ -z "$h" ] && continue
        hits="${hits}  ${DRIVE_FILE} (post-finalize drive): ${h}"$'\n'
    done <<< "$a_hits"
fi

# Scope B: the note function body only.
b_hits="$(extract_note_fn | strip_comments | grep -nE "$FORBIDDEN" || true)"
if [ -n "$b_hits" ]; then
    fail=1
    while IFS= read -r h; do
        [ -z "$h" ] && continue
        hits="${hits}  ${NOTE_FILE} (${NOTE_FN} body): ${h}"$'\n'
    done <<< "$b_hits"
fi

if [ "$fail" = "0" ]; then
    echo "gate_no_csr_lock_on_finalize_drive: OK — post-finalize drive takes no csr->lock and runs no drain machinery"
    exit 0
fi

echo ""
echo "gate_no_csr_lock_on_finalize_drive: FAIL — LOCK-ORDER LAW violated"
echo ""
echo "The post-finalize reducer DRIVE acquired csr->lock or ran the chain-evidence"
echo "DRAIN/record/snapshot machinery. The drive already holds the coins_kv"
echo "authority mutex; that path takes csr->lock THEN coins_kv — an inverted ABBA"
echo "acquire that is a LIVE TOTAL-NODE DEADLOCK at tip (prior wedge 873ba9955)."
echo ""
echo "Offending token(s):"
printf '%s' "$hits"
echo ""
echo "FIX: the drive must ONLY note the tip via the leaf-mutex slot"
echo "(chain_evidence_note_finalized_tip). The actual evidence record must run on"
echo "the health-collect DRAIN path (node_health_service.c -> "
echo "chain_evidence_drain_pending_tip), which owns the csr->lock-then-coins_kv"
echo "order. Do NOT call csr_snapshot / record_finalized_tip / drain / controller_"
echo "init / controller_snapshot / csr_align_coins_best_block from the drive."
exit 1
