#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_raw_sqlite.sh - ensure code outside vendored/test paths does not use
# raw sqlite3_step() outside the AR_* wrappers (activerecord.h), and does not
# issue raw node.db DML through sqlite3_exec().
#
# Scans app/, tools/, lib/, config/, and src/ for `sqlite3_step(` outside:
#   - vendor/
#   - any test/ directory
#   - the AR_STEP_ROW / AR_STEP_DONE / AR_STEP_ROW_READONLY macros themselves
#     (which textually contain `sqlite3_step` inside their #define bodies)
#   - lines annotated with `// raw-sql-ok:<tag>` (no space after the colon;
#     tag matches [A-Za-z][A-Za-z0-9_-]+)
#
# It also scans for direct sqlite3_exec(ndb->db|ndb.db, "INSERT/DELETE/UPDATE/
# REPLACE ...") because those are node.db write statements that can be prepared
# and stepped through ar_exec_write_sql()/AR_STEP_WRITE. Transaction control,
# PRAGMAs, ATTACH/DETACH, schema DDL, projection stores, the kernel store, and
# central checked helpers remain out of this narrow DML gate.
#
# Two distinct hatches, NOT the same thing:
#
#   1. Per-line `// raw-sql-ok:<tag>` markers. These are PRINCIPLED, not
#      debt. The load-bearing one is `progress-kv-kernel-store`: the
#      reducer pipeline writes its stage cursor + per-stage *_log tables
#      to consensus.db (historically progress.kv; the tag name is unchanged
#      across the flip) — a separate singleton WAL KERNEL store that sits
#      BELOW the AR/domain-model layer (a stage_cursor row is not a model;
#      see DEFENSIVE_CODING.md §1 "The one principled exception" and
#      engine/modules/storage/src/progress_store.c). Routing these through AR would be
#      a category error. The count here is bounded and stable-by-design —
#      it changes only when the reducer gains/drops a stage table, NOT a
#      migration that ratchets to zero. progress_store.c's own home-module
#      sites use the equivalent `kernel-primitive` tag.
#
#   2. The whole-file allowlist (raw_sqlite_allowlist.txt). THIS is the
#      ratchet — files grandfathered through the sqlite3_step →
#      AR_BEGIN_SAVE migration for node.db *models*. Entries come off as
#      each subsystem completes migration. It is currently empty; once it
#      stays empty the allowlist is removed and the lint's whole-file
#      escape becomes unconditional. The per-line kernel-store markers
#      above are unaffected by this — they are correct-by-design forever.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$ROOT/tools/lint/scan_exclusions.sh"
# shellcheck source=tools/lint/gate_lib.sh
source "$ROOT/tools/lint/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$ROOT/tools/lint/repo_shape.sh"

PRODUCTION_ROOTS=(core engine contexts cognition platform tools)
mapfile -t CONTEXT_ROOTS < <({ repo_shape_room_dirs controllers; repo_shape_room_dirs services; } | sort -u)

ALLOWLIST="$SCRIPT_DIR/raw_sqlite_allowlist.txt"

declare -A ALLOWED=()
gate_load_list_file "$ALLOWLIST" ALLOWED

# Fail-loud grep: a grep exit >=2 is a REAL ERROR (bad pattern, unreadable
# tree, non-GNU grep rejecting the syntax). The old form swallowed it with
# `2>/dev/null ... || true`, so the producer silently emptied and the gate
# passed "clean" exit 0 over zero scanned hits. Capture the first grep's
# exit explicitly: 0=hits, 1=no-hits (fine), >=2=fatal.
raw_scan=$(grep -rn 'sqlite3_step[[:space:]]*(' "${PRODUCTION_ROOTS[@]}" --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}")
grep_rc=$?
if [[ $grep_rc -ge 2 ]]; then
    echo "check_raw_sqlite: FATAL — grep exited $grep_rc scanning physical authorities." >&2
    echo "  This is a real error (bad pattern / unreadable tree / non-GNU grep)," >&2
    echo "  not 'no matches'. Refusing to pass hollow." >&2
    exit 2
fi
raw_hits=$(printf '%s\n' "$raw_scan" \
    | grep -v 'vendor/\|/test/\|AR_STEP_ROW\|AR_STEP_DONE\|AR_STEP_ROW_READONLY\|AR_STEP_WRITE\|safe_alloc\|".*sqlite3_step' \
    | grep -vE '// raw-sql-ok:[A-Za-z][A-Za-z0-9_-]+' \
    || true)

# Principled kernel-store hatch: kernel-store (consensus.db, historically
# progress.kv) stage cursor + *_log sites, correct-by-design below the AR
# layer. Bounded, NOT migration debt — we report the count for visibility,
# but it does not gate or ratchet.
kernel_store_total=$(grep -rn '// raw-sql-ok:progress-kv-kernel-store' \
    core engine contexts cognition platform --include='*.c' 2>/dev/null \
    | grep -v 'vendor/\|/test/' | wc -l | tr -d ' ')

violations=""
allowed_total=0
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"
    if [[ -n "${ALLOWED[$path]:-}" ]]; then
        allowed_total=$((allowed_total + 1))
        continue
    fi
    violations="${violations}${hit}"$'\n'
done <<< "$raw_hits"

exec_scan=$(
    find "${PRODUCTION_ROOTS[@]}" \
        \( -path '*/vendor/*' -o -path '*/build/*' -o -path '*/test/*' \) -prune \
        -o \( \( -name '*.c' -o -name '*.h' \) \
              "${LINT_FIND_PRUNE_ARGS[@]}" \) -type f -print |
    while IFS= read -r path; do
        [[ "$path" == "engine/models/include/models/activerecord.h" ]] && continue
        awk -v path="$path" '
            {
                lines[NR] = $0
            }
            END {
                call_re = "sqlite3_exec[[:space:]]*\\([[:space:]]*(&[[:space:]]*)?ndb(->|\\.)db[[:space:]]*,"
                for (i = 1; i <= NR; i++) {
                    if (lines[i] !~ /sqlite3_exec[[:space:]]*\(/)
                        continue
                    if (lines[i] ~ /\/\/[[:space:]]*raw-sql-ok:[A-Za-z][A-Za-z0-9_-]+/)
                        continue
                    chunk = lines[i]
                    for (j = i + 1; j <= NR && length(chunk) < 900; j++)
                        chunk = chunk "\n" lines[j]
                    if (chunk !~ call_re)
                        continue

                    tail = chunk
                    sub(".*" call_re, "", tail)
                    if (!match(tail, /"([^"\\]|\\.)*"/))
                        continue
                    sql = substr(tail, RSTART + 1, RLENGTH - 2)
                    sub(/^[[:space:]]+/, "", sql)
                    upper = toupper(sql)
                    gsub(/[[:space:]]+/, " ", upper)
                    if (upper ~ /^(INSERT|DELETE|UPDATE|REPLACE) /) {
                        split(upper, parts, " ")
                        printf "%s:%d: raw node.db sqlite3_exec %s; use ar_exec_write_sql()/AR_STEP_WRITE or a reviewed helper\n",
                               path, i, parts[1]
                    }
                }
            }
        ' "$path" || exit 2
    done
)
exec_scan_rc=$?
if [[ $exec_scan_rc -ge 2 ]]; then
    exit "$exec_scan_rc"
fi

if [[ -n "${exec_scan//[[:space:]]/}" ]]; then
    violations="${violations}${exec_scan}"$'\n'
fi

# Wallet projection tables are owned by their models. Controllers and
# Services may not reconstruct direct wallet-table DML; Controllers also may
# not invoke the destructive model APIs because the scan Service owns atomic
# replacement. Strip comments, then normalize case/whitespace/adjacent string
# literals so the rule judges the SQL consequence rather than one spelling.
context_files=$(find "${CONTEXT_ROOTS[@]}" -type f \
    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null)
context_find_rc=$?
if [[ $context_find_rc -ne 0 ]]; then
    echo "check_raw_sqlite: FATAL — wallet-owner source enumeration failed (find=$context_find_rc)" >&2
    exit 2
fi
context_count=$(awk 'NF { count++ } END { print count + 0 }' <<< "$context_files")
gate_require_scanned "$context_count" 2 "check_raw_sqlite.wallet_owner" \
    "expected controller and service C/header sources"

while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    normalized=$(awk -f tools/lint/strip_c_comments.awk "$path" | \
        LC_ALL=C tr '[:upper:]' '[:lower:]' | tr -d '"[:space:]')
    normalize_rc=$?
    if [[ $normalize_rc -ne 0 ]]; then
        echo "check_raw_sqlite: FATAL — wallet-owner normalization failed for $path" >&2
        exit 2
    fi
    for table in wallet_utxos wallet_transactions wallet_sapling_notes; do
        if [[ "$normalized" == *deletefrom"$table"* ||
              "$normalized" == *deletefrommain."$table"* ||
              "$normalized" == *"deletefrom[${table}]"* ||
              "$normalized" == *insertinto"$table"* ||
              "$normalized" == *insertor*into"$table"* ||
              "$normalized" == *replaceinto"$table"* ||
              "$normalized" == *update"$table"* ||
              "$normalized" == *updateor*"$table"* ]]; then
            violations="${violations}${path}: wallet projection DML for ${table}; call its model API"$'\n'
        fi
    done
    if [[ "$path" == */controllers/* ]] &&
       [[ "$normalized" == *db_wallet_utxo_delete_all* ||
          "$normalized" == *db_wallet_tx_delete_all* ||
          "$normalized" == *db_sapling_note_delete_all* ]]; then
        violations="${violations}${path}: Controller owns destructive wallet model call; delegate atomic replacement to the wallet scan Service"$'\n'
    fi
done <<< "$context_files"

if [[ -n "${violations//[[:space:]]/}" ]]; then
    echo "$violations"
    echo "FAIL: raw SQLite write primitive in production code"
    echo "  Use AR_STEP_ROW / AR_STEP_DONE / AR_STEP_ROW_READONLY (see"
    echo "  engine/models/include/models/activerecord.h), wrap in AR_BEGIN_SAVE /"
    echo "  AR_EXEC_BOOL, ar_exec_write_sql(), or — for unavoidable cases like schema bootstrap —"
    echo "  add a // raw-sql-ok:<tag> comment on the line (no space after the"
    echo "  colon). Kernel-store (consensus.db) sites use the canonical tag"
    echo "  // raw-sql-ok:progress-kv-kernel-store (see DEFENSIVE_CODING.md §1)."
    echo "  Allowlisted files (still pending sqlite3_step → AR migration) accounted for:"
    echo "    $allowed_total raw call sites across $(wc -l < <(grep -v '^[[:space:]]*#\|^[[:space:]]*$' "$ALLOWLIST" 2>/dev/null || true)) files"
    exit 1
fi

if (( allowed_total > 0 )); then
    file_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$ALLOWLIST" 2>/dev/null || echo 0)
    echo "check_raw_sqlite: clean outside allowlist"
    echo "  Allowlisted: $allowed_total raw call sites across $file_count files"
    echo "  (drives to zero as sqlite3_step → AR_BEGIN_SAVE migration lands)"
else
    echo "check_raw_sqlite: clean - no raw sqlite3_step in production code"
fi

# Surface the principled kernel-store hatch separately. This count is
# BOUNDED and stable-by-design (kernel-store stage cursor + *_log tables,
# below the AR layer) — it is not debt and does not gate.
echo "  Principled kernel-store sites (consensus.db, correct-by-design,"
echo "  below AR): $kernel_store_total // raw-sql-ok:progress-kv-kernel-store"
exit 0
