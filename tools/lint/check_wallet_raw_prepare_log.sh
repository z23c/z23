#!/usr/bin/env bash
# check_wallet_raw_prepare_log — RATCHET gate (shrink-only).
#
# Enforces "a raw sqlite3_prepare_v2() whose prepared-stmt NULL check returns
# WITHOUT logging is forbidden". This is the exact class fixed in
# contexts/wallet/models/src/wallet_tx.c (the null checks now LOG_FAIL/LOG_RETURN). The
# four check-silent-errors-* gates + check-silent-errors-bool do not see it:
# the failure here is a `if (!s) return 0;` after a BARE prepare, not the
# `if (!call(...)) return false;` shape those gates key on.
#
# DETECTED: a BARE prepare line (sqlite3_prepare_v2( that is NOT inside an
# `if (...)` condition) followed within ~12 lines by a simple null check
#     if (!stmt)
#         return ...;       // no LOG_* between the prepare and this return
# COMPLIANT: any of LOG_FAIL/LOG_ERR/LOG_NULL/LOG_RETURN/LOG_WARN appearing
# between the prepare and that return — e.g. `if (!s) LOG_FAIL(...)` or
# `if (!s) LOG_RETURN(0, ...)`.
#
# The `if (sqlite3_prepare_v2(...) != SQLITE_OK)` idiom (prepare INSIDE the
# condition) is a different class and is intentionally NOT scanned here — it
# has no separate `if (!stmt)` guard.
#
# RATCHET: today's population is grandfathered in the baseline; the gate fails
# only when a NEW (previously-unseen) site appears. Debt can only shrink.
# Stable key = "<relpath>::<enclosing_function>" so editing lines above a hit
# does not churn the baseline (unlike a file:line key). Mirrors the key scheme
# of check_silent_bool_errors.sh.
#
# Known limitation (accepted for a ratchet): two silent prepares in the SAME
# function of the SAME file collapse to one key.
#
# Excluded from scanning: tools/lint/ itself, and the AR_* macro-definition
# header engine/models/include/models/activerecord.h (a header, so not in the
# *.c set anyway) — callers that route a prepare through the AR_PREPARE_*/
# AR_QUERY_* macros carry no raw `sqlite3_prepare_v2(` token and are compliant
# by construction.
#
# Usage:
#   ./tools/lint/check_wallet_raw_prepare_log.sh            # FAIL mode (CI/lint)
#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_wallet_raw_prepare_log.sh  # regen/shrink baseline
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
BASELINE="tools/lint/wallet_raw_prepare_log_baseline.txt"
MODE="${ZCL_LINT_MODE:-FAIL}"

scan() {
  local files
  files=$(grep -rl 'sqlite3_prepare_v2(' app lib --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
            | grep -vE '^tools/lint/' || true)
  [ -n "$files" ] || return 0
  # shellcheck disable=SC2086
  awk '
    FNR==1 { curfunc=""; prep=0; gp=0; since=0; gsince=0; logseen=0 }
    {
      # enclosing-function detection: a column-0 definition header
      # ("<type> name(") that does not end in ; (which would be a prototype).
      if ($0 ~ /^[A-Za-z_]/ && index($0,"(")>0 && $0 !~ /;[ \t]*$/) {
        head=$0; sub(/\(.*/,"",head); gsub(/[ \t]+$/,"",head)
        n=split(head,parts,/[ \t\*]+/)
        if (n>=2 && parts[n] ~ /^[A-Za-z_][A-Za-z0-9_]*$/) curfunc=parts[n]
      }

      if (prep==1) {
        since++
        if (since>12) { prep=0; gp=0 }
        else {
          if ($0 ~ /LOG_(FAIL|ERR|NULL|RETURN|WARN)/) logseen=1
          hasret = ($0 ~ /return[ \t;(]/)
          if (gp==1) {                 # guard found earlier; body on a later line
            gsince++
            if (hasret)        { if (logseen==0) print pfile "::" pfunc; prep=0; gp=0 }
            else if (gsince>4) { prep=0; gp=0 }
          } else if ($0 ~ /if \( *! *[A-Za-z_][A-Za-z0-9_]* *\)/) {
            if (hasret)                                      { if (logseen==0) print pfile "::" pfunc; prep=0 }
            else if ($0 ~ /LOG_(FAIL|ERR|NULL|RETURN|WARN)/) { prep=0 }
            else                                             { gp=1; gsince=0 }
          }
        }
      }

      # open a window only for a BARE prepare (not inside an if-condition)
      if ($0 ~ /sqlite3_prepare_v2\(/ && $0 !~ /(^|[^A-Za-z0-9_])if[ \t]*\(/) {
        prep=1; since=0; logseen=0; gp=0; pfunc=curfunc; pfile=FILENAME
      }
    }
  ' $files | sort -u
}

CUR=$(scan)

if [ "$MODE" = "UPDATE" ]; then
  {
    echo "# check_wallet_raw_prepare_log RATCHET baseline (shrink-only)."
    echo "# Stable key = <relpath>::<enclosing_function>. A swallowed prepare:"
    echo "#   sqlite3_prepare_v2(...); if (!stmt) return ...;   with no LOG_*."
    echo "# Regenerate after fixing some: ZCL_LINT_MODE=UPDATE ./tools/lint/check_wallet_raw_prepare_log.sh"
    printf '%s\n' "$CUR"
  } > "$BASELINE"
  echo "check_wallet_raw_prepare_log: baseline updated ($(printf '%s' "$CUR" | grep -c '::' || true) entries)"
  exit 0
fi

BASE=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$BASELINE" 2>/dev/null | sort -u || true)
NEW=$(comm -23 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -E '::' || true)
if [ -n "$NEW" ]; then
  echo "FAIL: new raw sqlite3_prepare_v2() with an unlogged NULL-check return."
  echo "      Log the failure via LOG_FAIL/LOG_RETURN/LOG_ERR/LOG_NULL/LOG_WARN"
  echo "      between the prepare and the 'if (!stmt)' return, or route the"
  echo "      prepare through the AR_* lifecycle macros (activerecord.h):"
  printf '%s\n' "$NEW"
  exit 1
fi

n_cur=$(printf '%s' "$CUR" | grep -c '::' || true)
n_base=$(printf '%s' "$BASE" | grep -c '::' || true)
GONE=$(comm -13 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -c '::' || true)
echo "  OK: no new unlogged raw-prepare NULL-check ($n_cur tracked; baseline $n_base)"
if [ "${GONE:-0}" -gt 0 ]; then
  echo "  (ratchet: $GONE fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)"
fi
exit 0
