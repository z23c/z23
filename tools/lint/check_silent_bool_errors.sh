#!/usr/bin/env bash
# check_silent_bool_errors — RATCHET gate (shrink-only).
#
# The check-silent-errors-{,services,controllers,jobs,conditions} gates enforce
# "every error return logs context" — but only for the int/`return -1;` error
# convention. The bool/`return false;` error idiom slips through. This gate
# closes that blind spot for the highest-signal form: a SWALLOWED CALL FAILURE —
#
#     if (!some_call(...))
#         return false;          // no LOG_*, no // raw-return-ok: marker
#
# where a fallible call's failure is propagated as a bare `false` with no
# diagnostic context. (Plain predicate returns — `if (!ok) return false;` on a
# local bool — are NOT flagged; they are legitimate negative results, and
# gating them would be noise.)
#
# RATCHET: today's population is grandfathered in the baseline; the gate fails
# only when a NEW (previously-unseen) swallowed call-failure appears. Debt can
# only shrink. Stable key = "<relpath>::<guarded_call_name>" so editing lines
# above a hit does not churn the baseline (unlike a file:line key).
#
# Known limitation (documented, accepted for a ratchet): two silent guards of
# the SAME call in the SAME file collapse to one key, so re-introducing a guard
# of an already-listed call in that file is not caught. New DISTINCT swallowed
# calls — the common regression — are caught.
#
# Escape hatch: `// raw-return-ok:<reason>` (or `/* raw-return-ok:<reason> */`)
# on the guard line or the return line, same as the int-convention gates.
#
# Usage:
#   ./tools/lint/check_silent_bool_errors.sh              # FAIL mode (CI/lint)
#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_silent_bool_errors.sh   # shrink/regen baseline
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/lint/scan_exclusions.sh
source "$SCRIPT_DIR/scan_exclusions.sh"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"
BASELINE="tools/lint/silent_bool_errors_baseline.txt"
# The default scan set is every app shape, DERIVED from the Makefile's APP_DIRS
# by repo_shape.sh. Spelled out by hand it was a taxonomy copy that would have
# silently skipped an eighth shape's whole directory.
DIRS="${ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST:-$(repo_shape_dirs app src | tr '\n' ' ')}"
MODE="${ZCL_LINT_MODE:-FAIL}"

scan() {
  # One awk pass per scanned directory replaces a `while read` body that
  # forked cut/sed/grep/head/tr/printf/grep -q PER HIT (~3,900 hits x ~7
  # forks = ~27,000 forks on this tree). The grep pipeline above (one `grep
  # -r` + two filter greps per directory) is unchanged — only the per-hit
  # lookback into the previous line moves from per-hit shell forks into one
  # awk process that loads each hit file once and indexes it by line
  # number. Same stable key: "<relpath>::<guarded_call_name>".
  for d in $DIRS; do
    [ -d "$d" ] || continue
    grep -rn 'return false;' "$d" --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
      | grep -vE 'LOG_ERR|LOG_FAIL|LOG_RETURN|LOG_WARN|LOG_NULL|log_json' \
      | grep -vE '(//|/\*) raw-return-ok:' \
      | awk -F: '
          {
            file = $1; lnum = $2 + 0
            if (!(file in loaded)) {
              n = 0
              while ((getline line < file) > 0) { n++; linearr[file SUBSEP n] = line }
              close(file)
              loaded[file] = 1
            }
            prevln = lnum - 1
            if (prevln < 1) next
            pl = linearr[file SUBSEP prevln]
            if (pl == "") next
            # prev line must not itself log or be marked
            if (pl ~ /LOG_|log_json|raw-return-ok:/) next
            # A fallible call-guard on the previous line: if (!ident(  ...
            if (!match(pl, /if \(![A-Za-z_][A-Za-z0-9_]*\(/)) next
            call = substr(pl, RSTART, RLENGTH)
            sub(/^if \(!/, "", call)
            sub(/\($/, "", call)
            rel = file
            sub(/^\.\//, "", rel)
            print rel "::" call
          }
        '
  done | sort -u
}

CUR=$(scan)

if [ "$MODE" = "UPDATE" ]; then
  {
    echo "# check_silent_bool_errors RATCHET baseline (shrink-only)."
    echo "# Stable key = <relpath>::<guarded_call>. A swallowed call failure:"
    echo "#   if (!call(...)) return false;   with no LOG_* and no // raw-return-ok:"
    echo "# Regenerate after fixing some: ZCL_LINT_MODE=UPDATE ./tools/lint/check_silent_bool_errors.sh"
    printf '%s\n' "$CUR"
  } > "$BASELINE"
  echo "check_silent_bool_errors: baseline updated ($(printf '%s' "$CUR" | grep -c '::') entries)"
  exit 0
fi

BASE=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$BASELINE" 2>/dev/null | sort -u)
NEW=$(comm -23 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -E '::' || true)
if [ -n "$NEW" ]; then
  echo "FAIL: new silent call-guard 'return false' (log the failure via LOG_WARN/LOG_FAIL, or mark // raw-return-ok:<reason>):"
  printf '%s\n' "$NEW"
  exit 1
fi

n_cur=$(printf '%s' "$CUR" | grep -c '::')
n_base=$(printf '%s' "$BASE" | grep -c '::')
GONE=$(comm -13 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -c '::' || true)
echo "  OK: no new silent call-guard return-false ($n_cur tracked; baseline $n_base)"
[ "${GONE:-0}" -gt 0 ] && echo "  (ratchet: $GONE fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)"
exit 0
