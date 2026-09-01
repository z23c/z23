#!/usr/bin/env bash
# check_result_discard — RATCHET gate (shrink-only).
#
# struct zcl_result is [[nodiscard]] (platform/modules/util/include/util/result.h). That
# attribute catches the BARE statement discard —
#
#     do_thing(...);              // warning, and -Werror makes it fatal
#
# — but C23 lets a void cast suppress it, and the older GNU
# __attribute__((warn_unused_result)) behaviour (where a cast does NOT
# suppress) does not apply to the C23 spelling. So this compiles silently:
#
#     (void)do_thing(...);        // no diagnostic, no reason, no paper trail
#
# The compiler therefore fences off NEW bare discards but says nothing about
# the population of explicit cast discards already in the tree. This gate
# covers exactly that gap: it counts every `(void)<fn>(...)` discard of a
# zcl_result-returning function and refuses to let the count grow.
#
# THE FIX for a flagged line is to say WHY the failure is safe to drop:
#
#     ZCL_IGNORE_RESULT(do_thing(...), "best-effort; refold re-derives it");
#
# ZCL_IGNORE_RESULT (result.h) compile-enforces a non-empty reason and does
# not match this gate's pattern, so converting a discard shrinks the debt.
# Where the discard sits inside a larger expression and the macro cannot be
# used, mark the line `// result-discard-ok:<reason>`.
#
# Adding a plain `(void)` cast to silence a NEW bare discard is exactly the
# regression this gate exists to catch — it will fail the build.
#
# RATCHET: today's population is grandfathered in the baseline; the gate
# fails only when a NEW (previously-unseen) cast discard appears. Debt can
# only shrink.
#
# Stable key = "<relpath>::<discarded_fn>" — same scheme as
# check_silent_bool_errors.sh — so editing lines above a hit does not churn
# the baseline (unlike a file:line key).
#
# Known limitation (documented, accepted for a ratchet): two cast discards of
# the SAME function in the SAME file collapse to one key, so re-introducing a
# discard of an already-listed function in that file is not caught. New
# DISTINCT discards — the common regression — are caught.
#
# Usage:
#   ./tools/lint/check_result_discard.sh              # FAIL mode (CI/lint)
#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_result_discard.sh   # shrink/regen
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/lint/scan_exclusions.sh
source "$SCRIPT_DIR/scan_exclusions.sh"
BASELINE="tools/lint/result_discard_baseline.txt"
DIRS="${ZCL_RESULT_DISCARD_SCAN_DIRS_FOR_TEST:-app config core lib domain application adapters ports tools}"
MODE="${ZCL_LINT_MODE:-FAIL}"

# Every function whose return type is `struct zcl_result`. Derived from the
# tree on each run, so a newly-added fallible function is covered with no
# edit here.
result_fns() {
  for d in $DIRS; do
    [ -d "$d" ] || continue
    grep -rhoE 'struct zcl_result[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(' \
      "$d" --include='*.c' --include='*.h' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null
  done | sed -E 's/^struct zcl_result[[:space:]]+//; s/[[:space:]]*\($//' | sort -u
}

scan() {
  local alt
  alt=$(result_fns | paste -sd'|')
  [ -n "$alt" ] || return 0
  for d in $DIRS; do
    [ -d "$d" ] || continue
    grep -rnE "\(void\)[[:space:]]*($alt)[[:space:]]*\(" \
      "$d" --include='*.c' "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
      | grep -vE '(//|/\*)[[:space:]]*result-discard-ok:'
  done | while IFS= read -r hit; do
      file=${hit%%:*}
      text=${hit#*:}; text=${text#*:}
      fn=$(printf '%s' "$text" \
        | grep -oE "\(void\)[[:space:]]*($alt)[[:space:]]*\(" \
        | grep -oE "($alt)" | head -1)
      [ -n "$fn" ] || continue
      printf '%s::%s\n' "${file#./}" "$fn"
    done | sort -u
}

CUR=$(scan)

if [ "$MODE" = "UPDATE" ]; then
  {
    echo "# check_result_discard RATCHET baseline (shrink-only)."
    echo "# Stable key = <relpath>::<discarded_fn>. A cast discard of a"
    echo "# [[nodiscard]] struct zcl_result:  (void)fn(...);  with no reason."
    echo "# Fix one by stating the reason:"
    echo "#   ZCL_IGNORE_RESULT(fn(...), \"why the failure is safe to drop\");"
    echo "# Regenerate after fixing some:"
    echo "#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_result_discard.sh"
    printf '%s\n' "$CUR"
  } > "$BASELINE"
  echo "check_result_discard: baseline updated ($(printf '%s' "$CUR" | grep -c '::') entries)"
  exit 0
fi

BASE=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$BASELINE" 2>/dev/null | sort -u)
NEW=$(comm -23 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -E '::' || true)
if [ -n "$NEW" ]; then
  echo "FAIL: new (void)-cast discard of a [[nodiscard]] struct zcl_result."
  echo "State why the failure is safe to drop:"
  echo "  ZCL_IGNORE_RESULT(<call>, \"<reason>\");   (util/result.h)"
  echo "or mark the line // result-discard-ok:<reason> if the macro cannot be used:"
  printf '%s\n' "$NEW"
  exit 1
fi

n_cur=$(printf '%s' "$CUR" | grep -c '::')
n_base=$(printf '%s' "$BASE" | grep -c '::')
GONE=$(comm -13 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BASE") | grep -c '::' || true)
echo "  OK: no new zcl_result cast discard ($n_cur tracked; baseline $n_base)"
[ "${GONE:-0}" -gt 0 ] && echo "  (ratchet: $GONE fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)"
exit 0
