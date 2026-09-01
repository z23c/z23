#!/usr/bin/env bash
# Gate #23 — universal thread supervision (RATCHET).
#
# Every long-running background thread the node spawns must be ACCOUNTED FOR:
# either it is on the supervisor liveness tree (so a wedged loop becomes a
# named blocker, not a silent stop — the 2026-05-21 8.6 h sweeper wedge that
# motivated Round 5), or it is a documented exemption in the baseline.
#
# Seam: the canonical long-running spawn wrapper `thread_registry_spawn(`
# (raw pthread_create is separately gated by the Makefile `check-pthread-create`
# target, which forces the wrapper or a `// raw-pthread-ok` marker; those are
# short-burst/joined workers, out of scope here). This gate scans every
# thread_registry_spawn call site under the production roots and requires each
# to be one of:
#
#   (a) SUPERVISED — its translation unit registers a liveness contract
#       (`supervisor_register(`, `supervisor_register_in_domain(`, or the
#       platform/modules/util adapter `thread_liveness_register(`), OR the spawn call line
#       (or the line above) carries a `// supervised:<child>` marker.
#   (b) MARKED-EXEMPT — the spawn call line (or the line above) carries a
#       `// thread-supervision-ok:<reason>` marker (a bounded/joined worker
#       pool, a one-shot job, etc.).
#   (c) BASELINED — the thread's name literal appears in the baseline file
#       with a disposition + one-line justification.
#
# Anything else is a NEW unaccounted long-running thread → FAIL.
#
# Ratchet: the baseline may only SHRINK. A baseline entry whose thread no
# longer spawns as an uncovered site (renamed, removed, or since supervised)
# is a STALE entry → FAIL, which forces the list down as threads gain
# contracts. A thread that is both covered AND baselined → FAIL (remove the
# now-redundant baseline line).
#
# To clean up debt: pick a baselined thread, give it a liveness contract via
# util/thread_liveness.h (see engine/modules/health/src/heartbeat.c for the exemplar),
# delete its baseline line, re-run `make lint`.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
. tools/lint/scan_exclusions.sh

# Scan roots + baseline are overridable so the lint-gate self-test can point
# the gate at a planted fixture dir / empty baseline (and prove the
# non-empty-scan floor + trip/pass behavior) without touching the live tree.
THREADSUP_ROOTS_DEFAULT="core engine contexts cognition platform"
read -r -a ROOTS <<< "${ZCL_THREADSUP_SCAN_ROOTS:-$THREADSUP_ROOTS_DEFAULT}"

# ── --selftest: the coverage check, exercised on every `make lint` ──────────
# Three answers, not two. Each case re-invokes this gate for real with
# ZCL_THREADSUP_COVERAGE_ONLY=1, so it stops the moment the coverage verdict is
# in and the umbrella never pays for a second full per-file grep pass (the
# real, complete run follows immediately in the same `--selftest && <gate>`
# command).
if [ "${1:-}" = "--selftest" ]; then
    self="$PWD/tools/lint/check_thread_supervision.sh"
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL env assignments
        local want="$1" msg="$2" rc=0
        shift 2
        env "$@" "$self" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "check_thread_supervision: SELFTEST FAILED — $msg (wanted exit $want, got $rc)" >&2
            exit 2
        fi
    }
    # (1) the full, real scan clears its own expectation.
    cov_case 0 "the complete scan did not pass its coverage expectation" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_THREADSUP_COVERAGE_ONLY=1
    # (2) a scan set deliberately reduced below the expectation (the config/
    #     root dropped) is UNPROVEN exit 2 — never 0, never 1. The old floor of
    #     1 could not see this: ~1900 files still cleared it.
    cov_case 2 "a scan missing a whole declared root was not UNPROVEN" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_THREADSUP_COVERAGE_ONLY=1 \
        ZCL_THREADSUP_SCAN_ROOTS="app lib"
    # (3) a shortfall SMALLER than the recorded allowance is a stale ratchet,
    #     exit 1 — an allowance that may only ever rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_THREADSUP_COVERAGE_ONLY=1 \
        ZCL_THREADSUP_COVERAGE_ALLOWANCE=1
    echo "[check_thread_supervision] SELFTEST PASS (a full scan passes coverage," \
         "a scan short one declared root is UNPROVEN exit 2, and an allowance" \
         "above the true shortfall is a stale-ratchet exit 1)"
    exit 0
fi

BASELINE="${ZCL_THREADSUP_BASELINE:-tools/lint/thread_supervision_baseline.txt}"
[ -f "$BASELINE" ] || touch "$BASELINE"

MARKER_RE='//[[:space:]]*(supervised|thread-supervision-ok):'
COVER_RE='supervisor_register[[:space:]]*\(|supervisor_register_in_domain[[:space:]]*\(|thread_liveness_register[[:space:]]*\('
SPAWN_RE='thread_registry_spawn[[:space:]]*\('

# Production .c surface. Exclude the test/fuzz/vendor trees, the two seam
# files (the registry itself and the supervisor itself — the supervisor thread
# is the root and cannot supervise itself), and — when running as a
# production scan (ZCL_LINT_PRODUCTION_SCAN=1, see scan_exclusions.sh) — the
# shared `_*fixture*.c` transient-fixture glob (the self-test plants
# `_*probe_tmp.c` instead, which stays visible in every mode).
mapfile -t files < <(find "${ROOTS[@]}" -type f -name '*.c' 2>/dev/null \
    | grep -v '/test/' \
    | grep -v -i 'fuzz' \
    | grep -v '/vendor/' \
    | grep -v 'platform/modules/util/src/thread_registry.c' \
    | grep -v 'platform/modules/util/src/supervisor.c' \
    | lint_filter_excluded \
    | sort)
gate_require_scanned "${#files[@]}" 1 check_thread_supervision \
    "no *.c under: ${ROOTS[*]} — was a production dir renamed/moved?"

# ── Coverage: did the scan reach everything it claims to cover? ─────────────
# The floor above answers "did the scan produce anything at all" — and it was
# set to 1, i.e. this gate reported clean off a single file. Measured
# 2026-08-30 the realized scan is 1929 .c files, so the floor was 0.05% of the
# surface: a scan that silently lost 1928 of 1929 files still passed, and this
# gate's whole subject is a per-file grep — dropping a file drops its spawn
# sites entirely while the file COUNT stays large. This asks the right
# question: did the scan reach every file an INDEPENDENT oracle — the git
# index, which knows nothing about the find/grep pipeline above, so the two
# cannot fail together — says it should have?
#
# Derived from THREADSUP_ROOTS_DEFAULT, never from the (overridable) ROOTS
# actually in use, so pointing this gate at a subset reads as a shortfall
# rather than as a quiet redefinition of what "covered" means.
#
# Scope, unchanged: the expectation carries the SAME declared exclusions the
# find pipeline applies — */test/*, anything named *fuzz* (case-insensitively,
# matching the `grep -v -i fuzz`), */vendor/*, and the two seam files
# (thread_registry.c, supervisor.c — the supervisor thread is the root and
# cannot supervise itself). A coverage check that fired on files this gate
# deliberately never reads would only teach people to ignore it.
#
# Allowance 0, shrink-only: measured expected 1929, scanned 1929, missing 0.
THREADSUP_COVERAGE_ALLOWANCE="${ZCL_THREADSUP_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_THREADSUP_COVERAGE:-1}" = "1" ]; then
    threadsup_cov_specs=()
    for threadsup_cov_root in $THREADSUP_ROOTS_DEFAULT; do
        threadsup_cov_specs+=("$threadsup_cov_root/*.c")
    done
    # Per-root non-emptiness. KNOWN LIMIT of any git-oracle coverage check
    # over hardcoded roots: the oracle is independent of the gate's FIND, not
    # of its ROOT LIST. A renamed root empties the find and the pathspec
    # together, so the shortfall cancels out and reads as clean. Ask git
    # directly, root by root, and refuse to grade if one has gone silent.
    for threadsup_cov_root in $THREADSUP_ROOTS_DEFAULT; do
        if [ -z "$(git ls-files --cached -- "$threadsup_cov_root/*.c" 2>/dev/null || true)" ]; then
            echo "check_thread_supervision: UNPROVEN — declared scan root" >&2
            echo "  '$threadsup_cov_root' tracks no *.c at all. A renamed/emptied" >&2
            echo "  root removes its surface from BOTH the find and the" >&2
            echo "  expectation, so the shortfall cancels and reads clean." >&2
            echo "  Refusing to grade. Fix THREADSUP_ROOTS_DEFAULT, or drop the" >&2
            echo "  root if the code is genuinely gone." >&2
            exit 2
        fi
    done
    threadsup_cov_specs+=(
        ':(exclude)*/test/*'
        ':(exclude,icase)*fuzz*'
        ':(exclude)*/vendor/*'
        ':(exclude)platform/modules/util/src/thread_registry.c'
        ':(exclude)platform/modules/util/src/supervisor.c'
    )
    gate_require_git_coverage - "$THREADSUP_COVERAGE_ALLOWANCE" check_thread_supervision \
        ZCL_THREADSUP_COVERAGE_ALLOWANCE \
        "Re-run from a clean checkout. If a listed file genuinely left this gate's scope, move it out of $THREADSUP_ROOTS_DEFAULT or add its exclusion to BOTH the find pipeline and the pathspec list above — raising ZCL_THREADSUP_COVERAGE_ALLOWANCE is a last resort and needs the reason written down." \
        -- "${threadsup_cov_specs[@]}" < <(printf '%s\n' "${files[@]}")
fi
if [ "${ZCL_THREADSUP_COVERAGE_ONLY:-0}" = "1" ]; then
    echo "check_thread_supervision: coverage-only PASS (${#files[@]} files reached)"
    exit 0
fi

# Load baseline: "name  disposition  justification…". First token = thread name.
declare -A baseline
baseline_count=0
while read -r name _rest; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    baseline["$name"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# Emit one TAB record per spawn site: file<TAB>line<TAB>covered<TAB>marked<TAB>name
records=$(
    for f in "${files[@]}"; do
        cov=0
        if grep -qE "$COVER_RE" "$f"; then cov=1; fi
        while IFS=: read -r n line; do
            marked=0
            if printf '%s\n' "$line" | grep -qE "$MARKER_RE"; then
                marked=1
            else
                prev=$((n - 1))
                if [ "$prev" -gt 0 ] && \
                   grep -qE "$MARKER_RE" <<<"$(sed -n "${prev}p" "$f")"; then
                    marked=1
                fi
            fi
            name=$(printf '%s\n' "$line" | \
                sed -n 's/.*thread_registry_spawn[[:space:]]*([[:space:]]*"\([^"]*\)".*/\1/p')
            printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$n" "$cov" "$marked" "$name"
        done < <(grep -nE "$SPAWN_RE" "$f")
    done
)

fail=0
new_violations=()
redundant_baseline=()
declare -A baseline_hit
declare -A baseline_appeared

if [ -n "$records" ]; then
    while IFS=$'\t' read -r f n cov marked name; do
        [ -z "$f" ] && continue
        if [ -n "$name" ] && [ -n "${baseline[$name]+x}" ]; then
            baseline_appeared[$name]=1
        fi
        if [ "$cov" = 1 ] || [ "$marked" = 1 ]; then
            # Supervised or explicitly marked-exempt. If ALSO baselined, the
            # baseline line is now redundant and must be removed (shrink).
            if [ -n "$name" ] && [ -n "${baseline[$name]+x}" ]; then
                redundant_baseline+=("$name ($f:$n is now covered)")
                fail=1
            fi
            continue
        fi
        if [ -n "$name" ] && [ -n "${baseline[$name]+x}" ]; then
            baseline_hit[$name]=1
            continue
        fi
        new_violations+=("$f:$n  thread='${name:-<dynamic-name>}'")
        fail=1
    done <<< "$records"
fi

# Stale baseline entries: listed but never seen as an uncovered spawn.
stale_baseline=()
for name in "${!baseline[@]}"; do
    [ -n "${baseline_hit[$name]+x}" ] && continue
    [ -n "${baseline_appeared[$name]+x}" ] && continue  # flagged as redundant
    stale_baseline+=("$name")
    fail=1
done

if [ "$fail" = "0" ]; then
    echo "check_thread_supervision: clean — ${baseline_count} baselined exemption(s), no new unaccounted threads"
    exit 0
fi

echo ""
echo "check_thread_supervision: FAIL"
if [ "${#new_violations[@]}" -gt 0 ]; then
    echo ""
    echo "  NEW unaccounted long-running thread(s) (${#new_violations[@]}):"
    for v in "${new_violations[@]}"; do echo "    $v"; done
    echo ""
    echo "  Fix (preferred → fallback):"
    echo "    1. Supervise it: register a liveness contract via"
    echo "       util/thread_liveness.h (exemplar: engine/modules/health/src/heartbeat.c),"
    echo "       or add '// supervised:<child>' at the spawn site."
    echo "    2. If short-lived/joined/one-shot: add"
    echo "       '// thread-supervision-ok:<reason>' at the spawn site."
    echo "    3. Last resort: add '<name>  <disposition>  <why>' to $BASELINE."
fi
if [ "${#redundant_baseline[@]}" -gt 0 ]; then
    echo ""
    echo "  REDUNDANT baseline entries (thread is now covered — remove them):"
    for v in "${redundant_baseline[@]}"; do echo "    $v"; done
fi
if [ "${#stale_baseline[@]}" -gt 0 ]; then
    echo ""
    echo "  STALE baseline entries (no matching uncovered spawn — remove them):"
    for v in "${stale_baseline[@]}"; do echo "    $v"; done
fi
echo ""
exit 1
