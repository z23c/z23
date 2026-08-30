#!/usr/bin/env bash
# Lint gate #15 — supervisor registration for long-running services.
#
# Goal: every long-running service in the scanned roots (below) either
# registers a liveness contract with the supervisor (Round 5 —
# lib/util/supervisor.h), or appears in this gate's baseline file of
# grandfathered exceptions.
#
# Why: on 2026-05-21 the node ran for 8.6 h with `watchdog.checks_run`
# stuck at 0 because the lib/health sweeper wedged. The supervisor
# primitive (Round 5 C1) provides an independent time-driven driver,
# but only for services that opt in via supervisor_register_in_domain().
# gate is the ratchet that drives opt-in: new long-running services
# cannot land without a contract; baseline shrinks over Rounds 6-8.
#
# Scope (2026-07-21 widen — Task D/E supervision-coverage): originally
# hardcoded to app/services/src/*.c only, which left every supervision hole
# in app/controllers, app/conditions, app/jobs, config/src, and the
# production lib/ daemons (net/health/rpc) invisible to `make lint` — a
# background daemon loop is a long-running service whatever directory it
# lives in, and must be visible to `z23 dumpstate supervisor` so a
# wedged loop is not silent. Each root is scanned non-recursively
# (`-maxdepth 1`, the `*/src` leaf convention); widening further just means
# adding another root below.
#
# A file is "long-running" if it contains either:
#   - thread_registry_spawn      (the project's long-running wrapper)
#   - health_register_periodic(  (lib/health sweeper subscriber)
#   - pthread_create(            (raw thread spawn) — EXCEPT when the
#     only such call is a short-burst worker carrying a `raw-pthread-ok`
#     marker (on the call line or the line above). Those are joined
#     within the spawning function, have bounded lifetime, and need no
#     liveness contract — mirrors the check-pthread-create Makefile gate.
#
# Such a file must contain ≥1 call to a recognized registration site —
# `supervisor_register(_in_domain)?(`, the lib/util/thread_liveness.h
# adapters `thread_liveness_register(` /
# `thread_liveness_register_restartable(`, or the config/src boot-worker
# wrapper `boot_register_worker_supervisor(` (which itself calls
# supervisor_register_in_domain — see boot_worker_supervisor.c) — OR an
# entry in `tools/scripts/supervisor_baseline.txt`, OR a per-file override
# marker `// supervisor-ok:<tag>` on a line in the file.
#
# The `_restartable` variant is a recognized registration site because it
# IS one: thread_liveness_register_restartable() calls
# thread_liveness_register() (lib/util/src/thread_liveness.c) and then adds
# the bounded-restart wiring on top, so the child lands on the root liveness
# tree exactly like the plain form. Before this was spelled out the anchored
# `thread_liveness_register\(` alternative missed it, and two genuinely
# supervised daemons — lib/health/src/heartbeat.c (zcl_health_sweep) and
# lib/rpc/src/rpc_timeout.c (zcl_rpc_timeout) — were carried as baseline
# debt they had already paid off.
#
# To clean up debt: pick a baseline entry, register a liveness
# contract for that service (mirror what sync_watchdog_service.c
# does), delete the baseline line, re-run `make lint`.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

# Scan roots are overridable via ZCL_SERVICES_DIR (space-separated) so the
# lint-gate self-test can point the gate at an EMPTY dir and prove the
# non-empty-floor preflight fires (exit 2) instead of the `for f in glob`
# silently iterating the literal unmatched pattern and passing hollow.
SERVICES_ROOTS_DEFAULT="app/services/src app/controllers/src app/conditions/src app/jobs/src config/src lib/net/src lib/health/src lib/rpc/src"
read -r -a SERVICES_ROOTS <<< "${ZCL_SERVICES_DIR:-$SERVICES_ROOTS_DEFAULT}"

# ── --selftest: the coverage check, exercised on every `make lint` ──────────
# Three answers, not two. Each case re-invokes this gate for real with
# ZCL_SUPREG_COVERAGE_ONLY=1, so it stops the moment the coverage verdict is in
# and the umbrella never pays for a second full per-file grep pass (the real,
# complete run follows immediately in the same `--selftest && <gate>` command).
if [ "${1:-}" = "--selftest" ]; then
    self="$PWD/tools/scripts/check_supervisor_registration.sh"
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL env assignments
        local want="$1" msg="$2" rc=0
        shift 2
        env "$@" "$self" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "check_supervisor_registration: SELFTEST FAILED — $msg (wanted exit $want, got $rc)" >&2
            exit 2
        fi
    }
    # (1) the full, real scan clears its own expectation.
    cov_case 0 "the complete scan did not pass its coverage expectation" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_SUPREG_COVERAGE_ONLY=1
    # (2) a scan set deliberately reduced below the expectation (six of the
    #     eight declared roots dropped) is UNPROVEN exit 2 — never 0, never 1.
    #     The old floor of 1 could not see this: ~1000 files still cleared it.
    cov_case 2 "a scan missing whole declared roots was not UNPROVEN" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_SUPREG_COVERAGE_ONLY=1 \
        ZCL_SERVICES_DIR="app/services/src app/controllers/src"
    # (3) a shortfall SMALLER than the recorded allowance is a stale ratchet,
    #     exit 1 — an allowance that may only ever rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_LINT_PRODUCTION_SCAN=1 ZCL_SUPREG_COVERAGE_ONLY=1 \
        ZCL_SUPREG_COVERAGE_ALLOWANCE=1
    echo "[check_supervisor_registration] SELFTEST PASS (a full scan passes" \
         "coverage, a scan short six declared roots is UNPROVEN exit 2, and an" \
         "allowance above the true shortfall is a stale-ratchet exit 1)"
    exit 0
fi

COVER_RE='supervisor_register(_in_domain)?\(|thread_liveness_register(_restartable)?\(|boot_register_worker_supervisor\('

# Baseline path is overridable via ZCL_SUPREG_BASELINE so the lint-gate
# self-test can point the gate at a throwaway baseline file (planted
# fixture ⇒ trip; baselined ⇒ pass) without ever touching the real
# tools/scripts/supervisor_baseline.txt.
BASELINE="${ZCL_SUPREG_BASELINE:-tools/scripts/supervisor_baseline.txt}"
[ -f "$BASELINE" ] || touch "$BASELINE"

declare -A baseline
baseline_count=0
while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    baseline["$line"]=1
    baseline_count=$((baseline_count + 1))
done < "$BASELINE"

# Decide whether $1 spawns a *long-running* (supervisable) thread.
# thread_registry_spawn / health_register_periodic always qualify. A
# raw pthread_create qualifies only when it is NOT a short-burst worker
# (i.e. NOT covered by a raw-pthread-ok marker on the call line or the
# line above) — same exemption the check-pthread-create gate uses.
file_is_long_running() {
    local f="$1"
    if grep -qE 'thread_registry_spawn|health_register_periodic\(' "$f"; then
        return 0
    fi
    # Any unmarked pthread_create line ⇒ long-running.
    grep -nE 'pthread_create\s*\(' "$f" | while IFS=: read -r n _; do
        if sed -n "${n}p" "$f" | grep -q 'raw-pthread-ok'; then
            continue
        fi
        prev=$((n - 1))
        if [ "$prev" -gt 0 ] && \
           sed -n "${prev}p" "$f" | grep -q 'raw-pthread-ok'; then
            continue
        fi
        echo "unmarked"
    done | grep -q unmarked
}

# Fail-loud preflight: the service file set MUST be non-empty. A bare
# `for f in app/services/src/*.c` with no match iterates the LITERAL unmatched
# glob, `[ -f "$f" ]` skips it, the loop body runs zero times, `fail` stays 0,
# and the gate prints "clean" exit 0 — a hollow pass when the dir is
# renamed/moved/emptied. Discover the set with find + assert a floor instead.
mapfile -t scan_files < <(find "${SERVICES_ROOTS[@]}" -maxdepth 1 -type f -name '*.c' 2>/dev/null | sort)
gate_require_scanned "${#scan_files[@]}" 1 check_supervisor_registration \
    "no *.c under: ${SERVICES_ROOTS[*]} — was a scanned dir renamed/moved?"

# ── Coverage: did the scan reach everything it claims to cover? ─────────────
# The floor above answers "did the scan produce anything at all" — and it was
# set to 1, i.e. this gate reported clean off a single file. Measured
# 2026-08-30 the realized scan is 1056 .c files, so the floor was 0.09% of the
# surface: a scan that silently lost 1055 of 1056 files still passed, and this
# gate decides per FILE (does THIS file spawn without registering) — so a
# dropped file drops its whole verdict while the file COUNT stays large. This
# asks the right question: did the scan reach every file an INDEPENDENT oracle
# — the git index, which knows nothing about the find above, so the two cannot
# fail together — says it should have?
#
# Derived from SERVICES_ROOTS_DEFAULT, never from the (overridable)
# SERVICES_ROOTS actually in use, so pointing this gate at a subset reads as a
# shortfall rather than as a quiet redefinition of what "covered" means.
#
# Scope, unchanged: each declared root is scanned NON-recursively (`-maxdepth
# 1`, the `*/src` leaf convention), so the pathspecs carry `:(glob)` — which
# stops `*` at a `/` — instead of git's default cross-directory `*`. A .c file
# in a subdirectory of a declared root is out of this gate's surface today and
# stays out of the expectation.
#
# KNOWN LIMIT (shared with every git-oracle coverage check over hardcoded
# roots): the oracle is independent of the gate's FIND, not of the gate's ROOT
# LIST. If a whole declared root were renamed, both the find and the pathspec
# would go empty together and the shortfall would be invisible. The per-root
# assertion below closes exactly that hole: every declared root must still
# contribute at least one tracked file to the expectation.
#
# Allowance 0, shrink-only: measured expected 1056, scanned 1056, missing 0.
SUPREG_COVERAGE_ALLOWANCE="${ZCL_SUPREG_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_SUPREG_COVERAGE:-1}" = "1" ]; then
    supreg_cov_specs=()
    for supreg_cov_root in $SERVICES_ROOTS_DEFAULT; do
        supreg_cov_specs+=(":(glob)$supreg_cov_root/*.c")
    done
    # Per-root non-emptiness: a renamed root empties the find and the pathspec
    # together, which no actual-vs-expected diff can see. Ask git directly,
    # root by root, and refuse to grade if any declared root has gone silent.
    for supreg_cov_root in $SERVICES_ROOTS_DEFAULT; do
        if [ -z "$(git ls-files --cached -- ":(glob)$supreg_cov_root/*.c" 2>/dev/null || true)" ]; then
            echo "check_supervisor_registration: UNPROVEN — declared scan root" >&2
            echo "  '$supreg_cov_root' tracks no *.c at all." >&2
            echo "  A root that has been renamed, moved or emptied silently" >&2
            echo "  removes its whole surface from BOTH the find and the" >&2
            echo "  coverage expectation, so the shortfall cancels out and" >&2
            echo "  reads as clean. Refusing to grade. Fix the root list in" >&2
            echo "  SERVICES_ROOTS_DEFAULT, or drop the root if the code is" >&2
            echo "  genuinely gone." >&2
            exit 2
        fi
    done
    gate_require_git_coverage - "$SUPREG_COVERAGE_ALLOWANCE" check_supervisor_registration \
        ZCL_SUPREG_COVERAGE_ALLOWANCE \
        "Re-run from a clean checkout. If a listed file genuinely left this gate's scope, move it out of the declared roots — raising ZCL_SUPREG_COVERAGE_ALLOWANCE is a last resort and needs the reason written down." \
        -- "${supreg_cov_specs[@]}" < <(printf '%s\n' "${scan_files[@]}")
fi
if [ "${ZCL_SUPREG_COVERAGE_ONLY:-0}" = "1" ]; then
    echo "check_supervisor_registration: coverage-only PASS (${#scan_files[@]} files reached)"
    exit 0
fi

fail=0
new_violations=()
for f in "${scan_files[@]}"; do
    [ -f "$f" ] || continue
    # Long-running? Check for spawn / periodic-subscriber markers.
    file_is_long_running "$f" || continue
    # Already registered with the supervisor (directly, or via a
    # recognized adapter/wrapper)? Pass.
    if grep -qE "$COVER_RE" "$f"; then
        continue
    fi
    # Per-file override marker? Pass.
    if grep -qE '//[[:space:]]*supervisor-ok:[A-Za-z][A-Za-z0-9_-]*' "$f"; then
        continue
    fi
    # In baseline? Pass.
    if [ -n "${baseline[$f]+x}" ]; then
        continue
    fi
    new_violations+=("$f")
    fail=1
done

if [ "$fail" = "0" ]; then
    echo "check_supervisor_registration: clean — ${baseline_count} grandfathered, no new ones"
    exit 0
fi

echo ""
echo "check_supervisor_registration: ${#new_violations[@]} NEW long-running service(s) without supervisor_register_in_domain"
echo ""
for v in "${new_violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Fix options (preferred → fallback):"
echo "  1. Add a liveness contract: declare struct liveness_contract,"
echo "     init it, register it. See app/services/src/sync_watchdog_service.c"
echo "     (g_wd_contract + supervisor_register) for the canonical pattern."
echo "  2. Add a per-file override marker '// supervisor-ok:<tag>' explaining"
echo "     why this service intentionally manages its own lifecycle."
echo "  3. As last resort, add the file to $BASELINE."
exit 1
