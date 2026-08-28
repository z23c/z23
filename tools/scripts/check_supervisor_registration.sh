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
read -r -a SERVICES_ROOTS <<< "${ZCL_SERVICES_DIR:-app/services/src app/controllers/src app/conditions/src app/jobs/src config/src lib/net/src lib/health/src lib/rpc/src}"

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
