#!/usr/bin/env bash
# Lint gate #15 — supervisor registration for long-running services.
#
# Goal: every long-running service in the scanned roots (below) either
# registers a liveness contract with the supervisor (Round 5 —
# platform/modules/util/supervisor.h), or appears in this gate's baseline file of
# grandfathered exceptions.
#
# Why: on 2026-05-21 the node ran for 8.6 h with `watchdog.checks_run`
# stuck at 0 because the engine/modules/health sweeper wedged. The supervisor
# primitive (Round 5 C1) provides an independent time-driven driver,
# but only for services that opt in via supervisor_register_in_domain().
# gate is the ratchet that drives opt-in: new long-running services
# cannot land without a contract; baseline shrinks over Rounds 6-8.
#
# Scope (2026-07-21 widen — Task D/E supervision-coverage): originally
# hardcoded to engine/services/src/*.c only, which left every supervision hole
# in app/controllers, app/conditions, app/jobs, engine/composition/src, and the
# production lib/ daemons (net/health/rpc) invisible to `make lint` — a
# background daemon loop is a long-running service whatever directory it
# lives in, and must be visible to `z23 dumpstate supervisor` so a
# wedged loop is not silent. Each root is scanned non-recursively
# (`-maxdepth 1`, the `*/src` leaf convention); widening further just means
# adding another root below.
#
# A file is "long-running" if it contains either:
#   - thread_registry_spawn      (the project's long-running wrapper)
#   - health_register_periodic(  (engine/modules/health sweeper subscriber)
#   - pthread_create(            (raw thread spawn) — EXCEPT when the
#     only such call is a short-burst worker carrying a `raw-pthread-ok`
#     marker (on the call line or the line above). Those are joined
#     within the spawning function, have bounded lifetime, and need no
#     liveness contract — mirrors the check-pthread-create Makefile gate.
#
# Such a file must contain ≥1 call to a recognized registration site —
# `supervisor_register(_in_domain)?(`, the platform/modules/util/thread_liveness.h
# adapters `thread_liveness_register(` /
# `thread_liveness_register_restartable(`, or the engine/composition/src boot-worker
# wrapper `boot_register_worker_supervisor(` (which itself calls
# supervisor_register_in_domain — see boot_worker_supervisor.c) — OR an
# entry in `tools/scripts/supervisor_baseline.txt`, OR a per-file override
# marker `// supervisor-ok:<tag>` on a line in the file.
#
# The `_restartable` variant is a recognized registration site because it
# IS one: thread_liveness_register_restartable() calls
# thread_liveness_register() (platform/modules/util/src/thread_liveness.c) and then adds
# the bounded-restart wiring on top, so the child lands on the root liveness
# tree exactly like the plain form. Before this was spelled out the anchored
# `thread_liveness_register\(` alternative missed it, and two genuinely
# supervised daemons — engine/modules/health/src/heartbeat.c (zcl_health_sweep) and
# engine/modules/rpc/src/rpc_timeout.c (zcl_rpc_timeout) — were carried as baseline
# debt they had already paid off.
#
# To clean up debt: pick a baseline entry, register a liveness
# contract for that service (mirror what sync_watchdog_service.c
# does), delete the baseline line, re-run `make lint`.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-supervisor-registration "$@"
