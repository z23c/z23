/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Central registry for spawned threads, plus a single-source-of-
 * truth shutdown flag. Before this module landed, the node spawned ~50
 * threads from 40-plus call sites and each subsystem rolled its own
 * stop flag: `g_shutdown_requested` (signal handler), `svc->stop_requested`
 * (bg_validation), `cancel_requested` (sync jobs), etc. SIGTERM
 * propagation to every long-running loop depended on each subsystem's
 * shutdown hook being called in the correct order, so a hang anywhere
 * in the orderly-shutdown sequence left other threads spinning and
 * the systemd SIGTERM → SIGKILL grace period (5 min default) had to
 * expire.
 *
 * This header exposes a minimal API:
 *
 *   thread_registry_spawn(name, fn, arg, out_tid)
 *     Wraps pthread_create + records the tid with a human-readable
 *     name. pthread_setname_np is set when available so `top -H` and
 *     `gdb info threads` identify the thread by purpose rather than
 *     "zclassic23". Pass NULL for `out_tid` for long-running daemons
 *     that exit via thread_registry_shutdown_requested polling alone;
 *     pass a non-NULL pthread_t* for bounded-lifetime services that
 *     already have their own stop() routine and need to pthread_join
 *     the spawned thread directly.
 *
 *   thread_registry_shutdown_requested()
 *     True once shutdown has been signaled. Every long-running loop
 *     should poll this (alongside any local stop flag) — it is the
 *     single source of truth.
 *
 *   thread_registry_request_shutdown()
 *     Idempotent setter. The main signal handler sets it; programmatic
 *     shutdown paths call it too.
 *
 *   thread_registry_join_all(timeout_sec)
 *     Walks the registry, pthread_timedjoin_np's each entry with
 *     `timeout_sec` seconds, and returns the count that failed to
 *     exit in time. Diagnostic output names any stragglers so the
 *     operator can see which subsystem is hanging shutdown.
 *
 * Ownership is explicit at spawn: NULL out_tid means the registry owns the
 * join and retains a finished thread until join_all reaps it. A non-NULL
 * out_tid transfers join ownership to the subsystem; its stop routine must
 * join that tid. The registry remains a shutdown fallback while it is live.
 */

#ifndef ZCL_THREAD_REGISTRY_H
#define ZCL_THREAD_REGISTRY_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

/* Max concurrent registered threads. Sized generously above the ~50
 * currently spawned so we have headroom for swarm/parallel-sync
 * workers. */
#define ZCL_THREAD_REGISTRY_CAP 256

/* Spawn a thread via pthread_create and record it in the registry.
 * `name` is copied; pass NULL for "unnamed". When `out_tid` is
 * non-NULL, writes the spawned thread's pthread_t into *out_tid so the
 * caller can pthread_join it from its own subsystem stop() path. The
 * A NULL `out_tid` gives join ownership to the registry: normal exit marks the
 * row finished but join_all still reaps it. A non-NULL `out_tid` gives join
 * ownership to the caller: normal exit unregisters the row and the caller's
 * stop routine must pthread_join the retained tid.
 *
 * Pass a non-NULL `out_tid` for bounded-lifetime services that already
 * have their own stop() routine; pass NULL for long-running daemons
 * that exit via thread_registry_shutdown_requested polling alone.
 *
 * Returns 0 on success, pthread errno on pthread_create failure, -1 on
 * registry-full. */
int thread_registry_spawn(const char *name,
                          void *(*entry)(void *), void *arg,
                          pthread_t *out_tid);

/* True once thread_registry_request_shutdown has been called. Safe
 * to call from any thread. */
bool thread_registry_shutdown_requested(void);

/* Idempotent. Must be callable from a signal handler (atomic-only,
 * no heap allocation, no lock acquisition). */
void thread_registry_request_shutdown(void);

/* Record that the calling thread is exiting. For registry-owned threads the
 * row remains pending until join_all reaps the joinable pthread. For
 * caller-owned threads the row is removed; their stop routine retained the
 * tid and must join it. The spawn trampoline calls this automatically. */
void thread_registry_unregister_self(void);

/* pthread_timedjoin_np each registered thread with `timeout_sec`.
 * Returns the number that failed to join in time (0 on clean
 * shutdown). Prints the name of every straggler. */
int thread_registry_join_all(int timeout_sec);

/* Same diagnostic sweep, but leave the exact pthread_t values in `excluded`
 * active and owned by their subsystem. This is for dependency providers that
 * must remain alive while every consumer drains (for example the serialized
 * DB worker used by shutdown persistence). Exclusion is by pthread identity,
 * never by a fragile display name. */
int thread_registry_join_all_except(int timeout_sec,
                                    const pthread_t *excluded,
                                    size_t excluded_count);

/* Drain every still-active registered thread without abandoning ownership.
 * This is the final shutdown barrier: callers must keep every dependency
 * alive until it returns. A process-level shutdown watchdog may terminate an
 * irrecoverably stuck process, but this function never detaches a worker and
 * never reports completion while one can still access caller-owned state. */
void thread_registry_join_all_owned(void);

/* Ownership-retaining form of thread_registry_join_all_except(). */
void thread_registry_join_all_owned_except(const pthread_t *excluded,
                                           size_t excluded_count);

/* Current count of threads whose entry function has not returned. */
int thread_registry_live_count(void);

/* Current count of occupied ownership rows, including finished registry-owned
 * pthreads that still require join. A clean final shutdown audit requires both
 * live_count and unreaped_count to be zero. */
int thread_registry_unreaped_count(void);

/* One row of a registry snapshot: the spawned thread's pthread_t plus its
 * human-readable name. `tid` is directly usable with pthread_kill(). */
struct thread_registry_view {
    pthread_t tid;
    char      name[48];
};

/* Copy up to `cap` running registry entries into `out` and return the number
 * written. Acquires the registry mutex briefly for a consistent snapshot;
 * NOT signal-handler safe — call it from ordinary context (e.g. the
 * self-backtrace orchestrator) and then pthread_kill each `tid`. */
int thread_registry_snapshot(struct thread_registry_view *out, int cap);

/* Reset all registry state. For test harness use only — production
 * code should never call this. */
void thread_registry_reset_for_test(void);

#endif /* ZCL_THREAD_REGISTRY_H */
