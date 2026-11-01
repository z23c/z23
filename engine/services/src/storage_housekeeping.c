/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage_housekeeping — implementation. See the header for the field
 * measurements each bound exists to prevent.
 *
 * The sweep is deliberately a plain function the thread calls on a timer,
 * not logic buried in a thread body: the whole behaviour is then testable
 * synchronously, without starting a thread or waiting for a tick.
 */
// one-result-type-ok:json-dump-bool — storage_housekeeping_dump_state_json is
// the mandated *_dump_state_json bool contract (CLAUDE.md "Adding state
// introspection"); the one genuinely fallible surface here,
// storage_housekeeping_start, already returns zcl_result.

#include "platform/time_compat.h"
#include "services/storage_housekeeping.h"

#include "json/json.h"
#include "kernel/service_kernel.h"
#include "net/tor_integration.h"
#include "storage/projection_store.h"
#include "storage/topology_store.h"
#include "util/log_macros.h"
#include "util/log_rotate.h"
#include "util/storage_pacing.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SH_SUBSYS "storage_housekeeping"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct storage_housekeeping_stats g_stats = {
    .projection_file_bytes = -1,
    .projection_live_bytes = -1,
    .topology_wal_bytes = -1,
};
static pthread_t g_thread;
static bool g_thread_running = false;
static bool g_stop_requested = false;
/* True when the thread owes its first sweep at once (the deferred boot start)
 * instead of one tick after launch. Set under g_lock before the spawn. */
static bool g_first_sweep_now = false;
static char g_datadir[1024];

/* ── the sweep ─────────────────────────────────────────────────────── */

/* Each step takes the maintenance token for ITSELF and releases it before
 * the next one starts. That is what produces the idle gap between writers on
 * rotational storage: holding the token across the whole sweep would
 * serialise them against other threads but not against each other. */

/* Take the maintenance token without ever waiting past a stop request. The
 * plain begin() is an uninterruptible mutex lock, and the boot sweep now runs
 * on this service's thread: a token held for minutes by a boot-time scan would
 * make storage_housekeeping_stop()'s join wait it out. try_begin() naps at
 * most 200 ms per attempt, so the stop flag is seen at that cadence. Returns
 * false (token NOT held; the caller must not call maintenance_end) once a
 * stop or registry shutdown is requested. A non-cancelable caller (a direct
 * storage_housekeeping_sweep(), which no stop request governs) keeps the
 * original blocking begin and always gets the token. */
static bool sh_maintenance_begin(bool cancelable)
{
    if (!cancelable)
        return storage_pacing_maintenance_begin();
    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool stop = g_stop_requested;
        pthread_mutex_unlock(&g_lock);
        if (stop || thread_registry_shutdown_requested())
            return false; // raw-return-ok:stop_requested_interrupt
        if (storage_pacing_maintenance_try_begin(200))
            return true;
    }
}

/* The three steps keep their pre-existing behaviour: each attempts its bound
 * and ignores the store's result, as before this change. The only thing a
 * step reports is whether it ran at all: false means a stop request ended the
 * wait for the maintenance token, so the step did not run. */

static bool sweep_projection(const struct storage_pacing *pacing,
                             bool cancelable)
{
    /* Compaction can refuse before measuring a closed or unavailable store.
     * Preserve the unavailable sentinel until it supplies an observation. */
    struct projection_store_usage after = {
        .page_size = -1, .page_count = -1, .free_pages = -1,
        .file_bytes = -1, .live_bytes = -1, .free_bytes = -1,
    };
    if (!sh_maintenance_begin(cancelable))
        return false; // raw-return-ok:stop_requested_interrupt
    bool compacted = projection_store_compact_if_needed(
        pacing->compact_floor_bytes, pacing->compact_ratio_pct, NULL,
        &after);
    storage_pacing_maintenance_end();

    pthread_mutex_lock(&g_lock);
    g_stats.projection_file_bytes = after.file_bytes;
    g_stats.projection_live_bytes = after.live_bytes;
    if (compacted)
        g_stats.projection_compactions++;
    pthread_mutex_unlock(&g_lock);
    return true;
}

static bool sweep_topology(const struct storage_pacing *pacing,
                           bool cancelable)
{
    int64_t wal_before = -1;
    if (!sh_maintenance_begin(cancelable))
        return false; // raw-return-ok:stop_requested_interrupt
    bool truncated = topology_store_wal_checkpoint_if_over(
        pacing->wal_truncate_bytes, &wal_before);
    storage_pacing_maintenance_end();

    pthread_mutex_lock(&g_lock);
    g_stats.topology_wal_bytes =
        truncated ? topology_store_wal_bytes() : wal_before;
    if (truncated)
        g_stats.topology_checkpoints++;
    pthread_mutex_unlock(&g_lock);
    return true;
}

static bool sweep_logs(const char *datadir, const struct storage_pacing *pacing,
                       bool cancelable)
{
    if (!datadir || !datadir[0])
        return true;
    if (!sh_maintenance_begin(cancelable))
        return false; // raw-return-ok:stop_requested_interrupt
    int rotated = tor_logs_rotate(datadir, pacing->log_rotate_bytes);
    storage_pacing_maintenance_end();

    if (rotated > 0) {
        pthread_mutex_lock(&g_lock);
        g_stats.log_rotations += rotated;
        pthread_mutex_unlock(&g_lock);
    }
    return true;
}

/* Finished sweeps: the supervisor's progress marker. Separate from
 * g_stats.sweeps, which is bumped on entry. Advances for every sweep that ran
 * to its end (every step attempted), exactly as before this change; it does
 * not advance for a sweep abandoned on stop. */
static _Atomic uint64_t g_sweeps_done = 0;

/* One sweep. `cancelable` is true only for the service thread: a stop request
 * then abandons the sweep at the next token wait and counts it in
 * sweeps_interrupted. A direct call is never cancelable. */
static bool sh_sweep(const char *datadir, bool cancelable)
{
    const struct storage_pacing *pacing = storage_pacing();

    pthread_mutex_lock(&g_lock);
    g_stats.sweeps++;
    pthread_mutex_unlock(&g_lock);

    bool ran = sweep_topology(pacing, cancelable) &&
               sweep_projection(pacing, cancelable) &&
               sweep_logs(datadir, pacing, cancelable);

    pthread_mutex_lock(&g_lock);
    if (ran)
        g_stats.sweeps_finished++;
    else
        g_stats.sweeps_interrupted++;
    pthread_mutex_unlock(&g_lock);
    if (ran)
        atomic_fetch_add(&g_sweeps_done, 1);
    return ran; // raw-return-ok:interrupted_sweep_counted
}

void storage_housekeeping_sweep(const char *datadir)
{
    (void)sh_sweep(datadir, false);
}

/* ── supervisor liveness ───────────────────────────────────────────── */

/* The sweeper is a long-running thread whose whole job is to keep writing
 * bounded. A wedged one is invisible — the datadir simply starts growing
 * again — so it carries a liveness contract like its maintenance siblings.
 *
 * The deadline is generous on purpose: a single VACUUM of a multi-gigabyte
 * progress.kv on a 7200 rpm disk is minutes of work between heartbeats, and
 * the point of this service is to survive exactly that machine. Ten minutes
 * tolerates the longest legitimate sweep while still catching a real wedge,
 * the same margin db_maintenance uses for the same reason. */
#define SH_SUPERVISOR_DEADLINE_SEC 600

/* The progress marker is the COMPLETED-SWEEP count, not the 200 ms loop
 * counter: the loop counter advances whether or not the service ever
 * bounds anything again, so arming a detector on it would prove only that
 * a thread is spinning. A sweep runs every STORAGE_HOUSEKEEPING_TICK_SECONDS
 * and always does the work (measure, then rotate or vacuum whatever is over
 * its bound), so a stalled count is a real wedge. The window is one tick
 * plus the full stall deadline, so the longest legitimate sweep — a VACUUM
 * of a multi-gigabyte progress.kv on a 7200 rpm disk — never trips it. */
#define SH_PROGRESS_MAX_QUIET_US \
    ((uint64_t)(STORAGE_HOUSEKEEPING_TICK_SECONDS + SH_SUPERVISOR_DEADLINE_SEC) * \
     1000000ULL)

static _Atomic supervisor_child_id g_supervisor_id = SUPERVISOR_INVALID_ID;
static _Atomic uint64_t g_loop_ticks = 0;
static struct liveness_contract g_contract;

static void sh_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_sweeps_done));
}

static void sh_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN(SH_SUBSYS, "supervisor stall reason=%s ticks=%lld", reason,
             (long long)atomic_load(&g_loop_ticks));
}

static struct zcl_result sh_register_supervisor(void)
{
    if (!supervisor_start())
        return ZCL_ERR(-3, "storage_housekeeping: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_progress_max_quiet(id, SH_PROGRESS_MAX_QUIET_US);
        supervisor_set_deadline(id, SH_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, atomic_load(&g_sweeps_done));
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_contract, "op.storage_housekeeping");
    atomic_store(&g_contract.period_secs, 0);
    atomic_store(&g_contract.deadline_secs, SH_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_contract.progress_max_quiet_us, SH_PROGRESS_MAX_QUIET_US);
    g_contract.on_stall = sh_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_op_sup, &g_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-4, "storage_housekeeping: supervisor_register failed");
    atomic_store(&g_supervisor_id, id);
    supervisor_set_progress_max_quiet(id, SH_PROGRESS_MAX_QUIET_US);
    supervisor_progress(id, atomic_load(&g_sweeps_done));
    supervisor_tick(id);
    return ZCL_OK;
}

/* ── lifecycle ─────────────────────────────────────────────────────── */


static void *sh_thread_fn(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&g_lock);
    bool first_now = g_first_sweep_now;
    pthread_mutex_unlock(&g_lock);
    int64_t next_at_ms = platform_time_monotonic_ms() +
                         (first_now ? 0
                                    : (int64_t)STORAGE_HOUSEKEEPING_TICK_SECONDS *
                                          1000);
    for (;;) {
        pthread_mutex_lock(&g_lock);
        bool stop = g_stop_requested;
        pthread_mutex_unlock(&g_lock);
        if (stop)
            break;

        atomic_fetch_add(&g_loop_ticks, 1);
        sh_supervisor_heartbeat();

        int64_t now_ms = platform_time_monotonic_ms();
        if (now_ms >= next_at_ms) {
            char datadir[sizeof(g_datadir)];
            pthread_mutex_lock(&g_lock);
            snprintf(datadir, sizeof(datadir), "%s", g_datadir);
            pthread_mutex_unlock(&g_lock);
            (void)sh_sweep(datadir, true);
            next_at_ms = platform_time_monotonic_ms() +
                         (int64_t)STORAGE_HOUSEKEEPING_TICK_SECONDS * 1000;
        }
        /* Short sleeps so stop() returns promptly rather than after a full
         * tick — same shape as binary_staleness_service.c. */
        platform_sleep_ms(200);
    }

    pthread_mutex_lock(&g_lock);
    g_thread_running = false;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

/* Shared launch. `inline_boot_sweep` true runs the first sweep on the
 * caller's thread before returning; false leaves it to the new thread, which
 * runs it immediately, so the caller never waits on a storage lock. */
static struct zcl_result sh_start(const char *datadir, bool inline_boot_sweep)
{
    /* A sweeper with no datadir is a misconfiguration, not a degraded mode:
     * the log bound would silently never run. Refuse it by name so the
     * optional-service wrapper can report it instead of swallowing it. */
    if (!datadir || !datadir[0])
        return ZCL_ERR(-5, "storage_housekeeping_start: datadir required");
    struct stat st;
    if (stat(datadir, &st) != 0 || !S_ISDIR(st.st_mode))
        return ZCL_ERR(-6, "storage_housekeeping_start: datadir does not "
                       "exist: %s", datadir);

    pthread_mutex_lock(&g_lock);
    if (g_thread_running) {
        pthread_mutex_unlock(&g_lock);
        return ZCL_ERR(-1, "storage_housekeeping_start: already running");
    }
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
    g_stop_requested = false;
    g_first_sweep_now = !inline_boot_sweep;
    g_thread_running = true;
    int rc = thread_registry_spawn("zcl_storage_housekeeping", sh_thread_fn,
                                   NULL, &g_thread);
    if (rc != 0) {
        g_thread_running = false;
        pthread_mutex_unlock(&g_lock);
        return ZCL_ERR(-2, "storage_housekeeping_start: "
                       "thread_registry_spawn failed (%d)", rc);
    }
    pthread_mutex_unlock(&g_lock);

    struct zcl_result sup = sh_register_supervisor();
    if (!sup.ok) {
        storage_housekeeping_stop();
        return sup;
    }

    /* Inline start: one synchronous sweep before returning. The deferred
     * start skips it; the thread already owes that sweep right now. */
    if (inline_boot_sweep)
        storage_housekeeping_sweep(datadir);
    return ZCL_OK;
}

struct zcl_result storage_housekeeping_start(const char *datadir)
{
    return sh_start(datadir, true);
}

/* Boot-path start. The first sweep takes storage locks (maintenance token,
 * projection-store and topology locks) that other boot-time writers hold; the
 * live boot log shows "started service=storage_housekeeping" taking 212-850 s
 * per warm restart while START blocked the service kernel and therefore the
 * READY transition. The bounds it applies are datadir-size bounds, not
 * correctness, so the sweep runs on its own thread at once. */
struct zcl_result storage_housekeeping_start_deferred(const char *datadir)
{
    return sh_start(datadir, false);
}

void storage_housekeeping_stop(void)
{
    supervisor_child_id sup_id = atomic_load(&g_supervisor_id);
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(sup_id, 0);

    pthread_mutex_lock(&g_lock);
    if (!g_thread_running) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    g_stop_requested = true;
    pthread_t thread = g_thread;
    pthread_mutex_unlock(&g_lock);
    pthread_join(thread, NULL);
#ifdef ZCL_TESTING
    sup_id = atomic_exchange(&g_supervisor_id, SUPERVISOR_INVALID_ID);
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(sup_id);
#endif
}

void storage_housekeeping_stats(struct storage_housekeeping_stats *out)
{
    if (!out)
        return;
    pthread_mutex_lock(&g_lock);
    *out = g_stats;
    pthread_mutex_unlock(&g_lock);
}

bool storage_housekeeping_dump_state_json(struct json_value *out,
                                          const char *key)
{
    (void)key;
    if (!out)
        return false;
    struct storage_housekeeping_stats s;
    storage_housekeeping_stats(&s);

    json_set_object(out);
    json_push_kv_int(out, "sweeps", s.sweeps);
    json_push_kv_int(out, "sweeps_finished", s.sweeps_finished);
    json_push_kv_int(out, "sweeps_interrupted", s.sweeps_interrupted);
    json_push_kv_int(out, "projection_compactions", s.projection_compactions);
    json_push_kv_int(out, "topology_checkpoints", s.topology_checkpoints);
    json_push_kv_int(out, "log_rotations", s.log_rotations);
    json_push_kv_int(out, "projection_file_bytes", s.projection_file_bytes);
    json_push_kv_int(out, "projection_live_bytes", s.projection_live_bytes);
    json_push_kv_int(out, "topology_wal_bytes", s.topology_wal_bytes);
    json_push_kv_int(out, "tick_seconds", STORAGE_HOUSEKEEPING_TICK_SECONDS);
    diag_push_health(out, true, "");
    return true;
}

/* ── Boot service registration ──────────────────────────────────── */
/* Datadir size bounds: progress.kv compaction, topology.db WAL truncation,
 * and Tor log rotation, all paced by the measured storage class. Optional
 * like its maintenance siblings — a node that cannot start the sweeper still
 * runs, it just stops bounding its own datadir, and the failure is named. */
static bool sh_service_start(void *ctx)
{
    const char *datadir = ctx;
    struct zcl_result r = storage_housekeeping_start_deferred(datadir);
    if (r.ok) {
        printf("Storage housekeeping started (%ds tick; storage=%s)\n",
               STORAGE_HOUSEKEEPING_TICK_SECONDS,
               platform_storage_class_name(storage_pacing_class()));
        return true;
    }
    fprintf(stderr, "storage_housekeeping_start failed: %s\n", r.message);
    return false;
}

static void sh_service_stop(void *ctx)
{
    (void)ctx;
    storage_housekeeping_stop();
}

bool storage_housekeeping_register_service(struct zcl_service_kernel *kernel,
                                           const char *datadir)
{
    const struct zcl_service_spec spec = {
        .name = "storage_housekeeping",
        .start = sh_service_start,
        .stop = sh_service_stop,
        .ctx = (void *)datadir,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(kernel, &spec);
}
