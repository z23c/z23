/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "framework/condition.h"
#include "util/log_macros.h"

#include "services/chain_restore_integrity.h"
#include "services/chain_restore_repair.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── #6: supervised watchdog over the background restore worker ───────
 *
 * chain_integrity_restore_worker (below) runs the heavy
 * chain_restore_finalize() fire-and-forget on a detached thread, guarded
 * only by the bare bool g_restore_running: if the worker ever hangs (stuck
 * DB lock, pathological block-index walk), the flag never clears and every
 * future chain-integrity repair is silently skipped for the rest of the
 * process's life (queue_chain_restore's "already running" guard above).
 * Nothing watched that possibility before this. This is a DEADLINE/OBSERVE
 * -only addition — chain_restore_finalize's own logic is unchanged. A
 * period-driven supervisor child (mirrors chain_tip_watchdog's shape: it
 * watches EXTERNAL state, not its own loop) polls g_restore_running + the
 * wall-clock age of the current attempt every 30s; crossing the deadline
 * names a typed blocker and reports a self-stall so `dumpstate supervisor`
 * and `ops state --subsystem=condition` both surface the wedge instead of
 * it being invisible. 30 minutes is generous slack over any observed
 * chain_restore_finalize repair (a bounded active-chain/nBits walk+repair,
 * not a from-genesis replay). */
#define CHAIN_INTEGRITY_RESTORE_WATCHDOG_PERIOD_SECS   30
#define CHAIN_INTEGRITY_RESTORE_DEADLINE_SECS         1800

static struct liveness_contract     g_restore_watchdog_contract;
static _Atomic supervisor_child_id  g_restore_watchdog_id = SUPERVISOR_INVALID_ID;
/* CLOCK_MONOTONIC us timestamp the currently-running restore was queued at;
 * 0 when no restore is in flight. Written under g_restore_mu alongside
 * g_restore_running so the watchdog's read is always consistent with it. */
static _Atomic int64_t g_restore_started_us;

static _Atomic int g_remedy_calls;
static _Atomic int g_last_zero_nbits;
static _Atomic int g_last_tip_window_holes;
static _Atomic int g_last_total_holes;
static _Atomic int g_last_mismatches;
static _Atomic int g_last_tip_height;
static _Atomic int g_last_first_nbits_zero_height;
static _Atomic int g_last_first_hole_height;
static _Atomic int g_last_first_mismatch_height;
static _Atomic int g_last_first_tip_window_hole;
static _Atomic int g_last_tip_slot_ok;
static _Atomic int g_last_tip_real;
static _Atomic int g_last_integrity_ok;
static _Atomic int g_last_integrity_class;
static _Atomic int g_restore_queued;
static _Atomic int g_restore_finished;
static _Atomic int g_restore_last_ok;
static _Atomic int g_restore_last_code;
static _Atomic int g_restore_last_used_datadir;

static pthread_mutex_t g_restore_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_restore_running;
static struct main_state *g_restore_ms;
static char g_restore_datadir[1024];

#ifdef ZCL_TESTING
static _Atomic bool g_test_force_async;
static _Atomic bool g_test_disable_spawn;
static _Atomic int g_test_queue_calls;
#endif

static void record_integrity(const struct chain_integrity_result *r)
{
    atomic_store(&g_last_zero_nbits, r ? r->zero_nbits_count : 0);
    atomic_store(&g_last_tip_window_holes, r ? r->tip_window_holes : 0);
    atomic_store(&g_last_total_holes, r ? r->active_chain_holes : 0);
    atomic_store(&g_last_mismatches, r ? r->active_chain_mismatches : 0);
    atomic_store(&g_last_tip_height, r ? r->tip_height : -1);
    atomic_store(&g_last_first_nbits_zero_height,
                 r ? r->first_nbits_zero_height : -1);
    atomic_store(&g_last_first_hole_height, r ? r->first_hole_height : -1);
    atomic_store(&g_last_first_mismatch_height,
                 r ? r->first_mismatch_height : -1);
    atomic_store(&g_last_first_tip_window_hole,
                 r ? r->first_tip_window_hole : -1);
    atomic_store(&g_last_tip_slot_ok, r && r->tip_slot_ok ? 1 : 0);
    atomic_store(&g_last_tip_real, r && r->tip_real ? 1 : 0);
    atomic_store(&g_last_integrity_ok, r && r->ok ? 1 : 0);
    atomic_store(&g_last_integrity_class,
                 r ? (int)chain_integrity_classify(r)
                   : (int)CHAIN_INTEGRITY_UNRECOVERABLE);
}

static const char *integrity_class_name(int c)
{
    switch ((enum chain_integrity_class)c) {
    case CHAIN_INTEGRITY_CLEAN: return "clean";
    case CHAIN_INTEGRITY_RECONCILABLE: return "reconcilable";
    case CHAIN_INTEGRITY_UNRECOVERABLE: return "unrecoverable";
    }
    return "unknown";
}

static bool check_integrity(struct chain_integrity_result *out)
{
    struct main_state *ms = condition_engine_main_state();
    if (!ms) {
        if (out) memset(out, 0, sizeof(*out));
        return false;
    }

    struct chain_integrity_result r;
    chain_integrity_check_post_restore(&r, ms);
    record_integrity(&r);
    if (out) *out = r;
    return true;
}

static bool detect_chain_integrity_failed(void)
{
    struct chain_integrity_result r;
    if (!check_integrity(&r)) {
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] detect: no main_state; "
                 "skipping integrity check");
        return false;
    }
    return chain_integrity_classify(&r) != CHAIN_INTEGRITY_CLEAN;
}

static void *chain_integrity_restore_worker(void *arg)
{
    (void)arg;

    struct main_state *ms = NULL;
    char datadir[sizeof(g_restore_datadir)];
    datadir[0] = '\0';

    pthread_mutex_lock(&g_restore_mu);
    ms = g_restore_ms;
    snprintf(datadir, sizeof(datadir), "%s", g_restore_datadir);
    pthread_mutex_unlock(&g_restore_mu);

    LOG_WARN("condition",
             "[condition:chain_integrity_failed] background "
             "chain_restore_finalize started mode=%s",
             datadir[0] ? "disk" : "memory");
    struct zcl_result fr = chain_restore_finalize(
        ms, datadir[0] ? datadir : NULL);
    atomic_store(&g_restore_last_ok, fr.ok ? 1 : 0);
    atomic_store(&g_restore_last_code, fr.code);
    atomic_fetch_add(&g_restore_finished, 1);
    if (!fr.ok) {
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] background finalize "
                 "failed code=%d msg=%s", fr.code, fr.message);
    } else {
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] background finalize "
                 "finished ok");
    }

    pthread_mutex_lock(&g_restore_mu);
    g_restore_running = false;
    g_restore_ms = NULL;
    g_restore_datadir[0] = '\0';
    pthread_mutex_unlock(&g_restore_mu);
    atomic_store(&g_restore_started_us, 0);
    /* Clear any blocker the watchdog named while this attempt was still
     * running past its deadline — the worker DID return (however late), so
     * future repairs are no longer blocked. */
    blocker_clear("chain_integrity_restore_stuck");
    return NULL;
}

static enum condition_remedy_result queue_chain_restore(struct main_state *ms,
                                                        const char *datadir)
{
    if (!ms)
        return COND_REMEDY_SKIP;

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_queue_calls, 1);
    if (atomic_load(&g_test_disable_spawn))
        return COND_REMEDY_SKIP;
#endif

    pthread_mutex_lock(&g_restore_mu);
    if (g_restore_running) {
        pthread_mutex_unlock(&g_restore_mu);
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] chain restore already "
                 "running; not queueing duplicate");
        return COND_REMEDY_SKIP;
    }
    g_restore_running = true;
    g_restore_ms = ms;
    snprintf(g_restore_datadir, sizeof(g_restore_datadir), "%s",
             datadir ? datadir : "");
    pthread_mutex_unlock(&g_restore_mu);
    atomic_store(&g_restore_started_us, platform_time_monotonic_us());

    int rc = thread_registry_spawn("zcl_chain_fix",
                                   chain_integrity_restore_worker, NULL, NULL);
    if (rc != 0) {
        pthread_mutex_lock(&g_restore_mu);
        g_restore_running = false;
        g_restore_ms = NULL;
        g_restore_datadir[0] = '\0';
        pthread_mutex_unlock(&g_restore_mu);
        atomic_store(&g_restore_started_us, 0);
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] failed to spawn "
                 "background chain restore rc=%d", rc);
        return COND_REMEDY_FAILED;
    }

    atomic_fetch_add(&g_restore_queued, 1);
    atomic_store(&g_restore_last_used_datadir,
                 datadir && datadir[0] ? 1 : 0);
    LOG_WARN("condition",
             "[condition:chain_integrity_failed] queued background "
             "chain_restore_finalize mode=%s",
             datadir && datadir[0] ? "disk" : "memory");
    return COND_REMEDY_SKIP;
}

static enum condition_remedy_result remedy_chain_integrity_failed(void)
{
    struct main_state *ms = condition_engine_main_state();
    if (!ms)
        return COND_REMEDY_SKIP;

    atomic_fetch_add(&g_remedy_calls, 1);

    struct chain_integrity_result r;
    if (!check_integrity(&r)) {
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] remedy: no main_state; "
                 "skipping integrity check");
        return COND_REMEDY_SKIP;
    }
    enum chain_integrity_class cls = chain_integrity_classify(&r);

    LOG_WARN("condition", "[condition:chain_integrity_failed] zero_nbits=%d " "tip_window_holes=%d total_holes=%d mismatches=%d tip_h=%d class=%s " "action=chain_restore_finalize", r.zero_nbits_count, r.tip_window_holes, r.active_chain_holes, r.active_chain_mismatches, r.tip_height, integrity_class_name((int)cls));

    char datadir[1024];
    GetDataDir(true, datadir, sizeof(datadir));
    const char *repair_datadir =
        cls == CHAIN_INTEGRITY_UNRECOVERABLE ? datadir : NULL;

#ifdef ZCL_TESTING
    if (atomic_load(&g_test_force_async))
        return queue_chain_restore(ms, repair_datadir);
#else
    return queue_chain_restore(ms, repair_datadir);
#endif

    struct zcl_result fr = chain_restore_finalize(ms, repair_datadir);
    if (!fr.ok)
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] finalize failed "
                 "code=%d msg=%s", fr.code, fr.message);
    return fr.ok ? COND_REMEDY_OK : COND_REMEDY_FAILED;
}

static bool detail_chain_integrity_failed(struct json_value *out)
{
    if (!out)
        return false;

    int cls = atomic_load(&g_last_integrity_class);
    bool running;
    pthread_mutex_lock(&g_restore_mu);
    running = g_restore_running;
    pthread_mutex_unlock(&g_restore_mu);

    json_push_kv_bool(out, "integrity_ok",
                      atomic_load(&g_last_integrity_ok) != 0);
    json_push_kv_str(out, "integrity_class", integrity_class_name(cls));
    json_push_kv_int(out, "zero_nbits_count",
                     atomic_load(&g_last_zero_nbits));
    json_push_kv_int(out, "tip_window_holes",
                     atomic_load(&g_last_tip_window_holes));
    json_push_kv_int(out, "active_chain_holes",
                     atomic_load(&g_last_total_holes));
    json_push_kv_int(out, "active_chain_mismatches",
                     atomic_load(&g_last_mismatches));
    json_push_kv_int(out, "tip_height", atomic_load(&g_last_tip_height));
    json_push_kv_int(out, "first_nbits_zero_height",
                     atomic_load(&g_last_first_nbits_zero_height));
    json_push_kv_int(out, "first_hole_height",
                     atomic_load(&g_last_first_hole_height));
    json_push_kv_int(out, "first_mismatch_height",
                     atomic_load(&g_last_first_mismatch_height));
    json_push_kv_int(out, "first_tip_window_hole",
                     atomic_load(&g_last_first_tip_window_hole));
    json_push_kv_bool(out, "tip_slot_ok",
                      atomic_load(&g_last_tip_slot_ok) != 0);
    json_push_kv_bool(out, "tip_real",
                      atomic_load(&g_last_tip_real) != 0);
    json_push_kv_int(out, "remedy_calls", atomic_load(&g_remedy_calls));
    json_push_kv_bool(out, "restore_running", running);
    json_push_kv_int(out, "restore_queued",
                     atomic_load(&g_restore_queued));
    json_push_kv_int(out, "restore_finished",
                     atomic_load(&g_restore_finished));
    json_push_kv_bool(out, "restore_last_ok",
                      atomic_load(&g_restore_last_ok) != 0);
    json_push_kv_int(out, "restore_last_code",
                     atomic_load(&g_restore_last_code));
    json_push_kv_bool(out, "restore_last_used_datadir",
                      atomic_load(&g_restore_last_used_datadir) != 0);
    return true;
}

static bool witness_chain_integrity_failed(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: this is NOT poison-absence. check_integrity()
    // re-walks the real active_chain over the block index
    // (chain_integrity_check_post_restore) and recomputes holes / mismatches /
    // zero-nbits from scratch. The remedy (chain_restore_finalize) repairs the
    // chain but sets NO flag this witness reads, so it cannot self-certify.
    // This condition owns every non-clean class. UNRECOVERABLE uses the disk
    // repair path and stays loud; RECONCILABLE uses memory-mode window repair
    // so boot's "condition engine reconciles forward" contract actually fires.
    struct chain_integrity_result r;
    return check_integrity(&r) &&
           chain_integrity_classify(&r) == CHAIN_INTEGRITY_CLEAN;
}

static struct condition c_chain_integrity_failed = {
    .name = "chain_integrity_failed",
    .severity = COND_CRITICAL,
    .poll_secs = 30,
    .backoff_secs = 300,
    .max_attempts = 2,
    .detect = detect_chain_integrity_failed,
    .remedy = remedy_chain_integrity_failed,
    .witness = witness_chain_integrity_failed,
    .detail = detail_chain_integrity_failed,
    .witness_window_secs = 60,
};

/* ── #6: restore-worker watchdog tick (see block comment near the top) ── */
static void chain_integrity_restore_watchdog_tick(struct liveness_contract *c)
{
    (void)c;
    supervisor_child_id id = atomic_load(&g_restore_watchdog_id);

    pthread_mutex_lock(&g_restore_mu);
    bool running = g_restore_running;
    pthread_mutex_unlock(&g_restore_mu);

    if (!running) {
        /* Nothing in flight — advance the progress marker on the tick
         * counter itself so a healthy idle watchdog never looks frozen. */
        supervisor_progress(id, platform_time_monotonic_us());
        return;
    }

    int64_t started = atomic_load(&g_restore_started_us);
    /* Zero is the unset sentinel.  Test clocks may legitimately backdate a
     * synthetic start below zero when the host uptime is shorter than the
     * deadline; treating every negative value as unset made this watchdog's
     * fresh-boot proof silently exercise the no-op path. */
    int64_t age_s = started != 0
        ? (platform_time_monotonic_us() - started) / 1000000
        : 0;
    supervisor_progress(id, age_s);

    if (age_s >= CHAIN_INTEGRITY_RESTORE_DEADLINE_SECS) {
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] background "
                 "chain_restore_finalize has been running %llds (>= %ds "
                 "deadline) — naming a blocker; future chain-integrity "
                 "repairs stay skipped (queue_chain_restore's dedup guard) "
                 "until this worker returns or the process restarts",
                 (long long)age_s, CHAIN_INTEGRITY_RESTORE_DEADLINE_SECS);
        struct blocker_record rec;
        if (blocker_init(&rec, "chain_integrity_restore_stuck",
                         "condition.chain_integrity_failed",
                         BLOCKER_DEPENDENCY,
                         "background chain_restore_finalize exceeded its "
                         "deadline; no future chain-integrity repair can be "
                         "queued until it returns")) {
            rec.retry_budget = -1;  /* unbounded — never auto-expires */
            (void)blocker_set(&rec);
        }
        supervisor_report_stall(id, SUPERVISOR_STALL_CHILD_REPORTED);
    }
}

void register_chain_integrity_failed(void)
{
    (void)condition_register(&c_chain_integrity_failed);

    if (atomic_load(&g_restore_watchdog_id) != SUPERVISOR_INVALID_ID)
        return;  /* idempotent */
    liveness_contract_init(&g_restore_watchdog_contract,
                           "chain.chain_integrity_restore_watchdog");
    atomic_store(&g_restore_watchdog_contract.period_secs,
                (int64_t)CHAIN_INTEGRITY_RESTORE_WATCHDOG_PERIOD_SECS);
    atomic_store(&g_restore_watchdog_contract.deadline_secs, (int64_t)0);
    g_restore_watchdog_contract.on_tick = chain_integrity_restore_watchdog_tick;
    g_restore_watchdog_contract.on_stall = NULL;
    supervisor_domains_init();
    atomic_store(&g_restore_watchdog_id,
                supervisor_register_in_domain(g_chain_sup,
                                              &g_restore_watchdog_contract));
    if (atomic_load(&g_restore_watchdog_id) == SUPERVISOR_INVALID_ID)
        LOG_WARN("condition",
                 "[condition:chain_integrity_failed] WARN supervisor "
                 "register failed for restore watchdog");
}

#ifdef ZCL_TESTING
void chain_integrity_failed_test_reset(void)
{
    struct condition_state *s = &c_chain_integrity_failed.state;
    atomic_store(&s->first_detect_unix, 0);
    atomic_store(&s->last_poll_unix, 0);
    atomic_store(&s->last_remedy_unix, 0);
    atomic_store(&s->last_operator_needed_unix, 0);
    atomic_store(&s->target_at_detect, 0);
    atomic_store(&s->cleared_count, 0);
    condition_reset_state(&c_chain_integrity_failed);
    atomic_store(&g_remedy_calls, 0);
    atomic_store(&g_last_zero_nbits, 0);
    atomic_store(&g_last_tip_window_holes, 0);
    atomic_store(&g_last_total_holes, 0);
    atomic_store(&g_last_mismatches, 0);
    atomic_store(&g_last_tip_height, -1);
    atomic_store(&g_last_first_nbits_zero_height, -1);
    atomic_store(&g_last_first_hole_height, -1);
    atomic_store(&g_last_first_mismatch_height, -1);
    atomic_store(&g_last_first_tip_window_hole, -1);
    atomic_store(&g_last_tip_slot_ok, 0);
    atomic_store(&g_last_tip_real, 0);
    atomic_store(&g_last_integrity_ok, 0);
    atomic_store(&g_last_integrity_class,
                 (int)CHAIN_INTEGRITY_UNRECOVERABLE);
    atomic_store(&g_restore_queued, 0);
    atomic_store(&g_restore_finished, 0);
    atomic_store(&g_restore_last_ok, 0);
    atomic_store(&g_restore_last_code, 0);
    atomic_store(&g_restore_last_used_datadir, 0);
    pthread_mutex_lock(&g_restore_mu);
    g_restore_running = false;
    g_restore_ms = NULL;
    g_restore_datadir[0] = '\0';
    pthread_mutex_unlock(&g_restore_mu);
    atomic_store(&g_restore_started_us, 0);
    blocker_clear("chain_integrity_restore_stuck");
    atomic_store(&g_test_force_async, false);
    atomic_store(&g_test_disable_spawn, false);
    atomic_store(&g_test_queue_calls, 0);
}

/* Test-only accessors for the #6 restore watchdog. */
supervisor_child_id chain_integrity_failed_test_watchdog_id(void)
{
    return atomic_load(&g_restore_watchdog_id);
}

void chain_integrity_failed_test_set_started_us_ago(int64_t age_us)
{
    atomic_store(&g_restore_started_us,
                platform_time_monotonic_us() - age_us);
}

void chain_integrity_failed_test_force_running(bool running)
{
    pthread_mutex_lock(&g_restore_mu);
    g_restore_running = running;
    pthread_mutex_unlock(&g_restore_mu);
}

void chain_integrity_failed_test_watchdog_tick(void)
{
    chain_integrity_restore_watchdog_tick(&g_restore_watchdog_contract);
}

int chain_integrity_failed_test_deadline_secs(void)
{
    return CHAIN_INTEGRITY_RESTORE_DEADLINE_SECS;
}

int chain_integrity_failed_test_remedy_calls(void)
{
    return atomic_load(&g_remedy_calls);
}

void chain_integrity_failed_test_set_async(bool enabled)
{
    atomic_store(&g_test_force_async, enabled);
}

void chain_integrity_failed_test_disable_spawn(bool disabled)
{
    atomic_store(&g_test_disable_spawn, disabled);
}

int chain_integrity_failed_test_queue_calls(void)
{
    return atomic_load(&g_test_queue_calls);
}
#endif
