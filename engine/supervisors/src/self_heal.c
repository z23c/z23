/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "supervisors/self_heal.h"
#include "util/log_macros.h"

#include "event/event.h"
#include "framework/condition.h"
#include "platform/time_compat.h"
#include "services/service_state_driver.h"
#include "services/sticky_escalator.h"
#include "util/blocker.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

/* Why a dedicated thread (the never-freeze law)
 * ---------------------------------------------
 * The condition engine's detect() probes and remedies can each run for
 * seconds: SQL over a 3.1M-header progress store, a reducer-frontier L1
 * reconcile, a point-in-time chainstate copy. Running the engine as the
 * `self_heal.engine` supervisor CHILD's on_tick — INLINE on the root
 * supervisor sweep thread — is unsafe: because
 * supervisor_sweep_heartbeat() is bumped once per sweep_once() BEFORE any child
 * callback runs, a heavy pass freezes the heartbeat, and the independent backstop
 * declares a FATAL ">=30s sweep frozen" and shuts the node down (e.g. a single
 * condition_engine_tick() pass on a freshly bundle-activated datadir with 3
 * heavy conditions detecting + remedying in one pass can run >30s).
 *
 * Instead: the engine runs on a dedicated `zcl_self_heal` runner thread. The
 * supervisor only SUPERVISES the runner's heartbeat — a remedy that hangs past
 * SELF_HEAL_STALL_DEADLINE_SECS becomes a NAMED blocker (self_heal.worker_
 * wedged), never a frozen liveness root. The root sweep keeps beating no matter
 * how slow a remedy is. The runner heartbeats once per loop AND (via the
 * condition-engine progress hook) between every condition, so only a single
 * remedy that never returns can lapse the deadline. */

#define SELF_HEAL_PERIOD_SECS 5
/* A remedy that never returns is a genuine wedge worth naming; a normal
 * multi-second pass must never trip this. With the per-condition heartbeat
 * hook, only a single hung remedy can lapse it. */
#define SELF_HEAL_STALL_DEADLINE_SECS 120

static struct main_state *g_ms;
static struct liveness_contract g_contract;
static _Atomic supervisor_child_id g_id = SUPERVISOR_INVALID_ID;
/* Claimed once by the registering caller. g_id is only published at the end of
 * registration, so an atomic_load(&g_id) check-then-init still lets a second
 * concurrent call double-initialize (g_ms, the condition engine main state,
 * the contract). This CAS lets exactly one caller run the init body. */
static _Atomic bool g_registered = false;

/* Runner-thread lifecycle. g_started guards a single spawn; g_stop_requested
 * asks the loop to exit; g_worker_tid(_set) let self_heal_stop() join it. */
static _Atomic bool g_started = false;
static _Atomic bool g_stop_requested = false;
static pthread_t    g_worker_tid;
static _Atomic bool g_worker_tid_set = false;

/* Fine-grained liveness: refresh the runner heartbeat between conditions so a
 * long multi-condition pass never lapses the stall deadline. Cheap atomic. */
static void self_heal_engine_progress(void)
{
    supervisor_tick(atomic_load(&g_id));
}

/* One full self-heal pass — identical work to the former on_tick, now driven by
 * the dedicated runner thread instead of the root sweep thread. */
static void self_heal_run_once(void)
{
    if (!g_ms) return;
    condition_engine_tick();
    /* Dispatch any blocker whose escape_deadline has lapsed (edge-triggered +
     * rate-limited inside the sweep). */
    (void)blocker_supervisor_sweep();
    /* Drive the top-level always-terminating remedy ladder (the escalator's own
     * 30 s supervisor tick is the backstop if this driver stalls). No-op while
     * the ladder is disarmed and there is no unresolved CRITICAL backlog. */
    sticky_escalator_drive();
    /* Drive the canonical operational mode from real progress. Pure
     * observability/state — never touches the chain or a consensus gate. */
    service_state_driver_tick();
    supervisor_progress(atomic_load(&g_id),
                        (int64_t)condition_engine_get_active_count());
}

/* Runs on the ROOT supervisor sweep thread (edge-triggered, once) when the
 * runner's heartbeat lapses past the deadline: a condition remedy is wedged.
 * Never a frozen liveness root — name it as an operator blocker + page. Cheap
 * (in-memory blocker + one event), honoring the sweep-thread callback contract. */
static void self_heal_on_stall(struct liveness_contract *c)
{
    (void)c;
    struct blocker_record rec;
    if (blocker_init(&rec, "self_heal.worker_wedged", "self_heal",
                     BLOCKER_TRANSIENT,
                     "self-heal condition-runner heartbeat lapsed past its "
                     "stall deadline — a condition remedy is wedged. The root "
                     "supervisor sweep is UNAFFECTED (this is a named blocker, "
                     "not a frozen liveness root); the runner recovers when the "
                     "remedy returns or on restart") &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=self_heal.worker_wedged a condition remedy is wedged; "
                    "root sweep unaffected");
}

static void *self_heal_worker_main(void *arg)
{
    (void)arg;
    supervisor_child_id id = atomic_load(&g_id);
    supervisor_worker_alive(id);

    while (!atomic_load(&g_stop_requested) &&
           !thread_registry_shutdown_requested()) {
        self_heal_run_once();
        supervisor_tick(id);            /* per-loop heartbeat */
        /* A completed pass means the runner is beating again: self-clear a
         * prior wedge blocker so a transient (recovered) hang does not leave a
         * stale operator page. Idempotent no-op when it was never set. */
        if (blocker_exists("self_heal.worker_wedged"))
            blocker_clear("self_heal.worker_wedged");

        /* Sleep in short slices so stop/shutdown is responsive. */
        for (int i = 0; i < SELF_HEAL_PERIOD_SECS * 10 &&
                        !atomic_load(&g_stop_requested) &&
                        !thread_registry_shutdown_requested(); i++) {
            struct timespec req = { 0, 100L * 1000000L }; /* 100 ms */
            nanosleep(&req, NULL);
        }
    }

    supervisor_worker_exited(id);
    thread_registry_unregister_self();
    return NULL;
}

void self_heal_register(struct main_state *ms)
{
    if (!ms) return;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_registered, &expected, true))
        return; /* another caller already initialized */
    g_ms = ms;
    condition_engine_set_main_state(ms);
    /* Fine-grained per-condition heartbeat for the runner thread. */
    condition_engine_set_progress_hook(self_heal_engine_progress);
    liveness_contract_init(&g_contract, "self_heal.engine");
    /* period_secs=0 ⇒ the supervisor NEVER drives on_tick inline. The runner
     * thread drives the engine and heartbeats; the supervisor only watches the
     * heartbeat via deadline_secs and names a blocker if it lapses. */
    atomic_store(&g_contract.period_secs, (int64_t)0);
    atomic_store(&g_contract.deadline_secs,
                 (int64_t)SELF_HEAL_STALL_DEADLINE_SECS);
    atomic_store(&g_contract.progress_max_quiet_us, (int64_t)0);
    g_contract.on_tick = NULL;              /* sweep thread never runs the engine */
    g_contract.on_stall = self_heal_on_stall;
    supervisor_domains_init();
    atomic_store(&g_id, supervisor_register_in_domain(g_op_sup, &g_contract));
    if (atomic_load(&g_id) == SUPERVISOR_INVALID_ID) {
        /* Losing this registration silently loses the condition engine, the
         * blocker escape sweep, and the remedy ladder all at once; a bare
         * LOG_WARN is not loud enough. Make it a durable, operator-visible
         * fact. self_heal_start() below refuses without a valid id. */
        LOG_WARN("self_heal",
                 "[self_heal] register failed — condition engine, blocker "
                 "escape sweep, and the remedy ladder have NO driver");
        struct blocker_record rec;
        if (blocker_init(&rec, "self_heal.unsupervised", "self_heal",
                         BLOCKER_PERMANENT,
                         "supervisor_register_in_domain failed for "
                         "self_heal.engine — condition engine, blocker "
                         "escape sweep, and the remedy ladder are undriven; "
                         "operator must restart the node") &&
            blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=self_heal.unsupervised self_heal registration "
                        "failed, spine undriven");
    }
}

bool self_heal_start(void)
{
    if (atomic_load(&g_id) == SUPERVISOR_INVALID_ID)
        return false;                       /* registration never succeeded */
    bool was = atomic_exchange(&g_started, true);
    if (was) return true;                   /* idempotent */
    atomic_store(&g_stop_requested, false);

    pthread_t tid;
    /* Supervised: this translation unit registers a liveness contract
     * (self_heal_register above) and the runner heartbeats it, so a wedge is a
     * named blocker (Gate #23). */
    int rc = thread_registry_spawn("zcl_self_heal", self_heal_worker_main,
                                   NULL, &tid);
    if (rc != 0) {
        atomic_store(&g_started, false);
        LOG_FAIL("self_heal", "thread_registry_spawn(zcl_self_heal) rc=%d — "
                              "condition engine has NO driver", rc);
        struct blocker_record rec;
        if (blocker_init(&rec, "self_heal.unsupervised", "self_heal",
                         BLOCKER_PERMANENT,
                         "could not spawn the self-heal condition-runner "
                         "thread — condition engine, blocker escape sweep, and "
                         "the remedy ladder are undriven; restart the node") &&
            blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=self_heal.unsupervised runner thread spawn "
                        "failed, spine undriven");
        return false;
    }
    g_worker_tid = tid;
    atomic_store(&g_worker_tid_set, true);
    return true;
}

void self_heal_stop(void)
{
    atomic_store(&g_stop_requested, true);
    if (atomic_load(&g_worker_tid_set)) {
        pthread_join(g_worker_tid, NULL);
        atomic_store(&g_worker_tid_set, false);
    }
    atomic_store(&g_started, false);
}

#ifdef ZCL_TESTING
void self_heal_test_reset(void)
{
    self_heal_stop();
    /* After the runner has joined, retire the contract so a live supervisor
     * sweep cannot fire a stray deadline stall against a stopped runner. */
    supervisor_child_id id = atomic_load(&g_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_child_complete(id);
    condition_engine_set_progress_hook(NULL);
    g_ms = NULL;
    atomic_store(&g_id, SUPERVISOR_INVALID_ID);
    atomic_store(&g_registered, false);
    atomic_store(&g_stop_requested, false);
}
#endif
