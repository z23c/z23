/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sovereign_promotion_service — see the header for the full model. This file is
 * the control plane: tier detection, the pure seam verdict, the flip/page apply
 * step, the duty-cycle gate, the supervised worker, and the state dump.
 *
 * The one remaining integration is the ISOLATED re-derivation driver
 * (promotion_rederive_isolated): folding real on-disk bodies from the compiled
 * SHA3/ROM checkpoint up to the seam height into a promotion sub-datadir store,
 * NEVER the live coins_kv frontier. It reuses the same fold engine the boot
 * refold path drives (app/jobs stage_rederive_range + the refold drive), but
 * against a second store — the piece that must be copy-proven (H* CLIMB) before
 * it can flip live state. Until it is wired, an assisted node parks in the
 * REDERIVE_PENDING phase: fail-closed, still serving, never self-promoting on
 * unverified state. */

// one-result-type-ok:total-predicates-and-json-dump — tier/verdict/duty are
// total predicates (answers, not failures) and dump_state_json is the mandated
// bool *_dump_state_json contract (CLAUDE.md "Adding state introspection").

#include "services/sovereign_promotion_service.h"

#include "config/boot.h"                          /* boot_ratify_seam_check_and_stamp */
#include "config/consensus_state_snapshot_install.h" /* read_assisted_seam */
#include "event/event.h"                          /* event_emitf, EV_OPERATOR_NEEDED */
#include "json/json.h"
#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SP_SUBSYS "sovereign_promotion"
#define SP_CHILD_NAME "sync.sovereign_promotion"
#define SP_POLL_SECONDS 30
#define SP_SUPERVISOR_DEADLINE_SEC (SP_POLL_SECONDS * 3)

enum sp_phase {
    SP_PHASE_IDLE = 0,        /* no store / not started */
    SP_PHASE_NOT_ASSISTED,    /* sovereign or empty node — nothing to do */
    SP_PHASE_REDERIVE_PENDING,/* assisted; isolated re-fold driver not yet wired */
    SP_PHASE_PROMOTED,        /* re-derivation matched → flipped to SOVEREIGN */
    SP_PHASE_MISMATCH,        /* re-derivation disagreed → operator paged */
};

static const char *sp_phase_name(enum sp_phase p)
{
    switch (p) {
    case SP_PHASE_IDLE:             return "idle";
    case SP_PHASE_NOT_ASSISTED:     return "not_assisted";
    case SP_PHASE_REDERIVE_PENDING: return "rederive_pending";
    case SP_PHASE_PROMOTED:         return "promoted";
    case SP_PHASE_MISMATCH:         return "mismatch";
    }
    return "?";
}

static struct {
    pthread_mutex_t lock;
    pthread_t       thread;
    bool            thread_running;
    bool            stop_requested;
    _Atomic int     phase;              /* enum sp_phase */
    _Atomic bool    running;
    _Atomic int64_t attempts;
    _Atomic int64_t ratified;
    _Atomic int64_t mismatches;
    _Atomic int64_t last_seam_height;
    _Atomic uint64_t loop_ticks;
    _Atomic int     supervisor_id;
} g_sp = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .phase = SP_PHASE_IDLE,
    .last_seam_height = -1,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_sp_contract;

/* ── Pure control logic ──────────────────────────────────────────────────── */

bool sovereign_promotion_tier_is_assisted(sqlite3 *db,
                                          struct sovereign_promotion_seam *seam)
{
    if (!db)
        return false;
    /* migration-complete present (operational tier stamped). */
    uint8_t mv = 0;
    size_t mn = 0;
    bool mfound = false;
    progress_store_tx_lock();
    bool mok = progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY, &mv,
                                 sizeof(mv), &mn, &mfound);
    progress_store_tx_unlock();
    if (!mok || !mfound || mn != 1 || mv != 0x01)
        return false;
    /* self_folded ABSENT — a stamped self_folded means already SOVEREIGN. */
    if (coins_kv_contains_refold_marker(db))
        return false;
    /* an assisted seam recorded. */
    struct sovereign_promotion_seam local;
    struct sovereign_promotion_seam *s = seam ? seam : &local;
    bool found = false;
    if (!consensus_state_install_read_assisted_seam(
            db, &s->height, s->utxo_root, s->anchor_digest, s->nullifier_digest,
            &found))
        return false;
    return found;
}

enum sovereign_promotion_verdict sovereign_promotion_evaluate(
    const struct sovereign_promotion_derived *derived,
    const struct sovereign_promotion_seam *seam)
{
    if (!derived || !seam ||
        derived->height != seam->height ||
        memcmp(derived->utxo_root, seam->utxo_root, 32) != 0 ||
        memcmp(derived->anchor_digest, seam->anchor_digest, 32) != 0 ||
        memcmp(derived->nullifier_digest, seam->nullifier_digest, 32) != 0)
        return SOVEREIGN_PROMOTION_MISMATCH;
    return SOVEREIGN_PROMOTION_MATCH;
}

bool sovereign_promotion_apply_verdict(
    sqlite3 *db, enum sovereign_promotion_verdict verdict,
    const struct sovereign_promotion_seam *seam,
    const struct sovereign_promotion_derived *derived)
{
    if (!db || !seam) {
        LOG_WARN(SP_SUBSYS, "apply_verdict: null db/seam");
        return false;
    }
    atomic_store(&g_sp.last_seam_height, seam->height);
    if (verdict == SOVEREIGN_PROMOTION_MATCH) {
        if (!derived) {
            LOG_WARN(SP_SUBSYS, "apply_verdict MATCH with null derived");
            return false;
        }
        /* The live store already holds exactly this (height, root, count); the
         * generalized ratifier re-derives and atomically stamps self_folded. */
        struct boot_ratify_result r;
        bool flipped = boot_ratify_seam_check_and_stamp(
            db, seam->height, seam->utxo_root, derived->utxo_count, &r);
        if (flipped) {
            atomic_fetch_add(&g_sp.ratified, 1);
            atomic_store(&g_sp.phase, SP_PHASE_PROMOTED);
            LOG_INFO(SP_SUBSYS,
                     "PROMOTED: assisted seam h=%d re-derived from the compiled "
                     "anchor and matched — flipped to SOVEREIGN (%s)",
                     seam->height, r.reason);
        } else {
            LOG_WARN(SP_SUBSYS,
                     "seam matched but the live-store ratify refused: %s",
                     r.reason);
        }
        return flipped;
    }

    /* MISMATCH — the borrowed state disagreed with an independent fold from the
     * sovereign anchor. Raise the PERMANENT named blocker + page the operator
     * and NEVER promote (keep serving on the borrowed state). */
    atomic_fetch_add(&g_sp.mismatches, 1);
    atomic_store(&g_sp.phase, SP_PHASE_MISMATCH);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "assisted seam at h=%d disagreed with an independent re-derivation "
             "from the compiled trust anchor; borrowed state NOT promoted — "
             "operator must investigate the bundle source", seam->height);
    struct blocker_record rec;
    if (blocker_init(&rec, SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID, SP_SUBSYS,
                     BLOCKER_PERMANENT, reason) &&
        blocker_set(&rec) >= 0) {
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "sovereign_promotion seam_mismatch h=%d", seam->height);
        LOG_WARN(SP_SUBSYS,
                 "OPERATOR NEEDED: seam_mismatch h=%d — %s", seam->height,
                 reason);
    } else {
        LOG_WARN(SP_SUBSYS,
                 "seam_mismatch page emission failed h=%d (blocker registry)",
                 seam->height);
    }
    return false;
}

bool sovereign_promotion_duty_admits(uint64_t tick)
{
    int pct = 25; /* ZCL_PROMOTION_DUTY_PCT default */
    const char *e = getenv("ZCL_PROMOTION_DUTY_PCT");
    if (e && *e) {
        long v = strtol(e, NULL, 10);
        if (v >= 1 && v <= 100)
            pct = (int)v;
    }
    return (tick % 100u) < (uint64_t)pct;
}

/* ── Isolated re-derivation driver (the remaining integration) ────────────── */

/* Fold real on-disk bodies from the compiled SHA3/ROM checkpoint UP TO the seam
 * height into an ISOLATED promotion store (never the live frontier) and fill
 * *out with the re-derived commitments. Returns true iff a complete, independent
 * re-derivation is available. v1: not yet wired — returns false so the caller
 * parks fail-closed (the assisted node stays RELEASE_ASSISTED, still serving,
 * never self-promoting on unverified state). */
static bool promotion_rederive_isolated(
    const struct sovereign_promotion_seam *seam,
    struct sovereign_promotion_derived *out)
{
    (void)seam;
    (void)out;
    return false;
}

/* ── Supervised worker ───────────────────────────────────────────────────── */

static void promotion_attempt_once(void)
{
    atomic_fetch_add(&g_sp.attempts, 1);
    sqlite3 *db = progress_store_db();
    if (!db) {
        atomic_store(&g_sp.phase, SP_PHASE_IDLE);
        return;
    }
    struct sovereign_promotion_seam seam;
    if (!sovereign_promotion_tier_is_assisted(db, &seam)) {
        /* Sovereign or empty node: nothing to promote. Mark the child complete
         * so the supervisor stops gating an inert service, and signal stop. */
        atomic_store(&g_sp.phase, SP_PHASE_NOT_ASSISTED);
        supervisor_child_id id = atomic_load(&g_sp.supervisor_id);
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_child_complete(id);
        pthread_mutex_lock(&g_sp.lock);
        g_sp.stop_requested = true;
        pthread_mutex_unlock(&g_sp.lock);
        return;
    }
    atomic_store(&g_sp.last_seam_height, seam.height);
    /* Yield to the live reducer — they share the fold engine. */
    if (!sovereign_promotion_duty_admits(atomic_load(&g_sp.loop_ticks)))
        return;
    struct sovereign_promotion_derived derived;
    memset(&derived, 0, sizeof(derived));
    if (!promotion_rederive_isolated(&seam, &derived)) {
        atomic_store(&g_sp.phase, SP_PHASE_REDERIVE_PENDING);
        return; /* fail-closed: park, retry next tick */
    }
    (void)sovereign_promotion_apply_verdict(
        db, sovereign_promotion_evaluate(&derived, &seam), &seam, &derived);
    /* PROMOTED or MISMATCH is terminal for this node — stop the loop. */
    pthread_mutex_lock(&g_sp.lock);
    g_sp.stop_requested = true;
    pthread_mutex_unlock(&g_sp.lock);
}

static void *sp_thread_fn(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_sp.lock);
        bool stop = g_sp.stop_requested;
        pthread_mutex_unlock(&g_sp.lock);
        if (stop)
            break;
        atomic_fetch_add(&g_sp.loop_ticks, 1);
        supervisor_child_id id = atomic_load(&g_sp.supervisor_id);
        if (id != SUPERVISOR_INVALID_ID) {
            supervisor_tick(id);
            supervisor_progress(id, (int64_t)atomic_load(&g_sp.loop_ticks));
        }
        promotion_attempt_once();
        for (int i = 0; i < SP_POLL_SECONDS * 10; i++) {
            pthread_mutex_lock(&g_sp.lock);
            bool s = g_sp.stop_requested;
            pthread_mutex_unlock(&g_sp.lock);
            if (s)
                break;
            platform_sleep_ms(100);
        }
    }
    atomic_store(&g_sp.running, false);
    return NULL;
}

static void sp_on_stall(struct liveness_contract *c)
{
    LOG_WARN(SP_SUBSYS, "supervisor stall reason=%s phase=%s ticks=%llu",
             c ? supervisor_stall_reason_name(
                     (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
               : "unknown",
             sp_phase_name((enum sp_phase)atomic_load(&g_sp.phase)),
             (unsigned long long)atomic_load(&g_sp.loop_ticks));
}

void sovereign_promotion_service_register(void)
{
    pthread_mutex_lock(&g_sp.lock);
    if (g_sp.thread_running) {
        pthread_mutex_unlock(&g_sp.lock);
        return;
    }
    g_sp.stop_requested = false;
    g_sp.thread_running = true;
    atomic_store(&g_sp.running, true);
    pthread_mutex_unlock(&g_sp.lock);

    if (supervisor_start() &&
        atomic_load(&g_sp.supervisor_id) == SUPERVISOR_INVALID_ID) {
        liveness_contract_init(&g_sp_contract, SP_CHILD_NAME);
        atomic_store(&g_sp_contract.period_secs, 0);
        atomic_store(&g_sp_contract.deadline_secs, SP_SUPERVISOR_DEADLINE_SEC);
        atomic_store(&g_sp_contract.progress_max_quiet_us, 0);
        g_sp_contract.on_stall = sp_on_stall;
        supervisor_domains_init();
        supervisor_child_id id =
            supervisor_register_in_domain(g_chain_sup, &g_sp_contract);
        atomic_store(&g_sp.supervisor_id, id);
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_tick(id);
    }

    int rc = thread_registry_spawn("zcl_sovereign_promotion", sp_thread_fn,
                                   NULL, &g_sp.thread);
    if (rc != 0) {
        pthread_mutex_lock(&g_sp.lock);
        g_sp.thread_running = false;
        pthread_mutex_unlock(&g_sp.lock);
        atomic_store(&g_sp.running, false);
        LOG_WARN(SP_SUBSYS, "thread_registry_spawn failed (%d)", rc);
    }
}

void sovereign_promotion_service_stop(void)
{
    pthread_t th;
    bool joinable = false;
    supervisor_child_id id = atomic_load(&g_sp.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    pthread_mutex_lock(&g_sp.lock);
    if (g_sp.thread_running) {
        g_sp.stop_requested = true;
        th = g_sp.thread;
        joinable = true;
        g_sp.thread_running = false;
    }
    pthread_mutex_unlock(&g_sp.lock);
    if (joinable)
        (void)pthread_join(th, NULL);
    atomic_store(&g_sp.running, false);
}

bool sovereign_promotion_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    json_set_object(out);
    json_push_kv_str(out, "phase",
                     sp_phase_name((enum sp_phase)atomic_load(&g_sp.phase)));
    json_push_kv_bool(out, "running", atomic_load(&g_sp.running));
    json_push_kv_int(out, "attempts", atomic_load(&g_sp.attempts));
    json_push_kv_int(out, "ratified", atomic_load(&g_sp.ratified));
    json_push_kv_int(out, "mismatches", atomic_load(&g_sp.mismatches));
    json_push_kv_int(out, "last_seam_height",
                     atomic_load(&g_sp.last_seam_height));
    return true;
}
