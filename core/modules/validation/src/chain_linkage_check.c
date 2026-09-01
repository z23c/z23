/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_linkage_check — see validation/chain_linkage_check.h.
 *
 * Crash-only: every refusal here is a `return false` to a caller that
 * already handles false (JOB_FATAL rollback in tip_finalize, CSR reject in
 * chain_state_service, logged skips elsewhere). The process never dies. */

#include "validation/chain_linkage_check.h"
#include "validation/chainstate.h"

#include "event/event.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct hold_slot {
    char check_id[CHAIN_HOLD_CHECK_ID_MAX];
    char blocker_id[BLOCKER_ID_MAX];
    char reason[CHAIN_HOLD_REASON_MAX];
    int  refuse_from;
    bool held;
};

/* Hot-path flag: one relaxed load on every tip move. The slots and the
 * derived minimum are written under g_lock and re-derived on each
 * set/clear (cold path). */
static _Atomic bool g_hold_active = false;
static _Atomic int  g_refuse_from = -1;

static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hold_slot g_slots[CHAIN_HOLD_SLOTS];

static _Atomic uint64_t g_violations_total = 0;
static _Atomic uint64_t g_hold_refusals_total = 0;
static _Atomic uint64_t g_offtip_switches_total = 0;

/* De-storm the refusal log: the reducer re-attempts the held move every
 * tick; without a throttle that is the 279-identical-warnings shape this
 * pack exists to kill. */
static struct log_throttle g_refusal_throttle = LOG_THROTTLE_INIT;

static void hold_publish_locked(void)
{
    int min_refuse = -1;
    bool any = false;
    for (int i = 0; i < CHAIN_HOLD_SLOTS; i++) {
        if (!g_slots[i].held)
            continue;
        any = true;
        if (min_refuse < 0 || g_slots[i].refuse_from < min_refuse)
            min_refuse = g_slots[i].refuse_from;
    }
    atomic_store_explicit(&g_refuse_from, min_refuse, memory_order_relaxed);
    atomic_store_explicit(&g_hold_active, any, memory_order_release);
}

static struct hold_slot *hold_slot_for_locked(const char *check_id)
{
    struct hold_slot *free_slot = NULL;
    for (int i = 0; i < CHAIN_HOLD_SLOTS; i++) {
        if (g_slots[i].held &&
            strncmp(g_slots[i].check_id, check_id,
                    CHAIN_HOLD_CHECK_ID_MAX) == 0)
            return &g_slots[i];
        if (!g_slots[i].held && !free_slot)
            free_slot = &g_slots[i];
    }
    return free_slot;
}

void chain_linkage_hold_set(const char *check_id, int refuse_from_h,
                            const char *reason)
{
    if (!check_id || !check_id[0] || refuse_from_h < 0) {
        LOG_WARN("validation_pack",
                 "[validation_pack] hold_set rejected: check_id=%s h=%d",
                 check_id ? check_id : "(null)", refuse_from_h);
        return;
    }
    pthread_mutex_lock(&g_lock);
    struct hold_slot *s = hold_slot_for_locked(check_id);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_WARN("validation_pack",
                 "[validation_pack] hold slots exhausted; check=%s h=%d "
                 "NOT latched (existing holds still enforce)",
                 check_id, refuse_from_h);
        return;
    }
    if (s->held) {
        /* Keep the LOWER boundary — a deeper divergence tightens the hold,
         * a shallower re-fire never loosens it. */
        if (refuse_from_h < s->refuse_from)
            s->refuse_from = refuse_from_h;
    } else {
        memset(s, 0, sizeof(*s));
        snprintf(s->check_id, sizeof(s->check_id), "%s", check_id);
        s->refuse_from = refuse_from_h;
        s->held = true;
    }
    snprintf(s->reason, sizeof(s->reason), "%s", reason ? reason : "");
    hold_publish_locked();
    pthread_mutex_unlock(&g_lock);
}

void chain_linkage_hold_raise(const char *check_id, const char *blocker_id,
                              int refuse_from_h, const char *reason)
{
    chain_linkage_hold_set(check_id, refuse_from_h, reason);

    if (!blocker_id || !blocker_id[0])
        return;
    /* Remember the blocker id on the slot so hold_clear releases it. */
    pthread_mutex_lock(&g_lock);
    struct hold_slot *s = hold_slot_for_locked(check_id);
    if (s && s->held)
        snprintf(s->blocker_id, sizeof(s->blocker_id), "%s", blocker_id);
    pthread_mutex_unlock(&g_lock);

    struct blocker_record rec;
    if (!blocker_init(&rec, blocker_id, "validation_pack",
                      BLOCKER_PERMANENT, reason))
        return; /* blocker_init already logged the malformed input */
    int rc = blocker_set(&rec);
    /* PAGE exactly once per fresh blocker write — rc==1 is a rate-limited
     * duplicate, rc==-1 an error (already logged by blocker_set). */
    if (rc == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=%s blocker=%s refuse_from_h=%d %s",
                    check_id, blocker_id, refuse_from_h,
                    reason ? reason : "");
}

void chain_linkage_hold_clear(const char *check_id)
{
    if (!check_id || !check_id[0])
        return;
    char blocker_id[BLOCKER_ID_MAX] = {0};
    bool was_held = false;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < CHAIN_HOLD_SLOTS; i++) {
        if (g_slots[i].held &&
            strncmp(g_slots[i].check_id, check_id,
                    CHAIN_HOLD_CHECK_ID_MAX) == 0) {
            memcpy(blocker_id, g_slots[i].blocker_id, sizeof(blocker_id));
            memset(&g_slots[i], 0, sizeof(g_slots[i]));
            was_held = true;
        }
    }
    hold_publish_locked();
    pthread_mutex_unlock(&g_lock);
    if (was_held) {
        if (blocker_id[0])
            blocker_clear(blocker_id);
        LOG_INFO("validation_pack",
                 "[validation_pack] hold cleared check=%s", check_id);
    }
}

bool chain_linkage_hold_active(void)
{
    return atomic_load_explicit(&g_hold_active, memory_order_acquire);
}

int chain_linkage_hold_refuse_from(void)
{
    if (!chain_linkage_hold_active())
        return -1;
    return atomic_load_explicit(&g_refuse_from, memory_order_relaxed);
}

void chain_linkage_hold_snapshot(bool *active, int *refuse_from,
                                 char *check_ids, int check_ids_cap,
                                 char *reason, int reason_cap)
{
    if (active)
        *active = chain_linkage_hold_active();
    if (refuse_from)
        *refuse_from = chain_linkage_hold_refuse_from();
    if (check_ids && check_ids_cap > 0)
        check_ids[0] = '\0';
    if (reason && reason_cap > 0)
        reason[0] = '\0';
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < CHAIN_HOLD_SLOTS; i++) {
        if (!g_slots[i].held)
            continue;
        if (check_ids && check_ids_cap > 0) {
            size_t len = strlen(check_ids);
            snprintf(check_ids + len, (size_t)check_ids_cap - len, "%s%s",
                     len ? "," : "", g_slots[i].check_id);
        }
        if (reason && reason_cap > 0 && !reason[0])
            snprintf(reason, (size_t)reason_cap, "%s", g_slots[i].reason);
    }
    pthread_mutex_unlock(&g_lock);
}

uint64_t chain_linkage_violations_total(void)
{
    return atomic_load(&g_violations_total);
}

uint64_t chain_linkage_hold_refusals_total(void)
{
    return atomic_load(&g_hold_refusals_total);
}

uint64_t chain_linkage_offtip_switches_total(void)
{
    return atomic_load(&g_offtip_switches_total);
}

/* ── Check 1: parent linkage at connect ───────────────────────────── */

bool chain_linkage_check_advance(const struct active_chain *c,
                                 const struct block_index *bi)
{
    /* Hot path: both checks are integer compares on fields already in
     * cache; the hold test is one relaxed atomic load. */
    if (bi->pprev && bi->pprev->nHeight != bi->nHeight - 1) {
        atomic_fetch_add(&g_violations_total, 1);
        char reason[CHAIN_HOLD_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "label splice at connect: h=%d pprev_h=%d (expected %d)",
                 bi->nHeight, bi->pprev->nHeight, bi->nHeight - 1);
        LOG_WARN("validation_pack",
                 "[validation_pack] REFUSED tip move: %s", reason);
        chain_linkage_hold_raise("linkage", "chain.linkage_violation",
                                 bi->nHeight, reason);
        return false;
    }

    /* Pointer identity for strict +1 advances of the visible window:
     * DIAGNOSTIC ONLY, never a refusal. A +1 move whose pprev is not the
     * current window tip object is either a legitimate single-move fork
     * switch — which active_chain_fill_window is explicitly designed to
     * absorb by rewriting the window from the pprev walk — or a label
     * splice, and a splice is already refused above at its boundary block
     * (where pprev->nHeight != nHeight-1 must hold). Refusing here would
     * false-HOLD routine 1-block network reorgs applied as one move, so
     * we count it for native dump-state inspection and let the move proceed. */
    int win_h = c->height;
    if (win_h >= 0 && bi->nHeight == win_h + 1) {
        struct block_index *t = active_chain_at(c, win_h);
        if (t && bi->pprev && bi->pprev != t) {
            atomic_fetch_add(&g_offtip_switches_total, 1);
            LOG_INFO("validation_pack",
                     "[validation_pack] +1 window move off-tip (fork "
                     "switch) h=%d window_tip_h=%d — absorbed by window "
                     "rewrite", bi->nHeight, t->nHeight);
        }
    }

    /* HOLD enforcement: refuse moves AT or PAST the divergence; moves
     * below it (rewinds, reorg unwind, repair installs) always pass. */
    if (atomic_load_explicit(&g_hold_active, memory_order_acquire)) {
        int refuse_from =
            atomic_load_explicit(&g_refuse_from, memory_order_relaxed);
        if (refuse_from >= 0 && bi->nHeight >= refuse_from) {
            atomic_fetch_add(&g_hold_refusals_total, 1);
            uint64_t reps = 0;
            uint64_t key = ((uint64_t)(uint32_t)bi->nHeight << 32)
                           | (uint32_t)refuse_from;
            if (log_throttle_should_emit(&g_refusal_throttle, key,
                                         platform_time_wall_unix(), 300,
                                         &reps))
                LOG_WARN("validation_pack",
                         "[validation_pack] HOLD refused tip move h=%d "
                         "(refuse_from=%d) repeats=%llu",
                         bi->nHeight, refuse_from,
                         (unsigned long long)reps);
            return false;
        }
    }
    return true;
}

#ifdef ZCL_TESTING
void chain_linkage_reset_for_testing(void)
{
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < CHAIN_HOLD_SLOTS; i++) {
        if (g_slots[i].held && g_slots[i].blocker_id[0])
            blocker_clear(g_slots[i].blocker_id);
        memset(&g_slots[i], 0, sizeof(g_slots[i]));
    }
    hold_publish_locked();
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_violations_total, (uint64_t)0);
    atomic_store(&g_hold_refusals_total, (uint64_t)0);
    atomic_store(&g_offtip_switches_total, (uint64_t)0);
}
#endif
