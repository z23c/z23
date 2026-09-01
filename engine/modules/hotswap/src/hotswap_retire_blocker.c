/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Naming surface for an undrained retired hot-swap generation. See
 * hotswap/hotswap_retire_blocker.h for why this exists and why the reason
 * string carries no volatile data.
 */

#include "hotswap/hotswap_retire_blocker.h"

#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>

/* Fixed reason text. Deliberately carries NO retained count / handle /
 * generation: blocker_set folds the reason into fault identity, so varying
 * it per occurrence would re-anchor the escape deadline on every retention
 * and the blocker would never converge. */
static const char *const RETIRE_REASON =
    "superseded module mapping retained: dispatch drain unconfirmed "
    "within the bounded window";

static _Atomic unsigned long g_retained;
static _Atomic(hotswap_reclaim_fn) g_reclaim_fn;
static void *_Atomic g_reclaim_ctx;

unsigned long hotswap_retire_blocker_retained(void)
{
    return atomic_load(&g_retained);
}

void hotswap_retire_blocker_set_reclaimer(hotswap_reclaim_fn fn, void *ctx)
{
    atomic_store(&g_reclaim_ctx, ctx);
    atomic_store(&g_reclaim_fn, fn);
}

/* Escape: one bounded reclaim retry. A reclaimer that reports "everything
 * drained" clears the blocker; anything else leaves it standing, because a
 * mapping that is still retained is still a live fault and saying otherwise
 * would be the silent stop this blocker exists to prevent. */
static void hotswap_reclaim_retry_escape(const struct blocker_snapshot *snap)
{
    (void)snap;
    hotswap_reclaim_fn fn = atomic_load(&g_reclaim_fn);
    if (!fn) {
        LOG_WARN("hotswap.retire",
                 "escape %s: no reclaim path installed (release build, or "
                 "the activation core never armed the seam) — leaving the "
                 "blocker standing", HOTSWAP_RETIRE_ESCAPE_ACTION);
        return;
    }
    void *ctx = atomic_load(&g_reclaim_ctx);
    if (fn(ctx)) {
        atomic_store(&g_retained, 0UL);
        blocker_clear(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID);
        LOG_INFO("hotswap.retire",
                 "escape %s: every retained mapping reclaimed",
                 HOTSWAP_RETIRE_ESCAPE_ACTION);
        return;
    }
    LOG_WARN("hotswap.retire",
             "escape %s: reclaim retry did not drain every mapping "
             "(retained=%lu) — blocker stays named",
             HOTSWAP_RETIRE_ESCAPE_ACTION, atomic_load(&g_retained));
}

void hotswap_retire_blocker_register_escape(void)
{
    if (blocker_lookup_escape(HOTSWAP_RETIRE_ESCAPE_ACTION))
        return;  /* already registered — idempotent by design */
    /* Registered with the literal, not HOTSWAP_RETIRE_ESCAPE_ACTION: the
     * gates (check-blocker-escape-registered, check-blocker-remedy's
     * ESCAPE(...) row resolution) match the literal at the registration
     * site, same as chain_activation_service.c's "activation_drive_connect".
     * The macro above is the single definition every other use reads. */
    (void)blocker_register_escape("hotswap_reclaim_retry",
                                  hotswap_reclaim_retry_escape);
}

void hotswap_retire_blocker_raise(void)
{
    /* Self-registering: the escape is armed by the raise that needs it, so
     * there is no boot-order coupling to forget and no window where a live
     * blocker names an action the sweep cannot resolve. Idempotent. */
    hotswap_retire_blocker_register_escape();
    atomic_fetch_add(&g_retained, 1UL);

    struct blocker_record r;
    if (!blocker_init(&r, HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID,
                      "hotswap.activate", BLOCKER_DEPENDENCY, RETIRE_REASON))
        return;  /* blocker_init already logged via LOG_FAIL */
    r.escape_deadline_secs = HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS;
    snprintf(r.escape_action, sizeof(r.escape_action), "%s",
             HOTSWAP_RETIRE_ESCAPE_ACTION);
    r.retry_budget = -1;  /* the reclaim retry is never auto-expired */
    (void)blocker_set(&r);
}

void hotswap_retire_blocker_note_reclaimed(void)
{
    unsigned long prev = atomic_load(&g_retained);
    while (prev > 0 &&
           !atomic_compare_exchange_weak(&g_retained, &prev, prev - 1)) {
        /* retry with the reloaded prev */
    }
    if (prev == 0)
        return;              /* nothing was retained; nothing to clear */
    if (prev - 1 == 0)
        blocker_clear(HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID);
}

void hotswap_retire_blocker_reset_for_testing(void)
{
    atomic_store(&g_retained, 0UL);
    atomic_store(&g_reclaim_fn, NULL);
    atomic_store(&g_reclaim_ctx, NULL);
}
