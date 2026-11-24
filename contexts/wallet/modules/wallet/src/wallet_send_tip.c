/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The height a wallet send builds against: the chain tip, never a stale scan
 * cursor. The wallet module cannot read the reducer, so boot registers the
 * authoritative tip source (the same pattern as the coin reservation probe). */

#include "wallet/wallet.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

#include "platform/time_compat.h"

/* The wallet height cursor is the last thing a new block updates: the tip is
 * published first, then the post-step advances the wallet. A send that lands
 * in that window waits (bounded, woken by the advance itself) rather than
 * failing a moment before it would have worked. */
#define WALLET_SEND_TIP_WAIT_MS_DEFAULT 3000

static wallet_chain_tip_source g_tip_source;
static void *g_tip_ctx;
static int g_wait_ms = WALLET_SEND_TIP_WAIT_MS_DEFAULT;
#ifdef ZCL_TESTING
static atomic_int g_waits_entered;
#endif

static zcl_once_t g_gate_once = ZCL_ONCE_INIT;
static zcl_mutex_t g_gate;
static zcl_cond_t g_gate_cond;

static void wallet_gate_init(void)
{
    zcl_mutex_init(&g_gate);
    zcl_cond_init(&g_gate_cond);
}

void wallet_set_chain_tip_source(wallet_chain_tip_source source, void *ctx)
{
    /* Startup composition only: installed before RPC worker threads build
     * sends and left in place for the process lifetime. */
    g_tip_source = source;
    g_tip_ctx = ctx;
}

#ifdef ZCL_TESTING
void wallet_set_send_tip_wait_ms_for_test(int ms)
{
    g_wait_ms = ms < 0 ? 0 : ms;
}

int wallet_send_tip_waits_entered_for_test(void)
{
    return atomic_load(&g_waits_entered);
}
#endif

void wallet_notify_height_advanced(void)
{
    if (!zcl_once_call(&g_gate_once, wallet_gate_init))
        return;
    /* Taking the gate orders this after any waiter's cursor check, so the
     * broadcast cannot fall between that check and its wait. */
    zcl_mutex_lock(&g_gate);
    zcl_cond_broadcast(&g_gate_cond);
    zcl_mutex_unlock(&g_gate);
}

static int wallet_cursor(struct wallet *w)
{
    zcl_mutex_lock(&w->cs);
    int best = w->best_block_height;
    zcl_mutex_unlock(&w->cs);
    return best;
}

/* Block on the gate until a height advance or `deadline_ms` of budget is
 * spent; returns false once the budget is gone. Holds g_gate on entry. */
static bool wallet_gate_wait(int64_t *budget_ms)
{
#ifdef _WIN32
    int64_t t0 = (int64_t)GetTickCount64();
    SleepConditionVariableCS(&g_gate_cond, &g_gate, (DWORD)*budget_ms);
    *budget_ms -= (int64_t)GetTickCount64() - t0;
#else
    struct timespec start, deadline;
    platform_time_realtime_timespec(&start);
    deadline = start;
    deadline.tv_sec += *budget_ms / 1000;
    deadline.tv_nsec += (long)(*budget_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    int rc = pthread_cond_timedwait(&g_gate_cond, &g_gate, &deadline);
    struct timespec end;
    platform_time_realtime_timespec(&end);
    int64_t spent = (int64_t)(end.tv_sec - start.tv_sec) * 1000 +
                    (end.tv_nsec - start.tv_nsec) / 1000000;
    *budget_ms -= spent > 0 ? spent : 0;
    if (rc == ETIMEDOUT)
        *budget_ms = 0;
#endif
    return *budget_ms > 0;
}

/* A wallet exactly one block behind the tip is almost always mid-advance:
 * wait for the cursor to move, at most the wait budget. Any other lag, or a
 * wallet that is level, returns at once. */
static int wallet_settle_one_block_lag(struct wallet *w, int *best_out)
{
    int64_t budget = g_wait_ms;
    int tip = g_tip_source(g_tip_ctx);
    int best = wallet_cursor(w);
    if (tip - best != 1 || budget <= 0 ||
        !zcl_once_call(&g_gate_once, wallet_gate_init)) {
        *best_out = best;
        return tip;
    }
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_waits_entered, 1);
#endif
    for (;;) {
        zcl_mutex_lock(&g_gate);
        best = wallet_cursor(w);
        bool wait = tip - best == 1 && budget > 0;
        if (wait)
            wait = wallet_gate_wait(&budget) || wallet_cursor(w) != best;
        zcl_mutex_unlock(&g_gate);
        tip = g_tip_source(g_tip_ctx);
        best = wallet_cursor(w);
        if (!wait || tip - best != 1)
            break;
    }
    *best_out = best;
    return tip;
}

bool wallet_send_build_height(struct wallet *w, int *height_out,
                              const char **error)
{
    static _Thread_local char refusal[160];
    if (!w || !height_out || !error)
        return false;
    int tip = g_tip_source ? g_tip_source(g_tip_ctx) : 0;
    int best = wallet_cursor(w);
    if (tip <= 0) {
        /* No authoritative tip (hermetic fixture or unpublished cache):
         * nothing to compare against, keep the wallet cursor. */
        *height_out = best;
        return true;
    }
    if (tip - best == 1)
        tip = wallet_settle_one_block_lag(w, &best);
    /* The lag is the wallet's height cursor against the tip, not
     * wallet_scanned_through_height(): a pending scan-gap marker (restore,
     * birthday change, unread boot range) lowers that and may never clear
     * (a wallet without a Sapling key keeps counting shielded outputs as
     * unscanned), which would refuse every send forever with a message that
     * waiting cannot fix. A gap marker is reported by readiness and the
     * rescan commands, and sends kept working with it before this guard. */
    if (best < tip) {
        int behind = tip - best;
        if (behind == 1)
            snprintf(refusal, sizeof(refusal),
                     "wallet is catching up to the chain tip (scanned %d, "
                     "tip %d); retry in a moment", best, tip);
        else
            snprintf(refusal, sizeof(refusal),
                     "wallet is %d blocks behind chain tip (scanned %d, "
                     "tip %d)", behind, best, tip);
        *error = refusal;
        return false;
    }
    /* best >= tip: the wallet cursor has reached the node's published tip.
     * Build for the block after the cursor (the mempool validates the next
     * block). A cursor ahead of the tip is the active chain leading the
     * published tip, by one block normally and by more briefly during a
     * reorg to a shorter chain; the send builds at the cursor either way,
     * as it did before this guard. */
    *height_out = best;
    return true;
}
