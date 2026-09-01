/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * parity_slo_breach condition — see conditions/parity_slo_breach.h. A
 * standing measured SLO over the legacy_mirror_sync consensus-parity
 * comparison: the mirror's own mirror.rpc-unreachable / hash-disagreement
 * blockers latch and clear on individual RPC ticks (~3s cadence), so a
 * breach that never sustains long enough to page can still recur for DAYS
 * without ever crossing the mirror's own rate-limited blocker into operator
 * attention. This condition watches the SAME live comparison state over a
 * sustained window and pages once that window is exceeded — independent of
 * whether the mirror's own per-tick blocker happened to be latched at any
 * single instant. */

#include "conditions/parity_slo_breach.h"

#include "framework/condition.h"
#include "services/legacy_mirror_sync_service.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PARITY_SLO_BLOCKER_ID "consensus.parity_slo_breach"
#define PARITY_SLO_OWNER      "legacy_mirror_sync"

/* SLO windows. Both default to 30 minutes sustained — long enough that a
 * routine transient (a single slow RPC round, a momentary reorg-window
 * disagreement that resolves on the next tick) never fires, short enough
 * that a real divergence or a dead oracle is paged well inside a single
 * work session. Each is independently env-overridable for soak tuning. */
#define PARITY_SLO_DISAGREE_WINDOW_SECS    1800
#define PARITY_SLO_UNREACHABLE_WINDOW_SECS 1800

/* Sustained-window bookkeeping. 0 = signal not currently active. */
static _Atomic int64_t g_disagree_since;
static _Atomic int64_t g_unreachable_since;

/* Captured at detect for the blocker reason. */
static _Atomic int g_signal_at_detect;      /* 0=hash_disagreement, 1=oracle_unreachable */
static _Atomic int g_our_height_at_detect;
static _Atomic int g_oracle_height_at_detect;
static _Atomic int g_comparison_height_at_detect;

#ifdef ZCL_TESTING
static _Atomic int64_t g_now_override = -1;
#endif

static int64_t pslo_now(void)
{
#ifdef ZCL_TESTING
    int64_t o = atomic_load(&g_now_override);
    if (o >= 0)
        return o;
#endif
    return platform_time_wall_unix();
}

static int pslo_env_secs(const char *name, int fallback)
{
    const char *e = getenv(name);
    if (e && e[0]) {
        int v = atoi(e);
        if (v >= 1)
            return v;
    }
    return fallback;
}

static int pslo_disagree_window(void)
{
    return pslo_env_secs("ZCL_PARITY_SLO_DISAGREE_SECS",
                         PARITY_SLO_DISAGREE_WINDOW_SECS);
}

static int pslo_unreachable_window(void)
{
    return pslo_env_secs("ZCL_PARITY_SLO_UNREACHABLE_SECS",
                         PARITY_SLO_UNREACHABLE_WINDOW_SECS);
}

static void pslo_reset_tracking(void)
{
    atomic_store(&g_disagree_since, 0);
    atomic_store(&g_unreachable_since, 0);
}

static bool detect_parity_slo_breach(void)
{
    struct legacy_mirror_sync_stats s;
    legacy_mirror_sync_stats_cached_snapshot(&s);

    /* No oracle configured — nothing to measure. A later enable starts a
     * fresh window rather than firing on stale bookkeeping. */
    if (!s.enabled) {
        pslo_reset_tracking();
        return false;
    }

    int64_t now = pslo_now();

    /* Signal A: oracle reachable but the same-height comparison disagrees. */
    bool disagreeing = s.reachable && s.comparison_known &&
                       !s.comparison_hashes_agree;
    if (disagreeing) {
        if (atomic_load(&g_disagree_since) == 0)
            atomic_store(&g_disagree_since, now);
    } else {
        atomic_store(&g_disagree_since, 0);
    }

    /* Signal B: oracle unreachable while the mirror is configured. */
    if (!s.reachable) {
        if (atomic_load(&g_unreachable_since) == 0)
            atomic_store(&g_unreachable_since, now);
    } else {
        atomic_store(&g_unreachable_since, 0);
    }

    int64_t dsince = atomic_load(&g_disagree_since);
    bool sig_a = dsince != 0 && (now - dsince) >= pslo_disagree_window();

    int64_t usince = atomic_load(&g_unreachable_since);
    bool sig_b = usince != 0 && (now - usince) >= pslo_unreachable_window();

    if (sig_a || sig_b) {
        atomic_store(&g_signal_at_detect, sig_a ? 0 : 1);
        atomic_store(&g_our_height_at_detect, s.local_height);
        atomic_store(&g_oracle_height_at_detect, s.legacy_height);
        atomic_store(&g_comparison_height_at_detect, s.comparison_height);
        return true;
    }
    return false;
}

static enum condition_remedy_result remedy_parity_slo_breach(void)
{
    int sig = atomic_load(&g_signal_at_detect);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "signal=%s our_height=%d oracle_height=%d comparison_height=%d "
             "disagree_window>=%ds unreachable_window>=%ds",
             sig == 0 ? "hash_disagreement" : "oracle_unreachable",
             atomic_load(&g_our_height_at_detect),
             atomic_load(&g_oracle_height_at_detect),
             atomic_load(&g_comparison_height_at_detect),
             pslo_disagree_window(), pslo_unreachable_window());

    struct blocker_record r;
    if (blocker_init(&r, PARITY_SLO_BLOCKER_ID, PARITY_SLO_OWNER,
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
    LOG_WARN("condition", "[condition:parity_slo_breach] %s", reason);
    /* Non-destructive, observational: the mirror's own reconnect / re-agree
     * path is the recovery; this condition only names the standing SLO
     * breach so it cannot go unnoticed. */
    return COND_REMEDY_FAILED;
}

static bool witness_parity_slo_breach(int64_t target_at_detect)
{
    (void)target_at_detect;
    struct legacy_mirror_sync_stats s;
    legacy_mirror_sync_stats_cached_snapshot(&s);

    /* Resolved by one clean agreeing sample AT OR BEYOND the local height we
     * were at when the breach was detected: the oracle is reachable, the
     * same-height comparison agrees, AND s.local_height has not regressed
     * since detect. This is real observable forward progress (the local
     * chain height the comparator actually re-verified), not just an FSM
     * flag flip — a stale cached "agree" from before the breach even
     * latched can never satisfy it. A clean agreeing sample clears BOTH
     * signals: an oracle that just agreed at a common height is, by
     * construction, no longer unreachable either. */
    bool clean = s.reachable && s.comparison_known && s.comparison_hashes_agree &&
                 s.local_height >= atomic_load(&g_our_height_at_detect);
    if (clean) {
        blocker_clear(PARITY_SLO_BLOCKER_ID);
        pslo_reset_tracking();
    }
    return clean;
}

static struct condition c_parity_slo_breach = {
    .name = "parity_slo_breach",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 120,
    /* Finite fast ladder before paging once, then a rearm-forever cooldown
     * (peer_floor_violated's shape, engine/conditions/src/peer_floor_violated.c)
     * — an external-oracle dependency must never permanently give up. */
    .max_attempts = 1,
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_parity_slo_breach,
    .remedy = remedy_parity_slo_breach,
    .witness = witness_parity_slo_breach,
    .witness_window_secs = 60,
};

void register_parity_slo_breach(void)
{
    (void)condition_register(&c_parity_slo_breach);
}

#ifdef ZCL_TESTING
void parity_slo_breach_test_reset(void)
{
    pslo_reset_tracking();
    atomic_store(&g_now_override, -1);
    atomic_store(&g_signal_at_detect, 0);
    atomic_store(&g_our_height_at_detect, -1);
    atomic_store(&g_oracle_height_at_detect, -1);
    atomic_store(&g_comparison_height_at_detect, -1);
    blocker_clear(PARITY_SLO_BLOCKER_ID);
}

void parity_slo_breach_test_set_now(int64_t now_unix)
{
    atomic_store(&g_now_override, now_unix);
}

bool parity_slo_breach_test_detect(void)
{
    return detect_parity_slo_breach();
}
#endif
