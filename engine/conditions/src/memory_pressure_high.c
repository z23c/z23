/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * memory_pressure_high — condition. See conditions/memory_pressure_high.h. */

#include "conditions/memory_pressure_high.h"
#include "util/log_macros.h"
#include "framework/condition.h"

#include "platform/os_proc.h"
#include "util/blocker.h"
#include "util/mem_pressure.h"

#include <stdatomic.h>
#include <stdio.h>

/* Same continue-with-cooldown tier as disk_full_pause.c (sticky-node plan
 * #7): memory pressure is a TRANSIENT resource shortage, recoverable the
 * instant usage drops back below HIGH, not a deterministic-unrecoverable
 * local fault. max_attempts is small so a one-time INFORMATIONAL operator
 * notice fires once per episode, then cooldown_secs > 0 with
 * cooldown_max_rearms == 0 re-arms the remedy every cooldown_secs FOREVER
 * instead of latching operator_needed permanently. */
#define MEMORY_PRESSURE_POLL_SECS      10
#define MEMORY_PRESSURE_BACKOFF_SECS   60      /* 1 min between fast remedy attempts */
#define MEMORY_PRESSURE_MAX_ATTEMPTS   5       /* one-time informational page, then... */
#define MEMORY_PRESSURE_COOLDOWN_SECS  300     /* ...unbounded re-arm every 5 min */

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

static bool detect_memory_pressure_high(void)
{
    return mem_pressure_current() >= MEM_HIGH;
}

static enum condition_remedy_result remedy_memory_pressure_high(void)
{
    struct os_proc_mem before = {0};
    bool have_before = os_proc_mem_read(&before);

    /* Name the stall at CRITICAL: a BLOCKER_RESOURCE blocker so the
     * operator (and the supervisor sweep) see a NAMED blocker, never a
     * silent climb toward OOM. HIGH stays quieter (a WARN-adjacent state
     * the sink walk alone should resolve most of the time) — mirrors
     * disk_full_pause.c's "only name the blocker when it's serious"
     * shape. */
    if (mem_pressure_current() >= MEM_CRITICAL) {
        struct blocker_record r;
        if (blocker_init(&r, "memory-pressure", "runtime", BLOCKER_RESOURCE,
                         "resident usage at/above CRITICAL threshold; "
                         "forcing shrink-sink pass"))
            (void)blocker_set(&r);
    }

    /* Force every registered shrink sink to fire NOW instead of waiting for
     * the next passive mem_pressure health-ring tick (up to
     * MEM_PRESSURE_POLL_SECS away). This is what makes the condition
     * AUTO-TERMINATING: it can actually move RSS back down so the witness
     * clears, not just log intent and re-arm forever. */
    mem_pressure_poll_tick();

    struct os_proc_mem after = {0};
    bool have_after = os_proc_mem_read(&after);
    int64_t freed_estimate = (have_before && have_after &&
                              before.rss_bytes >= 0 && after.rss_bytes >= 0)
        ? before.rss_bytes - after.rss_bytes
        : 0;

    LOG_INFO("condition",
             "[condition:memory_pressure_high] level=%s rss_before=%lld "
             "rss_after=%lld freed_estimate_bytes=%lld",
             mem_pressure_level_name(mem_pressure_current()),
             (long long)(have_before ? before.rss_bytes : -1),
             (long long)(have_after ? after.rss_bytes : -1),
             (long long)freed_estimate);

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    /* Transient: report OK and let the witness decide. A still-high level
     * is re-detected and re-remedied on the next backoff — we never return
     * FAILED here (that would accrue attempts toward operator_needed for a
     * class that should keep quietly retrying). */
    return COND_REMEDY_OK;
}

static bool witness_memory_pressure_high(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: this condition is ENVIRONMENTAL (host memory
    // pressure), not chain-progress. "symptom moved" means resident usage
    // actually dropped — mem_pressure_poll_tick() forces a FRESH os_proc_mem
    // read (not stale/cached state), and the witness passes only when that
    // real re-measure shows the level dropped back below HIGH.
    mem_pressure_poll_tick();
    return mem_pressure_current() < MEM_HIGH;
}

static bool detail_memory_pressure_high(struct json_value *out)
{
    return mem_pressure_dump_state_json(out, NULL);
}

static struct condition c_memory_pressure_high = {
    .name = "memory_pressure_high",
    .severity = COND_CRITICAL,
    .poll_secs = MEMORY_PRESSURE_POLL_SECS,
    .backoff_secs = MEMORY_PRESSURE_BACKOFF_SECS,
    .max_attempts = MEMORY_PRESSURE_MAX_ATTEMPTS,
    /* Continue-with-cooldown (sticky-node plan #7): see the file-header
     * comment — memory pressure is a recoverable external/host-resource
     * shortage, never a permanent operator-needed latch. */
    .cooldown_secs = MEMORY_PRESSURE_COOLDOWN_SECS,
    .cooldown_max_rearms = 0,
    .detect = detect_memory_pressure_high,
    .remedy = remedy_memory_pressure_high,
    .witness = witness_memory_pressure_high,
    .detail = detail_memory_pressure_high,
    .witness_window_secs = MEMORY_PRESSURE_BACKOFF_SECS,
};

void register_memory_pressure_high(void)
{
    (void)condition_register(&c_memory_pressure_high);
}

#ifdef ZCL_TESTING
void memory_pressure_high_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
}

int memory_pressure_high_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
