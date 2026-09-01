/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * replay_count_only — implementation. See jobs/replay_count_only.h.
 *
 * Non-stopping COUNT-AND-CONTINUE harness for the D2 coinbase-maturity replay
 * gate. Entirely gated on ZCL_REPLAY_COUNT_ONLY: when unset, replay_count_only
 * _active() returns false and the live fold never enters this path (the live
 * consensus path runs exactly as it does today). */

#include "jobs/replay_count_only.h"

#include "core/uint256.h"
#include "util/log_json.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Cached active-state: -1 = unread, 0 = inactive, 1 = active. Read once. */
static _Atomic int g_active = -1;

/* Accumulators (atomics: the fold may tick from a background reducer thread). */
static _Atomic uint64_t g_total_newly_rejected = 0;
static _Atomic int64_t  g_first_offending_height = -1;
static _Atomic uint64_t g_blocks_replayed = 0;
static _Atomic int64_t  g_tip = -1;          /* max height seen */
static _Atomic _Bool    g_genesis_readable = false;

bool replay_count_only_active(void)
{
    int a = atomic_load_explicit(&g_active, memory_order_relaxed);
    if (a >= 0)
        return a == 1;
    /* First read: latch the env decision ONCE. A non-empty value that is not
     * "0" enables it; everything else (unset / "" / "0") leaves it off. The
     * env is read exactly here so the gate can never be flipped mid-process by
     * a setenv race, and so the UNSET path stays exactly as today. */
    const char *v = getenv("ZCL_REPLAY_COUNT_ONLY");
    int decided = (v && v[0] != '\0' && strcmp(v, "0") != 0) ? 1 : 0;
    /* CAS so concurrent first-callers agree on the latched value. */
    int expected = -1;
    atomic_compare_exchange_strong_explicit(&g_active, &expected, decided,
                                            memory_order_relaxed,
                                            memory_order_relaxed);
    a = atomic_load_explicit(&g_active, memory_order_relaxed);
    if (a == 1) {
        /* Loud one-time banner so an operator can never confuse a count-only
         * run (which authors no coins past a D2 fire) with a real fold. */
        static _Atomic _Bool announced = false;
        _Bool was = atomic_exchange_explicit(&announced, true,
                                             memory_order_relaxed);
        if (!was)
            LOG_WARN("replay_gate",
                     "[replay_gate] ZCL_REPLAY_COUNT_ONLY active: D2 "
                     "coinbase-maturity fires are LOGGED+COUNTED and the fold "
                     "CONTINUES without authoring coins for an offending "
                     "block. COPY DATADIR ONLY.");
    }
    return a == 1;
}

void replay_count_only_note_d2_fire(uint32_t height,
                                    const struct uint256 *spent_txid,
                                    uint32_t spent_vout)
{
    if (!replay_count_only_active())
        return;

    atomic_fetch_add_explicit(&g_total_newly_rejected, 1,
                              memory_order_relaxed);

    /* Record the FIRST offending height (mirrors note_first_fail: only set if
     * not already set). CAS from -1 so concurrent ticks pick the lowest-seen
     * via the monotonic genesis->tip walk's natural ordering. */
    int64_t expected = -1;
    atomic_compare_exchange_strong_explicit(&g_first_offending_height,
                                            &expected, (int64_t)height,
                                            memory_order_relaxed,
                                            memory_order_relaxed);

    char hex[65] = {0};
    if (spent_txid)
        uint256_get_hex(spent_txid, hex);
    log_jsonf(LOG_JSON_WARN, "replay_gate.d2_fire",
              "\"height\":%u,\"spent_txid\":\"%s\",\"spent_vout\":%u",
              height, hex, spent_vout);
}

void replay_count_only_note_block_replayed(uint32_t height)
{
    if (!replay_count_only_active())
        return;
    atomic_fetch_add_explicit(&g_blocks_replayed, 1, memory_order_relaxed);
    /* Track the max height as the tip of the contiguous walk. */
    int64_t cur = atomic_load_explicit(&g_tip, memory_order_relaxed);
    while ((int64_t)height > cur) {
        if (atomic_compare_exchange_weak_explicit(&g_tip, &cur,
                                                  (int64_t)height,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            break;
    }
}

void replay_count_only_mark_genesis_readable(void)
{
    if (!replay_count_only_active())
        return;
    atomic_store_explicit(&g_genesis_readable, true, memory_order_relaxed);
}

void replay_count_only_emit_summary(int64_t target_tip)
{
    if (!replay_count_only_active())
        return;

    uint64_t total  = atomic_load_explicit(&g_total_newly_rejected,
                                           memory_order_relaxed);
    int64_t  first  = atomic_load_explicit(&g_first_offending_height,
                                           memory_order_relaxed);
    uint64_t blocks = atomic_load_explicit(&g_blocks_replayed,
                                           memory_order_relaxed);
    int64_t  tip    = atomic_load_explicit(&g_tip, memory_order_relaxed);
    _Bool genesis   = atomic_load_explicit(&g_genesis_readable,
                                           memory_order_relaxed);

    /* Contiguity (anti-false-0): a clean genesis->tip walk replays exactly
     * tip+1 blocks. A sparse / cold-import set walks a subset -> a FALSE 0. */
    bool contiguous = (tip >= 0) &&
                      ((int64_t)blocks == tip + 1);
    /* reached_target: the apply walk climbed to the FULL header tip, not a
     * subset stalled below it (the reviewer's "proof_validate stalls below
     * chaintip" hole). target_tip is the header_admit cursor (the staged
     * pipeline's next-height target == header_count == tip+1 when complete).
     * <0 means "unknown" -> don't gate on it (preserves the unit-test path,
     * which has no staged pipeline / header_admit cursor). */
    bool reached_target = (target_tip < 0) ||
                          (tip >= 0 && tip + 1 == target_tip);
    bool gate_pass  = (total == 0) && genesis && contiguous && reached_target;

    /* ONE greppable line, models replay_verify_service.c:264-285. */
    log_jsonf(gate_pass ? LOG_JSON_INFO : LOG_JSON_WARN,
              "replay_gate.d2.summary",
              "\"first_offending_height\":%lld,"
              "\"total_newly_rejected\":%llu,"
              "\"blocks_replayed\":%llu,"
              "\"tip\":%lld,"
              "\"target_tip\":%lld,"
              "\"genesis_readable\":%s,"
              "\"contiguous\":%s,"
              "\"reached_target\":%s,"
              "\"gate_pass\":%s",
              (long long)first,
              (unsigned long long)total,
              (unsigned long long)blocks,
              (long long)tip,
              (long long)target_tip,
              genesis ? "true" : "false",
              contiguous ? "true" : "false",
              reached_target ? "true" : "false",
              gate_pass ? "true" : "false");
}

void replay_count_only_reset_for_test(void)
{
    atomic_store_explicit(&g_active, -1, memory_order_relaxed);
    atomic_store_explicit(&g_total_newly_rejected, 0, memory_order_relaxed);
    atomic_store_explicit(&g_first_offending_height, -1, memory_order_relaxed);
    atomic_store_explicit(&g_blocks_replayed, 0, memory_order_relaxed);
    atomic_store_explicit(&g_tip, -1, memory_order_relaxed);
    atomic_store_explicit(&g_genesis_readable, false, memory_order_relaxed);
}

int64_t replay_count_only_total_rejected(void)
{
    return (int64_t)atomic_load_explicit(&g_total_newly_rejected,
                                         memory_order_relaxed);
}

int64_t replay_count_only_first_offending_height(void)
{
    return atomic_load_explicit(&g_first_offending_height,
                                memory_order_relaxed);
}
