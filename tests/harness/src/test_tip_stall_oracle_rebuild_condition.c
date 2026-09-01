/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the tip_stall_oracle_rebuild Condition — the NON-fork twin of
 * tip_fork_stale. It heals the wedge where the tip stalls because the
 * CANONICAL next bodies never arrive over P2P, while a trusted local
 * zclassicd oracle is reachable and strictly ahead and HAS those bodies.
 *
 * We drive it the canonical way — condition_engine_tick() — and assert via
 * engine-observable state plus the ZCL_TESTING seams:
 *   - tip_stall_oracle_rebuild_test_force_stall(): satisfy the sustained
 *     no-advance window without waiting TIP_STALL_SECS in wall time.
 *   - tip_stall_oracle_rebuild_test_set_stubs(): replace the two real side
 *     effects (read zclassicd height, rebuild_recent_repair) with stubs so
 *     we can assert the remedy CALLS rebuild with the right `from` and that
 *     the oracle-reachability gate works, with no external dependency.
 *
 * Chain-construction mirrors test_tip_fork_stale.c.
 */

#include "test/test_core.h"

#include "conditions/tip_stall_oracle_rebuild.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "framework/condition.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define TSOR_CHECK(name, expr) do {                       \
    printf("tip_stall_oracle_rebuild: %s... ", (name));   \
    if (expr) printf("OK\n");                              \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Stubs for the two external side effects. */
static _Atomic int g_stub_oracle_height = 0;
static _Atomic bool g_stub_oracle_ok = true;
static struct main_state *g_advance_ms;
static struct block_index *g_advance_to;

static bool stub_oracle_height(int *out)
{
    if (out) *out = atomic_load(&g_stub_oracle_height);
    return atomic_load(&g_stub_oracle_ok);
}

static bool stub_rebuild(int from_height)
{
    (void)from_height;
    /* Model a successful canonical catch-up: advance the active tip so the
     * witness (tip advanced beyond detect height) passes. */
    if (g_advance_ms && g_advance_to)
        active_chain_move_window_tip(&g_advance_ms->chain_active, g_advance_to);
    return true;
}

/* Insert one block_index at height h with the given prev + chainwork. */
static struct block_index *tsor_insert(struct main_state *ms,
                                       struct uint256 *hash, int salt,
                                       int h, struct block_index *prev,
                                       uint64_t chainwork, unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[2] = (uint8_t)(salt & 0xFF);
    hash->data[3] = 0x07; /* distinct salt from other tests */

    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi) return NULL;
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = status;
    pi->nTx = 1;
    pi->nChainTx = (uint32_t)(h + 1);
    arith_uint256_set_u64(&pi->nChainWork, chainwork);
    pi->pprev = prev;
    return pi;
}

static struct block_index *tsor_build_main(struct main_state *ms,
                                           struct uint256 *hashes, int tip_h)
{
    struct block_index *prev = NULL;
    for (int h = 0; h <= tip_h; h++) {
        prev = tsor_insert(ms, &hashes[h], 0, h, prev,
                           (uint64_t)(h + 1),
                           BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    }
    active_chain_move_window_tip(&ms->chain_active, prev);
    return prev;
}

/* Build a higher-work header-only chain extending from `tip`, returning its
 * head (best_header). Heights tip+1..tip+5 with strictly more chainwork. */
static struct block_index *tsor_build_header_chain(struct main_state *ms,
                                                   struct uint256 *hdr_h,
                                                   struct block_index *tip,
                                                   int tip_h)
{
    struct block_index *prev = tip;
    struct block_index *best_header = NULL;
    for (int i = 1; i <= 5; i++) {
        int h = tip_h + i;
        prev = tsor_insert(ms, &hdr_h[i], 2 + i, h, prev,
                           (uint64_t)(tip_h + 1 + i * 1000),
                           BLOCK_VALID_TREE); /* header only, no data */
        best_header = prev;
    }
    return best_header;
}

static const struct json_value *tsor_json_condition(
    const struct json_value *root,
    const char *name)
{
    const struct json_value *conditions = json_get(root, "conditions");
    if (!conditions || !name)
        return NULL;
    for (size_t i = 0; i < json_size(conditions); i++) {
        const struct json_value *cond = json_at(conditions, i);
        const struct json_value *n = cond ? json_get(cond, "name") : NULL;
        if (n && strcmp(json_get_str(n), name) == 0)
            return cond;
    }
    return NULL;
}

int test_tip_stall_oracle_rebuild_condition(void)
{
    printf("\n=== tip_stall_oracle_rebuild condition tests ===\n");
    int failures = 0;
    const int TIP_H = 100;

    /* ── 1. Non-fork stall + oracle ahead → detect TRUE, remedy rebuilds
     *      from tip-2, witness confirms advancement. ─────────────────── */
    {
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        atomic_store(&g_stub_oracle_ok, true);
        atomic_store(&g_stub_oracle_height, TIP_H + 5); /* oracle ahead */

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[256];
        struct block_index *tip = tsor_build_main(&ms, hashes, TIP_H);

        /* Higher-work header chain extending the canonical tip (no fork). */
        struct uint256 hdr_h[8];
        struct block_index *best_header =
            tsor_build_header_chain(&ms, hdr_h, tip, TIP_H);
        ms.pindex_best_header = best_header;

        condition_engine_set_main_state(&ms);
        /* Model a successful heal: rebuild advances the active tip onto the
         * canonical header chain's tip+1. */
        g_advance_ms = &ms;
        g_advance_to = block_index_get_ancestor(best_header, TIP_H + 1);

        register_tip_stall_oracle_rebuild();
        tip_stall_oracle_rebuild_test_set_stubs(stub_oracle_height,
                                                stub_rebuild);
        tip_stall_oracle_rebuild_test_force_stall(TIP_H, 400);

        condition_engine_tick();

        bool ok = (best_header != NULL && g_advance_to != NULL);
        ok = ok && tip_stall_oracle_rebuild_test_rebuild_calls() == 1;
        ok = ok && tip_stall_oracle_rebuild_test_last_rebuild_from()
                       == TIP_H - 2;
        ok = ok && condition_engine_get_active_count() == 0; /* witnessed */
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond = tsor_json_condition(
            &dump, "tip_stall_oracle_rebuild");
        const struct json_value *detail = cond ? json_get(cond, "detail")
                                               : NULL;
        ok = ok && detail != NULL;
        ok = ok &&
             json_get_int(json_get(detail, "tip_height_at_detect")) == TIP_H;
        ok = ok &&
             json_get_int(json_get(detail, "best_header_at_detect")) ==
             TIP_H + 5;
        ok = ok &&
             json_get_int(json_get(detail, "oracle_height_at_detect")) ==
             TIP_H + 5;
        ok = ok &&
             json_get_int(json_get(detail, "current_tip_height")) ==
             TIP_H + 1;
        ok = ok &&
             json_get_int(json_get(detail, "last_rebuild_from")) ==
             TIP_H - 2;
        ok = ok && json_get_bool(json_get(detail, "last_rebuild_ok"));
        ok = ok &&
             json_get_int(json_get(detail, "last_witness_tip_height")) ==
             TIP_H + 1;
        ok = ok && json_get_bool(json_get(
            detail, "last_witness_tip_advanced"));
        ok = ok &&
             json_get_int(json_get(detail, "stall_secs")) == 120;
        ok = ok &&
             json_get_int(json_get(detail, "min_gap_blocks")) == 2;
        ok = ok && json_get(detail, "remedy_contract") != NULL;
        json_free(&dump);
        TSOR_CHECK("non-fork stall + oracle ahead -> rebuild from tip-2, "
                   "witnessed", ok);

        condition_engine_set_main_state(NULL);
        g_advance_ms = NULL; g_advance_to = NULL;
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        main_state_free(&ms);
    }

    /* ── 2. Oracle unreachable → detect FALSE, NO rebuild. ──────────── */
    {
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        atomic_store(&g_stub_oracle_ok, false); /* oracle down */
        atomic_store(&g_stub_oracle_height, 0);

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[256];
        struct block_index *tip = tsor_build_main(&ms, hashes, TIP_H);
        struct uint256 hdr_h[8];
        struct block_index *best_header =
            tsor_build_header_chain(&ms, hdr_h, tip, TIP_H);
        ms.pindex_best_header = best_header;

        condition_engine_set_main_state(&ms);
        register_tip_stall_oracle_rebuild();
        tip_stall_oracle_rebuild_test_set_stubs(stub_oracle_height,
                                                stub_rebuild);
        tip_stall_oracle_rebuild_test_force_stall(TIP_H, 400);

        condition_engine_tick();

        bool ok = condition_engine_get_active_count() == 0;
        ok = ok && tip_stall_oracle_rebuild_test_rebuild_calls() == 0;
        TSOR_CHECK("oracle unreachable -> detect false, NO rebuild", ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        main_state_free(&ms);
    }

    /* ── 3. Stale FORK present → detect FALSE (defer to tip_fork_stale). ─ */
    {
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        atomic_store(&g_stub_oracle_ok, true);
        atomic_store(&g_stub_oracle_height, TIP_H + 5);

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[256];
        struct block_index *tip = tsor_build_main(&ms, hashes, TIP_H);

        /* A data-bearing child of the active tip at tip+1 with LOW chainwork
         * (the stale fork the node keeps retrying). */
        struct uint256 stale_h;
        (void)tsor_insert(&ms, &stale_h, 1, TIP_H + 1, tip,
            (uint64_t)(TIP_H + 2),
            BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);

        /* Higher-work header chain branching off the SAME tip — its tip+1 is
         * a DIFFERENT (header-only) block, so the stale child is OFF it. */
        struct uint256 hdr_h[8];
        struct block_index *best_header =
            tsor_build_header_chain(&ms, hdr_h, tip, TIP_H);
        ms.pindex_best_header = best_header;

        condition_engine_set_main_state(&ms);
        register_tip_stall_oracle_rebuild();
        tip_stall_oracle_rebuild_test_set_stubs(stub_oracle_height,
                                                stub_rebuild);
        tip_stall_oracle_rebuild_test_force_stall(TIP_H, 400);

        condition_engine_tick();

        /* The stale child is OFF the best-header chain -> tip_fork_stale's
         * job. We must NOT fire. */
        bool ok = block_index_get_ancestor(best_header, TIP_H + 1) != NULL;
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && tip_stall_oracle_rebuild_test_rebuild_calls() == 0;
        TSOR_CHECK("stale fork at tip+1 -> detect false (defer to "
                   "tip_fork_stale)", ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        main_state_free(&ms);
    }

    /* ── 4. No higher-work header chain (normal at-tip) → detect FALSE. ── */
    {
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        atomic_store(&g_stub_oracle_ok, true);
        atomic_store(&g_stub_oracle_height, TIP_H); /* oracle == tip */

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[256];
        struct block_index *tip = tsor_build_main(&ms, hashes, TIP_H);
        ms.pindex_best_header = tip; /* no more-work header */

        condition_engine_set_main_state(&ms);
        register_tip_stall_oracle_rebuild();
        tip_stall_oracle_rebuild_test_set_stubs(stub_oracle_height,
                                                stub_rebuild);
        tip_stall_oracle_rebuild_test_force_stall(TIP_H, 400);

        condition_engine_tick();

        bool ok = condition_engine_get_active_count() == 0;
        ok = ok && tip_stall_oracle_rebuild_test_rebuild_calls() == 0;
        TSOR_CHECK("no higher-work header chain -> detect false", ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        main_state_free(&ms);
    }

    /* ── 5. Tip not stalled (fresh advance) → detect FALSE. ─────────── */
    {
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        atomic_store(&g_stub_oracle_ok, true);
        atomic_store(&g_stub_oracle_height, TIP_H + 5);

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[256];
        struct block_index *tip = tsor_build_main(&ms, hashes, TIP_H);
        struct uint256 hdr_h[8];
        struct block_index *best_header =
            tsor_build_header_chain(&ms, hdr_h, tip, TIP_H);
        ms.pindex_best_header = best_header;

        condition_engine_set_main_state(&ms);
        register_tip_stall_oracle_rebuild();
        tip_stall_oracle_rebuild_test_set_stubs(stub_oracle_height,
                                                stub_rebuild);
        /* Do NOT force a stall — first tick only arms the no-advance timer. */

        condition_engine_tick();

        bool ok = condition_engine_get_active_count() == 0;
        ok = ok && tip_stall_oracle_rebuild_test_rebuild_calls() == 0;
        TSOR_CHECK("tip not stalled (no sustained window) -> detect false",
                   ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        tip_stall_oracle_rebuild_test_reset();
        main_state_free(&ms);
    }

    return failures;
}
