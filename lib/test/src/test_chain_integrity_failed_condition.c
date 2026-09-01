/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "services/chain_restore_integrity.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <string.h>

#define CIF_CHECK(name, expr) do { \
    printf("chain_integrity_failed_condition: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_chain_integrity_failed(void);
void chain_integrity_failed_test_reset(void);
int chain_integrity_failed_test_remedy_calls(void);
void chain_integrity_failed_test_set_async(bool enabled);
void chain_integrity_failed_test_disable_spawn(bool disabled);
int chain_integrity_failed_test_queue_calls(void);

/* #6 restore-worker watchdog test seams. */
supervisor_child_id chain_integrity_failed_test_watchdog_id(void);
void chain_integrity_failed_test_set_started_us_ago(int64_t age_us);
void chain_integrity_failed_test_force_running(bool running);
void chain_integrity_failed_test_watchdog_tick(void);
int chain_integrity_failed_test_deadline_secs(void);

static void reset_cif(struct main_state *ms)
{
    condition_engine_reset_for_testing();
    chain_integrity_failed_test_reset();
    main_state_init(ms);
    condition_engine_set_main_state(ms);
}

static void cleanup_cif(struct main_state *ms)
{
    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    chain_integrity_failed_test_reset();
    main_state_free(ms);
}

static struct block_index *insert_test_block(struct main_state *ms,
                                             struct uint256 *hashes,
                                             int h)
{
    memset(&hashes[h], 0, sizeof(hashes[h]));
    hashes[h].data[0] = (uint8_t)(h & 0xFF);
    hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
    hashes[h].data[3] = 0xC1;
    struct block_index *pi = chainstate_insert_block_index(
        (struct chainstate *)ms, &hashes[h]);
    if (!pi) return NULL;
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    pi->nTx = 1;
    pi->nChainTx = (uint32_t)(h + 1);
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    if (h > 0)
        pi->pprev = block_map_find(&ms->map_block_index, &hashes[h - 1]);
    return pi;
}

static bool seed_linked_chain(struct main_state *ms,
                              struct uint256 *hashes,
                              int tip_h)
{
    for (int h = 0; h <= tip_h; h++) {
        if (!insert_test_block(ms, hashes, h))
            return false;
    }
    struct block_index *tip = block_map_find(&ms->map_block_index,
                                             &hashes[tip_h]);
    return tip && active_chain_move_window_tip(&ms->chain_active, tip);
}

static const struct json_value *find_condition_json(
    const struct json_value *conditions,
    const char *name)
{
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

int test_chain_integrity_failed_condition(void)
{
    printf("\n=== chain_integrity_failed condition tests ===\n");
    int failures = 0;

    /* Isolate GetDataDir() to a hermetic tmp directory for this whole test.
     * remedy_chain_integrity_failed() (app/conditions/src/chain_integrity_
     * failed.c) resolves GetDataDir(true, ...) unconditionally on every
     * remedy call and, when classification is UNRECOVERABLE, hands that path
     * to chain_restore_finalize() -> chain_restore_quarantine_synthetic_tip(),
     * which walks tip->pprev looking for a consensus-backed ancestor and, at
     * height 0 (genesis has no pprev-presence gate — see chain_restore_
     * backing.c), attempts a real pread() of "<datadir>/blocks/blk00000.dat"
     * even though this test's synthetic genesis block_index has no real
     * on-disk position (nFile=nDataPos=0, only BLOCK_HAVE_DATA is set).
     * Without SetDataDir here, GetDataDir() resolves to the operator's real
     * default datadir (~/.zclassic-c23): on a host with a live node running
     * there, that file exists and gets opened, silently weakening this test
     * into reading real, unrelated block bytes; on a hosted CI runner with no
     * node, the open legitimately fails ("cannot open .../blk00000.dat").
     * Neither behavior is intended — pin datadir to an empty, hermetic tmp
     * dir so the read consistently and honestly misses on every host. */
    char cif_datadir[256];
    test_make_tmpdir(cif_datadir, sizeof(cif_datadir),
                     "chain_integrity_failed_condition", "datadir");
    SetDataDir(cif_datadir);

    {
        struct main_state ms;
        struct uint256 hashes[11];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 10);
        for (int h = 0; h < 10; h++)
            ms.chain_active.chain[h] = NULL;

        struct chain_integrity_result before;
        chain_integrity_check_post_restore(&before, &ms);
        ok = ok && before.ok == false;
        ok = ok && before.active_chain_holes == 10;
        ok = ok && before.active_chain_mismatches == 0;
        ok = ok && chain_integrity_classify(&before) ==
                         CHAIN_INTEGRITY_RECONCILABLE;

        condition_engine_tick();

        struct chain_integrity_result after;
        chain_integrity_check_post_restore(&after, &ms);
        ok = ok && chain_integrity_failed_test_remedy_calls() == 1;
        ok = ok && chain_integrity_failed_test_queue_calls() == 0;
        ok = ok && after.ok == true;
        ok = ok && after.active_chain_holes == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        CIF_CHECK("ancestor holes stay reconcilable and trigger remedy", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        struct uint256 hashes[11];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 10);
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        ok = ok && tip != NULL;
        if (tip)
            tip->nBits = 0;

        struct chain_integrity_result before;
        chain_integrity_check_post_restore(&before, &ms);
        ok = ok && before.ok == false;
        ok = ok && before.zero_nbits_count == 1;

        condition_engine_tick();

        struct chain_integrity_result after;
        chain_integrity_check_post_restore(&after, &ms);
        ok = ok && chain_integrity_failed_test_remedy_calls() == 1;
        ok = ok && after.ok == false;
        ok = ok && condition_engine_get_active_count() == 1;
        CIF_CHECK("fatal nBits zero triggers restore finalize remedy", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        struct uint256 hashes[5];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 4);
        condition_engine_tick();

        ok = ok && chain_integrity_failed_test_remedy_calls() == 0;
        ok = ok && condition_engine_get_active_count() == 0;
        CIF_CHECK("clean chain is ignored", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        struct uint256 hashes[11];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 10);
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        ok = ok && tip != NULL;
        if (tip)
            tip->nBits = 0;

        chain_integrity_failed_test_set_async(true);
        chain_integrity_failed_test_disable_spawn(true);
        condition_engine_tick();

        struct chain_integrity_result after;
        chain_integrity_check_post_restore(&after, &ms);
        ok = ok && chain_integrity_failed_test_remedy_calls() == 1;
        ok = ok && chain_integrity_failed_test_queue_calls() == 1;
        ok = ok && after.ok == false;
        ok = ok && after.zero_nbits_count == 1;
        ok = ok && chain_integrity_classify(&after) ==
                         CHAIN_INTEGRITY_UNRECOVERABLE;
        ok = ok && condition_engine_get_active_count() == 1;
        CIF_CHECK("async remedy queues without inline finalize", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        struct uint256 hashes[11];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 10);
        ms.chain_active.chain[10] = NULL;

        chain_integrity_failed_test_set_async(true);
        chain_integrity_failed_test_disable_spawn(true);
        condition_engine_tick();
        ok = ok && chain_integrity_failed_test_remedy_calls() == 1;
        ok = ok && chain_integrity_failed_test_queue_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        ok = ok && condition_engine_dump_state_json(&out, NULL);
        const struct json_value *conditions = json_get(&out, "conditions");
        const struct json_value *cond =
            find_condition_json(conditions, "chain_integrity_failed");
        const struct json_value *detail = cond ? json_get(cond, "detail") : NULL;
        ok = ok && detail != NULL;
        ok = ok && strcmp(json_get_str(json_get(detail, "integrity_class")),
                          "reconcilable") == 0;
        ok = ok && json_get_int(json_get(detail, "tip_window_holes")) == 1;
        ok = ok && json_get_int(json_get(detail, "active_chain_holes")) == 1;
        ok = ok &&
             json_get_int(json_get(detail, "active_chain_mismatches")) == 0;
        ok = ok && !json_get_bool(json_get(detail,
                                           "restore_last_used_datadir"));
        json_free(&out);
        CIF_CHECK("reconcilable integrity queues memory repair and stays active", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        struct uint256 hashes[5];
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        ok = ok && seed_linked_chain(&ms, hashes, 4);
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        ok = ok && tip != NULL;
        if (tip)
            tip->nBits = 0;

        condition_engine_tick();

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        ok = ok && condition_engine_dump_state_json(&out, NULL);
        const struct json_value *conditions = json_get(&out, "conditions");
        const struct json_value *cond =
            find_condition_json(conditions, "chain_integrity_failed");
        const struct json_value *detail = cond ? json_get(cond, "detail") : NULL;
        ok = ok && detail != NULL;
        ok = ok && strcmp(json_get_str(json_get(detail, "integrity_class")),
                          "unrecoverable") == 0;
        ok = ok && json_get_int(json_get(detail, "zero_nbits_count")) == 1;
        ok = ok && json_get_int(json_get(detail,
                                         "first_nbits_zero_height")) == 4;
        json_free(&out);
        CIF_CHECK("detail exposes unrecoverable integrity state", ok);
        cleanup_cif(&ms);
    }

    {
        struct main_state ms;
        reset_cif(&ms);
        bool ok = true;
        register_chain_integrity_failed();

        supervisor_child_id wid = chain_integrity_failed_test_watchdog_id();
        ok = ok && wid != SUPERVISOR_INVALID_ID;

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        bool found = false;
        uint32_t stall_before = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].name,
                       "chain.chain_integrity_restore_watchdog") == 0) {
                found = true;
                stall_before = snaps[i].stall_fires;
                ok = ok && snaps[i].period_secs == 30;
                break;
            }
        }
        ok = ok && found;

        /* Not running: tick is a no-op, no blocker named. */
        chain_integrity_failed_test_force_running(false);
        chain_integrity_failed_test_watchdog_tick();
        ok = ok && !blocker_exists("chain_integrity_restore_stuck");

        /* Running, well under the deadline: still no blocker. */
        chain_integrity_failed_test_force_running(true);
        chain_integrity_failed_test_set_started_us_ago(5LL * 1000000);
        chain_integrity_failed_test_watchdog_tick();
        ok = ok && !blocker_exists("chain_integrity_restore_stuck");

        /* Running, past the deadline: the watchdog names a blocker and
         * reports a self-stall on its own supervisor child — the #6 fix
         * (previously a hung worker was invisible: only g_restore_running
         * stayed latched, no blocker, no supervisor signal). */
        int64_t deadline_s = chain_integrity_failed_test_deadline_secs();
        /* Force the synthetic start below zero, exactly as on a fresh CI VM
         * whose monotonic uptime is shorter than the 30-minute deadline.
         * Zero alone is the production unset sentinel. */
        chain_integrity_failed_test_set_started_us_ago(
            platform_time_monotonic_us() +
            (deadline_s + 60) * 1000000LL);
        chain_integrity_failed_test_watchdog_tick();
        ok = ok && blocker_exists("chain_integrity_restore_stuck");
        ok = ok && blocker_class_for("chain_integrity_restore_stuck") ==
                         BLOCKER_DEPENDENCY;

        n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        bool stall_bumped = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].name,
                       "chain.chain_integrity_restore_watchdog") == 0) {
                stall_bumped = snaps[i].stall_fires > stall_before;
                break;
            }
        }
        ok = ok && stall_bumped;

        /* Simulate the worker returning: the finish path clears the
         * blocker (exercised directly here; chain_integrity_restore_worker
         * itself calls the same blocker_clear on return). */
        chain_integrity_failed_test_force_running(false);
        blocker_clear("chain_integrity_restore_stuck");
        ok = ok && !blocker_exists("chain_integrity_restore_stuck");

        CIF_CHECK("restore watchdog names+clears a blocker past deadline", ok);
        cleanup_cif(&ms);
    }

    SetDataDir(""); ClearDataDirCache();
    test_rm_rf(cif_datadir);

    return failures;
}
