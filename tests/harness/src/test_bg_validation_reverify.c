/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the always-on SAMPLED re-verify loop that bg_validation enters
 * after the genesis→tip walk completes. We exercise the outcome-recording seam
 * (bg_validation_record_reverify) directly:
 *   - a healthy sample advances reverify_passes and keeps state COMPLETE;
 *   - a planted re-verify FAILURE flips state to FAILED and raises the
 *     PERMANENT `bg_validation.reverify_failed` blocker naming the height.
 * The seam is what the loop calls for every sampled height, so this proves the
 * branch the loop depends on without needing an on-disk historical chain. */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/bn254.h"
#include "sapling/params_vk_embedded.h"
#include "services/bg_validation_authority.h"
#include "services/bg_validation_service.h"
#include "storage/disk_block_io.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char g_fixture_tx_sprout_241[];
extern const size_t g_fixture_tx_sprout_241_len;

/* Sibling-private production helper. It is intentionally absent from the
 * public service header; this group drives the exact background verifier. */
bool bg_validation_verify_shielded_proofs(const struct transaction *tx,
                                          int height, size_t tx_idx,
                                          uint32_t branch_id,
                                          int64_t *proofs_out);

static _Atomic int g_body_read_calls;
static struct bg_validation_service *g_body_repair_svc;
static struct main_state *g_reorg_ms;
static struct block_index *g_reorg_replacement;
static _Atomic bool g_saw_reverify_read;
static int g_restart_progress = 1;
static int64_t g_restart_version = 1;
static struct block_index *g_repair_index;
static struct disk_block_pos g_repair_position;

static int test_bg_validation_owns_datadir(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "bg_validation", "datadir_owner");

    TEST("bg_validation: worker owns the caller's datadir bytes") {
        char caller_path[512];
        snprintf(caller_path, sizeof(caller_path), "%s", dir);
        struct bg_validation_service svc;
        bg_validation_init(&svc, NULL, NULL, caller_path, NULL);
        memset(caller_path, 0xA5, sizeof(caller_path));
        ASSERT(svc.datadir == svc.datadir_storage);
        ASSERT(strcmp(svc.datadir, dir) == 0);

        char oversized[sizeof(svc.datadir_storage) + 1u];
        memset(oversized, 'x', sizeof(oversized) - 1u);
        oversized[sizeof(oversized) - 1u] = '\0';
        bg_validation_init(&svc, NULL, NULL, oversized, NULL);
        ASSERT(svc.datadir == NULL);
        ASSERT(svc.datadir_storage[0] == '\0');
        ASSERT(!bg_validation_start(&svc));
        PASS();
    } _test_next:;
    test_rm_rf(dir);
    return failures;
}

static bool validation_reorgs_then_fails(
    const struct block *block, struct block_index *index, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, int64_t *sigs_out, int64_t *proofs_out,
    int64_t *skips_out)
{
    (void)block;
    (void)index;
    (void)datadir;
    (void)params;
    (void)num_workers;
    (void)max_script_batch;
    *sigs_out = 7;
    *proofs_out = 8;
    *skips_out = 9;
    active_chain_move_window_tip(
        &g_reorg_ms->chain_active, g_reorg_replacement);
    return false;
}

static bool body_read_succeeds_third(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    return atomic_fetch_add(&g_body_read_calls, 1) + 1 >= 3;
}

static bool body_read_never_succeeds(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    atomic_fetch_add(&g_body_read_calls, 1);
    if (atomic_load(&g_body_repair_svc->progress.reverify_active))
        atomic_store(&g_saw_reverify_read, true);
    return false;
}

static bool body_read_reorgs_before_success(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    int call = atomic_fetch_add(&g_body_read_calls, 1) + 1;
    if (call == 1)
        return false;
    if (call == 2)
        active_chain_move_window_tip(
            &g_reorg_ms->chain_active, g_reorg_replacement);
    return true;
}

static void body_repair_no_sleep(int ms) { (void)ms; }

static void body_repair_stop_on_sleep(int ms)
{
    (void)ms;
    atomic_store(&g_body_repair_svc->stop_requested, true);
}

static void body_repair_install_position(int ms)
{
    (void)ms;
    block_index_disk_pos_store(
        g_repair_index, g_repair_position.nFile, g_repair_position.nPos);
    (void)block_index_status_fetch_or(g_repair_index, BLOCK_HAVE_DATA);
}

static bool write_repair_block(
    const char *datadir, struct disk_block_pos *pos, struct uint256 *hash)
{
    struct block block;
    block_init(&block);
    block.header.nVersion = 4;
    block.header.nTime = 1720000000;
    block.header.nBits = 0x2000ffff;
    block.num_vtx = 1;
    block.vtx = calloc(1, sizeof(*block.vtx)); // raw-alloc-ok:test-fixture
    if (!block.vtx)
        return false;
    transaction_init(&block.vtx[0]);
    bool allocated = transaction_alloc(&block.vtx[0], 1, 1);
    if (allocated) {
        block.vtx[0].vin[0].sequence = UINT32_MAX;
        block.vtx[0].vout[0].value = 10 * COIN;
    }
    static const unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    bool written = allocated &&
        write_block_to_disk(&block, pos, datadir, msg_start);
    if (written)
        block_get_hash(&block, hash);
    block_free(&block);
    return written;
}

static struct block_index *make_repair_index(
    struct main_state *ms, struct uint256 *hash)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = 1;
    struct block_index *index =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!index)
        return NULL;
    index->nHeight = 0;
    index->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    index->nFile = 49;
    index->nDataPos = 46754837;
    arith_uint256_set_u64(&index->nChainWork, 1);
    active_chain_move_window_tip(&ms->chain_active, index);
    return index;
}

static struct block_index *make_repair_replacement(
    struct main_state *ms, struct uint256 *hash)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = 2;
    struct block_index *index =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!index)
        return NULL;
    index->nHeight = 0;
    index->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    index->nFile = 50;
    index->nDataPos = 8;
    arith_uint256_set_u64(&index->nChainWork, 2);
    return index;
}

static bool restart_load_progress(void *self, int *out)
{
    (void)self;
    *out = g_restart_progress;
    return true;
}

static bool restart_save_progress(void *self, int height)
{
    (void)self;
    g_restart_progress = height;
    return true;
}

static bool restart_load_i64(void *self, int64_t *out)
{
    (void)self;
    *out = 0;
    return true;
}

static bool restart_load_version(void *self, int64_t *out)
{
    (void)self;
    *out = g_restart_version;
    return true;
}

static bool restart_save_i64(void *self, int64_t value)
{
    (void)self;
    (void)value;
    return true;
}

static bool restart_save_version(void *self, int64_t value)
{
    (void)self;
    g_restart_version = value;
    return true;
}

static struct block_index *extend_repair_chain(
    struct main_state *ms, struct block_index *prev, struct uint256 *hash)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = 3;
    struct block_index *index =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!index)
        return NULL;
    index->nHeight = 1;
    index->pprev = prev;
    index->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    index->nFile = 51;
    index->nDataPos = 8;
    arith_uint256_set_u64(&index->nChainWork, 3);
    active_chain_move_window_tip(&ms->chain_active, index);
    return index;
}

static bool find_reverify_blocker(struct blocker_snapshot *out)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "bg_validation.reverify_failed") == 0) {
            if (out) *out = snaps[i];
            return true;
        }
    }
    return false;
}

static int test_bg_validation_phgr13_verdict_is_terminal(void)
{
    int failures = 0;

    TEST("bg_validation: loaded PHGR13 verifier rejection is terminal") {
        struct byte_stream stream;
        stream_init_from_data(&stream, g_fixture_tx_sprout_241,
                              g_fixture_tx_sprout_241_len);
        struct transaction tx;
        transaction_init(&tx);
        ASSERT(transaction_deserialize(&tx, &stream));
        ASSERT(stream_remaining(&stream) == 0);
        ASSERT(tx.num_joinsplit == 1 && tx.v_joinsplit != NULL);
        ASSERT(!tx.v_joinsplit[0].use_groth);

        const struct zcl_embedded_vk *embedded = &zcl_embedded_vks[3];
        struct ppzksnark_vk vk = {0};
        ASSERT(strcmp(embedded->name, "sprout-phgr") == 0);
        ASSERT(ppzksnark_vk_read(&vk, embedded->bytes, embedded->len));
        sprout_phgr_set_vk(&vk);
        ASSERT(sprout_phgr_vk_loaded());

        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        ASSERT(params != NULL);
        uint32_t branch_id = consensus_current_epoch_branch_id(
            241, &params->consensus);

        int64_t proofs = 0;
        ASSERT(bg_validation_verify_shielded_proofs(
            &tx, 241, 0, branch_id, &proofs));
        ASSERT(proofs == 1);

        /* Keep the signed transaction byte-exact and damage the installed
         * verifier instead. This reaches the PHGR13 false-verdict branch;
         * changing the proof bytes would be rejected earlier by the
         * transaction's JoinSplit signature and would not cover this bug. */
        bn_g1_identity(&vk.ic[0]);
        proofs = 0;
        ASSERT(!bg_validation_verify_shielded_proofs(
            &tx, 241, 0, branch_id, &proofs));
        ASSERT(proofs == 0);

        sprout_phgr_set_vk(NULL);
        ASSERT(!sprout_phgr_vk_loaded());
        proofs = 0;
        ASSERT(bg_validation_verify_shielded_proofs(
            &tx, 241, 0, branch_id, &proofs));
        ASSERT(proofs == 0);

        ppzksnark_vk_free(&vk);
        transaction_free(&tx);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_reverify_healthy_advances(void)
{
    int failures = 0;

    TEST("bg_validation: healthy sampled re-verify advances reverify_passes") {
        blocker_clear("bg_validation.reverify_failed");
        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        atomic_store(&svc.progress.state, BG_VALIDATION_COMPLETE);

        for (int i = 0; i < 5; i++)
            ASSERT(bg_validation_record_reverify(&svc, 1000 + i, true));

        struct bg_validation_progress p = bg_validation_get_progress(&svc);
        ASSERT(p.reverify_passes == 5);
        ASSERT(p.reverify_fails == 0);
        ASSERT(p.reverify_height == 1004);
        /* Healthy re-verify never regresses the COMPLETE state. */
        ASSERT(p.state == BG_VALIDATION_COMPLETE);
        ASSERT(!find_reverify_blocker(NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_reverify_failure_raises_blocker(void)
{
    int failures = 0;

    TEST("bg_validation: planted re-verify FAIL raises PERMANENT blocker") {
        blocker_clear("bg_validation.reverify_failed");
        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        atomic_store(&svc.progress.state, BG_VALIDATION_COMPLETE);

        /* One healthy sample, then a planted failure at a named height. */
        ASSERT(bg_validation_record_reverify(&svc, 2000, true));
        ASSERT(!bg_validation_record_reverify(&svc, 2500, false));

        struct bg_validation_progress p = bg_validation_get_progress(&svc);
        ASSERT(p.reverify_passes == 1);
        ASSERT(p.reverify_fails == 1);
        ASSERT(p.reverify_height == 2500);
        ASSERT(p.state == BG_VALIDATION_FAILED);

        struct blocker_snapshot snap;
        ASSERT(find_reverify_blocker(&snap));
        ASSERT(snap.class == BLOCKER_PERMANENT);
        ASSERT(strstr(snap.reason, "2500") != NULL);

        blocker_clear("bg_validation.reverify_failed");
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_body_repair_retries_exact_height(void)
{
    int failures = 0;

    TEST("bg_validation: unreadable body retries exact height and resumes") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hash;
        struct block_index *expected = make_repair_index(&ms, &hash);
        ASSERT(expected != NULL);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        atomic_store(&svc.progress.state, BG_VALIDATION_RUNNING);
        reducer_frontier_body_read_note_reset_for_testing();
        atomic_store(&g_body_read_calls, 0);
        g_body_repair_svc = &svc;
        bg_validation_test_set_body_repair_stubs(
            body_read_succeeds_third, body_repair_no_sleep);

        struct block block;
        block_init(&block);
        struct block_index *actual = NULL;
        ASSERT(bg_validation_read_body_resilient(
            &svc, 0, "unused", BG_VALIDATION_RUNNING, &block, &actual));
        ASSERT(atomic_load(&g_body_read_calls) == 3);
        ASSERT(actual == expected);
        ASSERT(atomic_load(&svc.progress.state) == BG_VALIDATION_RUNNING);
        ASSERT(!reducer_frontier_body_read_note_active());

        block_free(&block);
        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_body_repair_reads_replacement_bytes(void)
{
    int failures = 0;
    char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "bg_validation", "body_repair");

    TEST("bg_validation: corrupt position resumes on real replacement bytes") {
        struct disk_block_pos good;
        disk_block_pos_init(&good);
        struct uint256 hash;
        ASSERT(write_repair_block(datadir, &good, &hash));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *index = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash);
        ASSERT(index != NULL);
        index->nHeight = 0;
        block_index_disk_pos_store(index, good.nFile, good.nPos + 1);
        (void)block_index_status_fetch_or(
            index, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        active_chain_move_window_tip(&ms.chain_active, index);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        atomic_store(&svc.progress.state, BG_VALIDATION_RUNNING);
        g_repair_index = index;
        g_repair_position = good;
        reducer_frontier_body_read_note_reset_for_testing();
        bg_validation_test_set_body_repair_stubs(
            NULL, body_repair_install_position);

        struct block actual;
        block_init(&actual);
        struct block_index *actual_index = NULL;
        ASSERT(bg_validation_read_body_resilient(
            &svc, 0, datadir, BG_VALIDATION_RUNNING,
            &actual, &actual_index));
        struct uint256 actual_hash;
        block_get_hash(&actual, &actual_hash);
        ASSERT(actual_index == index);
        ASSERT(uint256_eq(&actual_hash, &hash));
        ASSERT(!reducer_frontier_body_read_note_active());

        block_free(&actual);
        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(datadir);
    return failures;
}

static int test_bg_validation_body_repair_stops_responsively(void)
{
    int failures = 0;

    TEST("bg_validation: unreadable body wait is stop-responsive") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hash;
        ASSERT(make_repair_index(&ms, &hash) != NULL);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        g_body_repair_svc = &svc;
        atomic_store(&g_body_read_calls, 0);
        g_restart_progress = 1;
        g_restart_version = 1;
        atomic_store(&g_saw_reverify_read, false);
        reducer_frontier_body_read_note_reset_for_testing();
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        struct block block;
        block_init(&block);
        struct block_index *actual = NULL;
        ASSERT(!bg_validation_read_body_resilient(
            &svc, 0, "unused", BG_VALIDATION_RUNNING, &block, &actual));
        ASSERT(atomic_load(&g_body_read_calls) == 1);
        ASSERT(!atomic_load(&g_saw_reverify_read));
        ASSERT(actual == NULL);
        ASSERT(atomic_load(&svc.progress.state) == BG_VALIDATION_PAUSED);
        ASSERT(reducer_frontier_body_read_note_active());
        ASSERT(reducer_frontier_body_read_note_height() == 0);

        block_free(&block);
        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_legacy_cursor_restarts_walk(void)
{
    int failures = 0;

    TEST("bg_validation: legacy coverage cursor restarts the walk") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h0_hash;
        struct uint256 h1_hash;
        struct block_index *h0 = make_repair_index(&ms, &h0_hash);
        ASSERT(h0 != NULL);
        ASSERT(extend_repair_chain(&ms, h0, &h1_hash) != NULL);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        svc.datadir = "unused";
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = restart_load_progress,
            .save_progress = restart_save_progress,
            .load_skips = restart_load_i64,
            .save_skips = restart_save_i64,
            .load_coverage_version = restart_load_version,
            .save_coverage_version = restart_save_version,
        };
        g_body_repair_svc = &svc;
        atomic_store(&g_body_read_calls, 0);
        g_restart_progress = 1;
        g_restart_version = 0;
        atomic_store(&g_saw_reverify_read, false);
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        ASSERT(bg_validation_start(&svc));
        for (int i = 0; i < 1000 &&
                        atomic_load(&g_body_read_calls) == 0; i++)
            platform_sleep_ms(1);
        ASSERT(atomic_load(&g_body_read_calls) == 1);
        ASSERT(!atomic_load(&g_saw_reverify_read));
        ASSERT(atomic_load(&svc.progress.verified_height) == 0);
        bg_validation_stop(&svc);

        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_body_repair_reproves_reorg(void)
{
    int failures = 0;

    TEST("bg_validation: body repair re-proves active identity after reorg") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 original_hash;
        struct uint256 replacement_hash;
        ASSERT(make_repair_index(&ms, &original_hash) != NULL);
        struct block_index *replacement =
            make_repair_replacement(&ms, &replacement_hash);
        ASSERT(replacement != NULL);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        g_reorg_ms = &ms;
        g_reorg_replacement = replacement;
        atomic_store(&g_body_read_calls, 0);
        reducer_frontier_body_read_note_reset_for_testing();
        bg_validation_test_set_body_repair_stubs(
            body_read_reorgs_before_success, body_repair_no_sleep);

        struct block block;
        block_init(&block);
        struct block_index *actual = NULL;
        ASSERT(bg_validation_read_body_resilient(
            &svc, 0, "unused", BG_VALIDATION_RUNNING, &block, &actual));
        ASSERT(atomic_load(&g_body_read_calls) == 3);
        ASSERT(actual == replacement);
        ASSERT(!reducer_frontier_body_read_note_active());

        block_free(&block);
        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_post_verify_reorg_is_orphan(void)
{
    int failures = 0;

    TEST("bg_validation: post-verify reorg cannot publish orphan outcome") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 original_hash;
        struct uint256 replacement_hash;
        struct block_index *original = make_repair_index(&ms, &original_hash);
        ASSERT(original != NULL);
        struct block_index *replacement =
            make_repair_replacement(&ms, &replacement_hash);
        ASSERT(replacement != NULL);
        g_reorg_ms = &ms;
        g_reorg_replacement = replacement;
        bg_validation_test_set_validate_stub(validation_reorgs_then_fails);

        struct block block;
        block_init(&block);
        int64_t sigs = 0, proofs = 0, skips = 0;
        enum bg_validation_block_outcome outcome =
            bg_validation_validate_canonical_block(
                &ms, 0, &block, original, "unused", NULL, 1, 0,
                &sigs, &proofs, &skips);
        ASSERT(outcome == BG_VALIDATION_BLOCK_ORPHAN);
        ASSERT(sigs == 7 && proofs == 8 && skips == 9);
        ASSERT(active_chain_at(&ms.chain_active, 0) == replacement);

        bg_validation_test_set_validate_stub(NULL);
        block_free(&block);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_restart_keeps_reverify_worker(void)
{
    int failures = 0;

    TEST("bg_validation: current-coverage restart launches sampled worker") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h0_hash;
        struct uint256 h1_hash;
        struct block_index *h0 = make_repair_index(&ms, &h0_hash);
        ASSERT(h0 != NULL);
        ASSERT(extend_repair_chain(&ms, h0, &h1_hash) != NULL);

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        svc.datadir = "unused";
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = restart_load_progress,
            .save_progress = restart_save_progress,
            .load_skips = restart_load_i64,
            .save_skips = restart_save_i64,
            .load_coverage_version = restart_load_version,
            .save_coverage_version = restart_save_version,
        };
        g_body_repair_svc = &svc;
        atomic_store(&g_body_read_calls, 0);
        atomic_store(&g_saw_reverify_read, false);
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        ASSERT(bg_validation_start(&svc));
        for (int i = 0; i < 1000 &&
                        atomic_load(&g_body_read_calls) == 0; i++)
            platform_sleep_ms(1);
        ASSERT(atomic_load(&g_body_read_calls) == 1);
        ASSERT(atomic_load(&g_saw_reverify_read));
        bg_validation_stop(&svc);
        ASSERT(!svc.thread_started);

        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_authority_requires_complete_coverage(void)
{
    int failures = 0;

    TEST("bg_validation: authority claim is exact and fail-closed") {
        ASSERT(bg_validation_authority_claim_is_complete(
            3000, 3000, 3000, 0, true));
        ASSERT(!bg_validation_authority_claim_is_complete(
            2999, 3000, 3000, 0, true));
        ASSERT(!bg_validation_authority_claim_is_complete(
            3000, 3000, 2999, 0, true));
        ASSERT(!bg_validation_authority_claim_is_complete(
            3000, 3000, 3000, 1, true));
        ASSERT(!bg_validation_authority_claim_is_complete(
            3000, 3000, 3000, 0, false));
        ASSERT(!bg_validation_authority_claim_is_complete(
            0, 0, 0, 0, true));
        PASS();
    } _test_next:;
    return failures;
}

int test_bg_validation_reverify(void)
{
    int failures = 0;
    failures += test_bg_validation_owns_datadir();
    failures += test_bg_validation_phgr13_verdict_is_terminal();
    failures += test_bg_validation_reverify_healthy_advances();
    failures += test_bg_validation_reverify_failure_raises_blocker();
    failures += test_bg_validation_body_repair_retries_exact_height();
    failures += test_bg_validation_body_repair_reads_replacement_bytes();
    failures += test_bg_validation_body_repair_stops_responsively();
    failures += test_bg_validation_body_repair_reproves_reorg();
    failures += test_bg_validation_post_verify_reorg_is_orphan();
    failures += test_bg_validation_restart_keeps_reverify_worker();
    failures += test_bg_validation_legacy_cursor_restarts_walk();
    failures += test_bg_validation_authority_requires_complete_coverage();
    return failures;
}
