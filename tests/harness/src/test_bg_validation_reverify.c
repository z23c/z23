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
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "jobs/reducer_frontier.h"
#include "mining/miner.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/bn254.h"
#include "sapling/params_vk_embedded.h"
#include "services/bg_validation_authority.h"
#include "services/bg_validation_service.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
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

/* Sibling-private undo-skip tally + rising-edge seam (same TU as the block
 * verifier). The verifier calls it once per block and LOG_WARNs only when it
 * returns true, so driving it directly is driving the exact suppression
 * decision the log depends on. */
bool bg_validation_note_undo_skips(int64_t skips, bool verified_with_undo,
                                   uint64_t *blocks_out, uint64_t *txs_out);

/* The production entry point the tally hangs off: driving the seam alone
 * cannot see the call being deleted or its have_undo argument flipped. */
bool bg_validation_validate_block_proofs(const struct block *block,
                                         struct block_index *pindex,
                                         const char *datadir,
                                         const struct chain_params *params,
                                         int num_workers,
                                         size_t max_script_batch,
                                         int64_t *sigs_out,
                                         int64_t *proofs_out,
                                         int64_t *skips_out);

static _Atomic int g_body_read_calls;
static pthread_mutex_t g_body_read_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_body_read_cv = PTHREAD_COND_INITIALIZER;
static struct bg_validation_service *g_body_repair_svc;
static struct main_state *g_reorg_ms;
static struct block_index *g_reorg_replacement;
static _Atomic bool g_saw_reverify_read;
static int g_restart_progress = 1;
static int64_t g_restart_version = BG_VALIDATION_COVERAGE_VERSION;
static int64_t g_restart_skips = 0;
static struct block_index *g_repair_index;
static struct disk_block_pos g_repair_position;

static int body_read_count_increment(void)
{
    pthread_mutex_lock(&g_body_read_mu);
    int count = atomic_fetch_add(&g_body_read_calls, 1) + 1;
    pthread_cond_broadcast(&g_body_read_cv);
    pthread_mutex_unlock(&g_body_read_mu);
    return count;
}

static bool body_read_count_wait_at_least(int expected)
{
    struct timespec deadline;
    if (platform_time_realtime_timespec(&deadline) != 0)
        return false;
    deadline.tv_sec += 10;
    pthread_mutex_lock(&g_body_read_mu);
    int wait_rc = 0;
    while (atomic_load(&g_body_read_calls) < expected &&
           wait_rc != ETIMEDOUT)
        wait_rc = pthread_cond_timedwait(
            &g_body_read_cv, &g_body_read_mu, &deadline);
    bool reached = atomic_load(&g_body_read_calls) >= expected;
    pthread_mutex_unlock(&g_body_read_mu);
    return reached;
}

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
    return body_read_count_increment() >= 3;
}

static bool body_read_never_succeeds(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    if (atomic_load(&g_body_repair_svc->progress.reverify_active))
        atomic_store(&g_saw_reverify_read, true);
    (void)body_read_count_increment();
    return false;
}

static bool body_read_reorgs_before_success(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    int call = body_read_count_increment();
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
    *out = g_restart_skips;
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
    g_restart_skips = value;
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
        g_restart_version = BG_VALIDATION_COVERAGE_VERSION;
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

static _Atomic int64_t g_slept_ms;
static _Atomic int g_blocker_sleeps;
static char g_blocker_reason[BLOCKER_REASON_MAX];

static bool find_blocker_by_id(const char *id, struct blocker_snapshot *out)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, id) == 0) {
            if (out) *out = snaps[i];
            return true;
        }
    }
    return false;
}

static int g_body_succeeds_at;

static bool body_read_succeeds_at_configured_call(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    return body_read_count_increment() >= g_body_succeeds_at;
}

static void body_repair_account_sleep(int ms)
{
    struct blocker_snapshot snap;
    atomic_fetch_add(&g_slept_ms, ms);
    if (find_blocker_by_id("bg_validation.body_unreadable", &snap)) {
        atomic_fetch_add(&g_blocker_sleeps, 1);
        snprintf(g_blocker_reason, sizeof(g_blocker_reason), "%s",
                 snap.reason);
    }
}

/* Runs one resilient read whose injected body read succeeds on call
 * `succeeds_at`, returning false when the read, the call count, the 5 s tick
 * total or the report count disagree with the design. */
static bool body_repair_run_backoff_case(
    int succeeds_at, int64_t slept_ms, int blocker_ticks, unsigned reports)
{
    struct main_state ms;
    main_state_init(&ms);
    struct uint256 hash;
    bool ok = make_repair_index(&ms, &hash) != NULL;

    struct bg_validation_service svc;
    memset(&svc, 0, sizeof(svc));
    svc.ms = &ms;
    atomic_store(&svc.progress.state, BG_VALIDATION_RUNNING);
    reducer_frontier_body_read_note_reset_for_testing();
    blocker_clear("bg_validation.body_unreadable");
    atomic_store(&g_body_read_calls, 0);
    atomic_store(&g_slept_ms, 0);
    atomic_store(&g_blocker_sleeps, 0);
    g_blocker_reason[0] = '\0';
    g_body_succeeds_at = succeeds_at;
    g_body_repair_svc = &svc;
    unsigned reports_before = bg_validation_test_body_report_count();
    bg_validation_test_set_body_repair_stubs(
        body_read_succeeds_at_configured_call, body_repair_account_sleep);

    struct block block;
    block_init(&block);
    struct block_index *actual = NULL;
    ok = ok && bg_validation_read_body_resilient(
        &svc, 0, "unused", BG_VALIDATION_RUNNING, &block, &actual);
    /* The read is retried on every 5 s tick: success on call N is noticed
     * after exactly N-1 ticks, however long the failures have run. */
    ok = ok && atomic_load(&g_body_read_calls) == succeeds_at;
    ok = ok && atomic_load(&g_slept_ms) == slept_ms;
    ok = ok && atomic_load(&g_blocker_sleeps) == blocker_ticks;
    ok = ok && bg_validation_test_body_report_count() - reports_before ==
        reports;
    ok = ok && !find_blocker_by_id("bg_validation.body_unreadable", NULL);

    block_free(&block);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    reducer_frontier_body_read_note_reset_for_testing();
    main_state_free(&ms);
    return ok;
}

static int test_bg_validation_body_repair_backs_off_and_names_blocker(void)
{
    int failures = 0;

    TEST("bg_validation: unreadable body is re-read every 5 s; warning and "
         "blocker follow a doubling cadence") {
        /* 19 failures: reports at failures 1, 12 (blocker raised) and 16
         * (interval 20 s). The blocker is up for the 8 waits after failure
         * 12 (8 x 5 ticks) and the total wait is 19 x 5 s. */
        ASSERT(body_repair_run_backoff_case(20, 95000, 40, 3));
        ASSERT(strstr(g_blocker_reason, "h=0") != NULL);
        ASSERT(strstr(g_blocker_reason, "nFile=") != NULL);
        ASSERT(strstr(g_blocker_reason, "nDataPos=") != NULL);
        ASSERT(strstr(g_blocker_reason, "failures=") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_body_repair_notices_body_mid_backoff(void)
{
    int failures = 0;

    TEST("bg_validation: a body that reads mid-backoff is noticed on the "
         "next tick and clears the blocker") {
        /* 13 failures then success: reports at failures 1 and 12, blocker up
         * for the 2 waits after failure 12, 13 x 5 s waited in total. */
        ASSERT(body_repair_run_backoff_case(14, 65000, 10, 2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_body_blocker_cleared_on_coverage_gap(void)
{
    int failures = 0;

    TEST("bg_validation: a coverage gap clears a stale unreadable-body "
         "blocker") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hash;
        ASSERT(make_repair_index(&ms, &hash) != NULL);

        struct blocker_record rec;
        ASSERT(blocker_init(&rec, "bg_validation.body_unreadable",
                            "bg_validation", BLOCKER_TRANSIENT, "stale"));
        ASSERT(blocker_set(&rec) == 0);
        ASSERT(find_blocker_by_id("bg_validation.body_unreadable", NULL));

        struct bg_validation_service svc;
        memset(&svc, 0, sizeof(svc));
        svc.ms = &ms;
        struct block block;
        block_init(&block);
        struct block_index *actual = NULL;
        /* Height 7 has no active block: the walk reports a coverage gap. */
        ASSERT(!bg_validation_read_body_resilient(
            &svc, 7, "unused", BG_VALIDATION_RUNNING, &block, &actual));
        ASSERT(!find_blocker_by_id("bg_validation.body_unreadable", NULL));

        block_free(&block);
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
        ASSERT(body_read_count_wait_at_least(1));
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

/* Wire a two-block walk over the restart stubs, for the census/gate cases. */
static void walk_svc_init(struct bg_validation_service *svc,
                          struct main_state *ms)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->datadir = "unused";
    svc->progress_store = (struct bg_validation_store_port) {
        .self = svc,
        .load_progress = restart_load_progress,
        .save_progress = restart_save_progress,
        .load_skips = restart_load_i64,
        .save_skips = restart_save_i64,
        .load_coverage_version = restart_load_version,
        .save_coverage_version = restart_save_version,
    };
    g_body_repair_svc = svc;
    atomic_store(&g_body_read_calls, 0);
    atomic_store(&g_saw_reverify_read, false);
}

/* A v1 cursor's census counted every self-connected block as a skip (only rev
 * files were consulted); carrying it into the restarted campaign would keep
 * full-history authority unpublishable. */
static int test_bg_validation_v1_cursor_drops_skip_census(void)
{
    int failures = 0;

    TEST("bg_validation: a refused v1 cursor restarts with a zero census") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h0_hash, h1_hash;
        struct block_index *h0 = make_repair_index(&ms, &h0_hash);
        ASSERT(h0 != NULL);
        ASSERT(extend_repair_chain(&ms, h0, &h1_hash) != NULL);
        struct bg_validation_service svc;
        walk_svc_init(&svc, &ms);
        g_restart_progress = 1;
        g_restart_version = 1;
        g_restart_skips = 41;
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        ASSERT(bg_validation_start(&svc));
        ASSERT(body_read_count_wait_at_least(1));
        ASSERT_EQ(atomic_load(&svc.progress.script_verif_skipped_no_undo), 0);
        bg_validation_stop(&svc);
        ASSERT_EQ(g_restart_skips, 0);
        ASSERT_EQ(g_restart_version, BG_VALIDATION_COVERAGE_VERSION);

        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_current_cursor_keeps_census(void)
{
    int failures = 0;

    TEST("bg_validation: a current cursor keeps its skip census") {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h0_hash, h1_hash;
        struct block_index *h0 = make_repair_index(&ms, &h0_hash);
        ASSERT(h0 != NULL);
        ASSERT(extend_repair_chain(&ms, h0, &h1_hash) != NULL);
        struct bg_validation_service svc;
        walk_svc_init(&svc, &ms);
        g_restart_progress = 1;
        g_restart_version = BG_VALIDATION_COVERAGE_VERSION;
        g_restart_skips = 41;
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        ASSERT(bg_validation_start(&svc));
        ASSERT(body_read_count_wait_at_least(1));
        ASSERT_EQ(atomic_load(&svc.progress.script_verif_skipped_no_undo), 41);
        bg_validation_stop(&svc);

        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        g_restart_skips = 0;
        PASS();
    } _test_next:;
    return failures;
}

static bool set_utxo_apply_cursor(int next)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
             "VALUES('utxo_apply', %d, 1)", next);
    progress_store_tx_lock();
    bool ok = sqlite3_exec(progress_store_db(), sql, NULL, NULL, NULL) ==
              SQLITE_OK;
    progress_store_tx_unlock();
    return ok;
}

/* The undo of a self-connected block is the delta row utxo_apply commits
 * with its cursor. Verifying a height the fold has not applied would book a
 * transient absence as a permanent skip, so the walk must hold there. */
static int test_bg_validation_walk_waits_for_fold(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "bg_validation", "fold_gate");
    bool store_open = false;

    TEST("bg_validation: the walk never verifies ahead of the fold") {
        ASSERT(progress_store_open(dir));
        store_open = true;
        ASSERT(set_utxo_apply_cursor(1));
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h0_hash, h1_hash;
        struct block_index *h0 = make_repair_index(&ms, &h0_hash);
        ASSERT(h0 != NULL);
        ASSERT(extend_repair_chain(&ms, h0, &h1_hash) != NULL);
        struct bg_validation_service svc;
        walk_svc_init(&svc, &ms);
        g_restart_progress = -1;
        g_restart_version = BG_VALIDATION_COVERAGE_VERSION;
        g_restart_skips = 0;
        bg_validation_test_set_body_repair_stubs(
            body_read_never_succeeds, body_repair_stop_on_sleep);

        ASSERT(bg_validation_start(&svc));
        platform_sleep_ms(1500);
        int held_reads = atomic_load(&g_body_read_calls);
        bool advanced = set_utxo_apply_cursor(2) &&
                        body_read_count_wait_at_least(1);
        bg_validation_stop(&svc);
        bg_validation_test_set_body_repair_stubs(NULL, NULL);
        reducer_frontier_body_read_note_reset_for_testing();
        main_state_free(&ms);
        g_restart_progress = 1;
        ASSERT_EQ(held_reads, 0);
        ASSERT(advanced);
        PASS();
    } _test_next:;
    if (store_open)
        progress_store_close();
    (void)test_rm_rf_recursive(dir);
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
        ASSERT(body_read_count_wait_at_least(1));
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

/* Seeded-node fixture: heights 1 and 2 lack BLOCK_HAVE_DATA (history below the
 * snapshot base, absent by design); height 3 is held. The rng tape draws the
 * absent heights first, so a sampler that reads them is caught at once. */
#define ABSENT_FIXTURE_TIP 3

static _Atomic uint64_t g_tape_next;
static _Atomic int g_read_heights_mask;
static _Atomic int g_read_succeeds;
static _Atomic int g_sleep_calls;

static uint64_t tape_u64(void *user)
{
    (void)user;
    return atomic_fetch_add(&g_tape_next, 1);
}

static bool body_read_records_height(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)datadir;
    atomic_fetch_or(&g_read_heights_mask, 1 << index->nHeight);
    (void)body_read_count_increment();
    return atomic_load(&g_read_succeeds);
}

static void body_repair_count_and_stop(int ms)
{
    atomic_fetch_add(&g_sleep_calls, 1);
    body_repair_stop_on_sleep(ms);
}

static bool validate_stub_passes(
    const struct block *block, struct block_index *index, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, int64_t *sigs_out, int64_t *proofs_out,
    int64_t *skips_out)
{
    (void)block; (void)index; (void)datadir; (void)params;
    (void)num_workers; (void)max_script_batch;
    *sigs_out = *proofs_out = *skips_out = 0;
    return true;
}

static bool absent_fixture_chain(struct main_state *ms, bool all_held)
{
    struct uint256 hash;
    struct block_index *prev = make_repair_index(ms, &hash);
    for (int h = 1; prev && h <= ABSENT_FIXTURE_TIP; h++) {
        memset(&hash, 0, sizeof(hash));
        hash.data[0] = 0x40;
        hash.data[1] = (unsigned char)h;
        struct block_index *index =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!index)
            return false;
        index->nHeight = h;
        index->pprev = prev;
        index->nStatus = BLOCK_VALID_SCRIPTS |
            (all_held || h == ABSENT_FIXTURE_TIP ? BLOCK_HAVE_DATA : 0);
        index->nFile = 51;
        index->nDataPos = 8;
        arith_uint256_set_u64(&index->nChainWork, 10 + h);
        active_chain_move_window_tip(&ms->chain_active, index);
        prev = index;
    }
    return prev != NULL;
}

/* Runs the sampler once over the fixture until the first body read, stops it,
 * and leaves the service for the caller to inspect. */
static bool absent_fixture_run(struct bg_validation_service *svc,
                               struct main_state *ms, bool read_ok,
                               bool all_held)
{
    main_state_init(ms);
    if (!absent_fixture_chain(ms, all_held))
        return false;
    walk_svc_init(svc, ms);
    g_restart_progress = ABSENT_FIXTURE_TIP;
    atomic_store(&g_tape_next, 0);
    atomic_store(&g_read_heights_mask, 0);
    atomic_store(&g_read_succeeds, read_ok);
    atomic_store(&g_sleep_calls, 0);
    static struct platform_rng_source tape = { .u64 = tape_u64 };
    platform_rng_set_source(&tape);
    bg_validation_test_set_validate_stub(validate_stub_passes);
    bg_validation_test_set_body_repair_stubs(body_read_records_height,
                                             body_repair_count_and_stop);
    bool ok = bg_validation_start(svc) && body_read_count_wait_at_least(1);
    for (int i = 0; ok && !read_ok && i < 1000 &&
                    atomic_load(&g_sleep_calls) == 0; i++)
        platform_sleep_ms(10);
    bg_validation_stop(svc);
    platform_rng_clear_source();
    bg_validation_test_set_validate_stub(NULL);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    reducer_frontier_body_read_note_reset_for_testing();
    g_restart_progress = 1;
    return ok;
}

static int test_bg_validation_reverify_skips_absent_by_design(void)
{
    int failures = 0;

    TEST("bg_validation: sampler skips heights with no body by design") {
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(absent_fixture_run(&svc, &ms, true, false));
        ASSERT_EQ(atomic_load(&g_read_heights_mask), 1 << 3);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_skipped_no_data), 2);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_passes), 1);
        ASSERT_EQ(atomic_load(&svc.progress.reverify_height), 3);
        ASSERT_EQ(atomic_load(&g_sleep_calls), 0);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_reverify_held_unreadable_still_repairs(void)
{
    int failures = 0;

    TEST("bg_validation: a held but unreadable sampled body takes the repair "
         "path") {
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(absent_fixture_run(&svc, &ms, false, false));
        ASSERT_EQ(atomic_load(&g_read_heights_mask), 1 << 3);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_skipped_no_data), 2);
        ASSERT_EQ(atomic_load(&g_sleep_calls), 1);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_passes), 0);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

/* The history floor bounds the draw: every height 1..3 holds data, the seed
 * floor is 2, and the tape's first draw would pick height 1 without it. */
static int test_bg_validation_reverify_draws_above_seed_floor(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "bg_validation", "seed_floor");
    bool store_open = false;

    TEST("bg_validation: sampler never draws at or below the seed floor") {
        ASSERT(progress_store_open(dir));
        store_open = true;
        progress_store_tx_lock();
        bool declared = reducer_seed_floor_declare_if_absent(
            progress_store_db(), 2);
        progress_store_tx_unlock();
        ASSERT(declared);
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(absent_fixture_run(&svc, &ms, true, true));
        ASSERT_EQ(atomic_load(&g_read_heights_mask), 1 << 3);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_skipped_no_data), 0);
        ASSERT_EQ((int)atomic_load(&svc.progress.reverify_passes), 1);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    if (store_open)
        progress_store_close();
    test_rm_rf(dir);
    return failures;
}

static bool body_read_always_succeeds(
    struct block *block, const struct block_index *index, const char *datadir)
{
    (void)block;
    (void)index;
    (void)datadir;
    return true;
}

static int64_t g_catchup_stub_skips;
static bool g_catchup_stub_verdict;

static bool catchup_validate_stub(
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
    *sigs_out = 3;
    *proofs_out = 4;
    *skips_out = g_catchup_stub_skips;
    return g_catchup_stub_verdict;
}

/* Runs one catch-up round over a one-block gap (verified=0, tip=1) with the
 * body read and the full validation stubbed at the walk's own seams, so the
 * REAL walk step, bookkeeping and progress save are what is exercised. */
static bool catchup_one_block(int64_t stub_skips, bool stub_verdict,
                              struct bg_validation_service *svc,
                              struct main_state *ms)
{
    main_state_init(ms);
    struct uint256 h0_hash, h1_hash;
    struct block_index *h0 = make_repair_index(ms, &h0_hash);
    if (!h0 || !extend_repair_chain(ms, h0, &h1_hash))
        return false;
    walk_svc_init(svc, ms);
    atomic_store(&svc->progress.verified_height, 0);
    atomic_store(&svc->progress.chain_height, 0);
    atomic_store(&svc->progress.state, BG_VALIDATION_COMPLETE);
    g_restart_progress = 0;
    g_catchup_stub_skips = stub_skips;
    g_catchup_stub_verdict = stub_verdict;
    bg_validation_test_set_body_repair_stubs(body_read_always_succeeds,
                                             body_repair_no_sleep);
    bg_validation_test_set_validate_stub(catchup_validate_stub);
    bool reached = bg_validation_test_catch_up_round(svc, 1, "unused", NULL, 1);
    bg_validation_test_set_validate_stub(NULL);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    reducer_frontier_body_read_note_reset_for_testing();
    return reached;
}

static int test_bg_validation_catchup_verifies_new_tip_block(void)
{
    int failures = 0;

    TEST("bg_validation: tip moved past the walk is caught up and verified") {
        ASSERT(bg_validation_authority_catchup_wanted(1, 2, 0, true));
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(catchup_one_block(0, true, &svc, &ms));
        ASSERT_EQ(atomic_load(&svc.progress.verified_height), 1);
        ASSERT_EQ(g_restart_progress, 1);
        ASSERT_EQ((int)atomic_load(&svc.progress.sigs_verified), 3);
        ASSERT_EQ((int)atomic_load(
                      &svc.progress.script_verif_skipped_no_undo), 0);
        ASSERT(bg_validation_authority_walk_is_complete(1, 1, 0, true));
        /* status readers need chain_height to follow verified and the
         * state to stay COMPLETE, not flip back to RUNNING. */
        ASSERT(bg_validation_authority_walk_is_complete(
            atomic_load(&svc.progress.verified_height),
            atomic_load(&svc.progress.chain_height), 0, true));
        ASSERT_EQ(atomic_load(&svc.progress.state), BG_VALIDATION_COMPLETE);
        main_state_free(&ms);
        g_restart_progress = 1;
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_catchup_never_forgives_skips_or_gaps(void)
{
    int failures = 0;

    TEST("bg_validation: skips or a coverage gap are never caught up") {
        /* The decision helper: only complete coverage, zero skips, a
         * started walk and verified strictly below the tip qualify. */
        ASSERT(bg_validation_authority_catchup_wanted(10, 11, 0, true));
        ASSERT(!bg_validation_authority_catchup_wanted(10, 11, 1, true));
        ASSERT(!bg_validation_authority_catchup_wanted(10, 11, 0, false));
        ASSERT(!bg_validation_authority_catchup_wanted(10, 10, 0, true));
        ASSERT(!bg_validation_authority_catchup_wanted(11, 10, 0, true));
        ASSERT(!bg_validation_authority_catchup_wanted(0, 10, 0, true));
        ASSERT(!bg_validation_authority_catchup_wanted(-1, 10, 0, true));

        /* A caught-up block that books a skip leaves the claim refused no
         * matter how many rounds ran. */
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(catchup_one_block(2, true, &svc, &ms));
        int64_t skips = atomic_load(
            &svc.progress.script_verif_skipped_no_undo);
        ASSERT_EQ((int)skips, 2);
        ASSERT(!bg_validation_authority_catchup_wanted(1, 2, skips, true));
        ASSERT(!bg_validation_authority_walk_is_complete(1, 1, skips, true));
        main_state_free(&ms);
        g_restart_progress = 1;
        PASS();
    } _test_next:;
    return failures;
}

static int test_bg_validation_catchup_block_failure_stays_unverified(void)
{
    int failures = 0;

    TEST("bg_validation: a catch-up block that fails leaves it unverified") {
        struct bg_validation_service svc;
        struct main_state ms;
        ASSERT(!catchup_one_block(0, false, &svc, &ms));
        ASSERT_EQ(atomic_load(&svc.progress.verified_height), 0);
        ASSERT_EQ(g_restart_progress, 0);
        ASSERT_EQ((int)atomic_load(&svc.progress.state),
                  (int)BG_VALIDATION_FAILED);
        ASSERT(!bg_validation_authority_walk_is_complete(0, 1, 0, true));
        main_state_free(&ms);
        g_restart_progress = 1;
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

/* N consecutive undo-missing blocks produce exactly ONE warn-worthy rising
 * edge. Tallies still count every block and skipped tx; an unbroken RUN of
 * blocks that re-verified against undo clears the streak, while an
 * interleaved gap (one present block per missing one) must not. */
static int test_bg_validation_undo_skip_warns_once_per_streak(void)
{
    int failures = 0;

    TEST("bg_validation: undo-missing skips warn on the rising edge only") {
        bg_validation_reset_undo_skip_stats();

        const int kBlocks = 500;
        int edges = 0;
        for (int i = 0; i < kBlocks; i++) {
            uint64_t blocks = 0, txs = 0;
            if (bg_validation_note_undo_skips(3, false, &blocks, &txs))
                edges++;
        }
        ASSERT(edges == 1);

        struct bg_validation_undo_skip_stats st =
            bg_validation_get_undo_skip_stats();
        ASSERT(st.blocks == (uint64_t)kBlocks);
        ASSERT(st.txs == (uint64_t)kBlocks * 3);
        ASSERT(st.streak_active);

        /* A coinbase-only / undo-less block does NOT clear the streak. */
        uint64_t b = 0, t = 0;
        ASSERT(!bg_validation_note_undo_skips(0, false, &b, &t));
        st = bg_validation_get_undo_skip_stats();
        ASSERT(st.streak_active);

        /* Neither does ONE block that verified against undo: a real gap
         * interleaves missing and present blocks. */
        ASSERT(!bg_validation_note_undo_skips(0, true, &b, &t));
        st = bg_validation_get_undo_skip_stats();
        ASSERT(st.streak_active);

        /* An UNBROKEN RUN of them does (threshold
         * UNDO_SKIP_STREAK_CLEAR_RUN in bg_validation_verify_block.c). */
        for (int i = 0; i < 128; i++)
            ASSERT(!bg_validation_note_undo_skips(0, true, &b, &t));
        st = bg_validation_get_undo_skip_stats();
        ASSERT(!st.streak_active);

        /* A later recurrence re-announces, and the tallies keep running. */
        ASSERT(bg_validation_note_undo_skips(2, false, &b, &t));
        ASSERT(b == (uint64_t)kBlocks + 1);
        ASSERT(t == (uint64_t)kBlocks * 3 + 2);
        ASSERT(!bg_validation_note_undo_skips(2, false, &b, &t));

        st = bg_validation_get_undo_skip_stats();
        ASSERT(st.blocks == (uint64_t)kBlocks + 2);
        ASSERT(st.txs == (uint64_t)kBlocks * 3 + 4);

        /* Interleaved gap (sub-floor sampler, scattered TOPUP_UNDO_CLEARED
         * rows): one present block per missing block must still yield exactly
         * ONE rising edge. */
        bg_validation_reset_undo_skip_stats();
        edges = 0;
        for (int i = 0; i < 1000; i++) {
            uint64_t ib = 0, it = 0;
            bool present = (i % 2) != 0;
            if (bg_validation_note_undo_skips(present ? 0 : 3, present,
                                              &ib, &it))
                edges++;
        }
        ASSERT(edges == 1);
        st = bg_validation_get_undo_skip_stats();
        ASSERT(st.streak_active);
        ASSERT(st.blocks == (uint64_t)500);

        /* Reset zeroes the tallies and re-arms the announcement. */
        bg_validation_reset_undo_skip_stats();
        st = bg_validation_get_undo_skip_stats();
        ASSERT(st.blocks == 0 && st.txs == 0 && !st.streak_active);
        ASSERT(bg_validation_note_undo_skips(1, false, &b, &t));
        bg_validation_reset_undo_skip_stats();
        PASS();
    } _test_next:;
    return failures;
}

/* Build a MINED regtest block: a coinbase plus one ordinary transparent spend,
 * whose input scripts cannot be re-checked without the block's undo record.
 * write_repair_block() cannot serve: it is coinbase-only with no Equihash
 * solution, and the verifier runs check_block_header(pow=true) first. Regtest
 * is (48,5); check_block() runs with check_size_limits=false, so only the
 * header PoW and merkle root must be genuine. */
static bool undoless_block_build(struct block *blk, int height,
                                 const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = calloc(2, sizeof(*blk->vtx)); // raw-alloc-ok:test-fixture
    if (!blk->vtx)
        return false;
    blk->num_vtx = 2;
    for (size_t i = 0; i < 2; i++) {
        transaction_init(&blk->vtx[i]);
        if (!transaction_alloc(&blk->vtx[i], 1, 1))
            return false;
        blk->vtx[i].vin[0].sequence = UINT32_MAX;
        blk->vtx[i].vout[0].value = 1000;
    }
    /* vtx[0] is the coinbase (null prevout); vtx[1] names a real outpoint,
     * so the verifier must reach for undo to recover what it spent. */
    outpoint_set_null(&blk->vtx[0].vin[0].prevout);
    memset(blk->vtx[1].vin[0].prevout.hash.data, 0x5a, 32);
    blk->vtx[1].vin[0].prevout.n = 0;
    transaction_compute_hash(&blk->vtx[0]);
    transaction_compute_hash(&blk->vtx[1]);

    struct uint256 txids[2] = { blk->vtx[0].hash, blk->vtx[1].hash };
    blk->header.nVersion = 4;
    blk->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    uint256_set_null(&blk->header.hashPrevBlock);
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)height;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return mine_block_pow(blk, height, cp, 0);
}

/* Pin the CALL SITE, not just the seam: deleting the
 * bg_validation_validate_block_proofs skip report, or passing it `true` for
 * have_undo, would leave every direct-seam assertion passing. */
static int test_bg_validation_undo_skip_tally_is_wired(void)
{
    int failures = 0;

    TEST("bg_validation: a real undo-less block moves the process tally") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bg_validation", "undoless");
        chain_params_select(CHAIN_REGTEST);
        const struct chain_params *cp = chain_params_get();
        ASSERT(cp != NULL);

        struct main_state ms;
        main_state_init(&ms);
        struct block blk;
        ASSERT(undoless_block_build(&blk, 1, cp));

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        struct block_index *index =
            chainstate_insert_block_index((struct chainstate *)&ms, &hash);
        ASSERT(index != NULL);
        index->nHeight = 1;
        /* HAVE_DATA with no HAVE_UNDO (header-only-import shape); no rev file. */
        index->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        index->nFile = 0;
        index->nDataPos = 8;

        bg_validation_reset_undo_skip_stats();
        int64_t sigs = 0, proofs = 0, skips = 0;
        ASSERT(bg_validation_validate_block_proofs(&blk, index, dir, cp, 1, 0,
                                                   &sigs, &proofs, &skips));
        /* The block advanced, and it advanced with one tx unverified. */
        ASSERT(skips == 1);
        ASSERT(sigs == 0);

        struct bg_validation_undo_skip_stats st =
            bg_validation_get_undo_skip_stats();
        ASSERT(st.blocks == 1);
        ASSERT(st.txs == 1);
        ASSERT(st.streak_active);

        bg_validation_reset_undo_skip_stats();
        block_free(&blk);
        main_state_free(&ms);
        chain_params_select(CHAIN_MAIN);
        PASS();
    } _test_next:;
    return failures;
}

int test_bg_validation_reverify(void)
{
    int failures = 0;
    failures += test_bg_validation_undo_skip_warns_once_per_streak();
    failures += test_bg_validation_undo_skip_tally_is_wired();
    failures += test_bg_validation_owns_datadir();
    failures += test_bg_validation_phgr13_verdict_is_terminal();
    failures += test_bg_validation_reverify_healthy_advances();
    failures += test_bg_validation_reverify_failure_raises_blocker();
    failures += test_bg_validation_body_repair_retries_exact_height();
    failures += test_bg_validation_body_repair_reads_replacement_bytes();
    failures += test_bg_validation_body_repair_stops_responsively();
    failures += test_bg_validation_body_repair_backs_off_and_names_blocker();
    failures += test_bg_validation_body_repair_notices_body_mid_backoff();
    failures += test_bg_validation_body_blocker_cleared_on_coverage_gap();
    failures += test_bg_validation_body_repair_reproves_reorg();
    failures += test_bg_validation_post_verify_reorg_is_orphan();
    failures += test_bg_validation_restart_keeps_reverify_worker();
    failures += test_bg_validation_reverify_skips_absent_by_design();
    failures += test_bg_validation_reverify_held_unreadable_still_repairs();
    failures += test_bg_validation_reverify_draws_above_seed_floor();
    failures += test_bg_validation_legacy_cursor_restarts_walk();
    failures += test_bg_validation_v1_cursor_drops_skip_census();
    failures += test_bg_validation_current_cursor_keeps_census();
    failures += test_bg_validation_walk_waits_for_fold();
    failures += test_bg_validation_authority_requires_complete_coverage();
    failures += test_bg_validation_catchup_verifies_new_tip_block();
    failures += test_bg_validation_catchup_never_forgives_skips_or_gaps();
    failures += test_bg_validation_catchup_block_failure_stays_unverified();
    return failures;
}
