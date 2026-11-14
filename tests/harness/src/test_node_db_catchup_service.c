/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "base/result.h"
#include "jobs/node_pace.h"
#include "services/node_db_catchup_service.h"
#include "services/node_db_catchup_wallet_replay.h"
#include "config/boot_wallet_cutover_replay.h"
#include "config/boot_wallet_cutover_publish.h"
#include "config/boot.h"
#include "util/thread_registry.h"
#include "config/boot_internal.h"
#include "../../../engine/composition/src/boot_cutover_startup_internal.h"
#include "services/wallet_private_relay.h"
#include "storage/coins_kv.h"
#include "storage/coins_kv_read_snapshot.h"
#include "storage/shielded_pool_kv.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_lock.h"
#include "services/node_db_catchup_wallet_transparent.h"
#include "services/node_db_catchup_wallet_transparent_startup.h"
#include "controllers/wallet_rescan_controller_internal.h"
#include "../../../engine/services/src/node_db_catchup_internal.h"
#include "sapling/note_encryption.h"
#include "sapling/sapling.h"
#include "support/cleanse.h"
#include "sha3/sha3.h"
#ifndef _WIN32
#include <sys/wait.h>
#include <signal.h>
#include "platform/os_proc.h"
#endif
#if defined(ZCL_TESTING) && !defined(_WIN32)
struct node_db;
void node_db_sapling_replay_test_crash_before_delivery(void);
void node_db_sapling_replay_test_rollback(struct node_db *db);
void node_db_sapling_replay_test_after_read(void (*hook)(void *), void *ctx);
void node_db_sapling_replay_test_after_keys(void (*hook)(void *), void *ctx);
void node_db_catchup_parallel_test_faults(bool init, bool run);
bool node_db_catchup_parallel_test_run_failed(void);
void node_db_catchup_parallel_test_workers(int count);
void node_db_catchup_parallel_test_signal(bool signal);
size_t node_db_catchup_parallel_test_selected(void);
int node_db_catchup_parallel_test_worker_count(const struct catchup_parallel_state *state);
void node_db_sapling_replay_test_revalidate_hooks(void (*before)(void *), void (*after)(void *), void *ctx);
bool boot_test_pending_busy_backoff(int64_t *since, int64_t deadline, int limit_ms);
int boot_test_pending_busy_at(int64_t *since, int64_t deadline, int limit_ms,
    int64_t now, bool locked, bool shutdown);
enum boot_pending_replay_result boot_test_pending_loop(struct boot_cutover_replay *replay);
void boot_test_pending_step_hook(void (*hook)(void));
void boot_cutover_replay_test_after_current(void (*hook)(void *), void *ctx);
void boot_cutover_replay_test_before_postcheck(void (*hook)(void *), void *ctx);
#endif
#include "wallet/wallet.h"
#include "services/node_db_catchup_lock_guard.h"
#include "services/db_maintenance.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "platform/time_compat.h"
#include "models/database.h"
#include "models/ar_after_commit.h"
struct zcl_result node_db_sapling_replay_test_flush_batch(struct node_db *db);
#include "models/block.h"
#include "models/explorer_index.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
extern bool rpc_z_importkey(const struct json_value *params, bool help, struct json_value *result);
extern void wallet_readiness_append_scan(struct json_value *result);
extern void wallet_rescan_test_before_clear(void (*hook)(void *), void *context);
#include "util/blocker.h"
#include "util/util.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "storage/wallet_projection.h"
#include "storage/event_log.h"
#include "models/wallet_tx.h"
#include "sapling/incremental_merkle_tree.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include <sqlite3.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define NDC_CHECK(name, expr) do { \
    printf("node_db_catchup_service: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Arguments for the one catchup run whose stderr is captured, so the
 * capture helper below can stay a plain void(void) thunk. */
static struct node_db          *g_cap_ndb;
static const struct active_chain *g_cap_chain;
static const char              *g_cap_datadir;
static int                      g_cap_result;

static void ndc_run_catchup_capture(void)
{
    g_cap_result = node_db_catchup_service_run(
        g_cap_ndb, g_cap_chain, NULL, g_cap_datadir);
}

/* Redirect stderr to a scratch file for the duration of `fn`, then hand
 * back what landed in it. Mirrors log_level_capture() in
 * test_log_level.c. Returns false when the plumbing itself failed —
 * callers treat that as a real FAIL, because the captured text is what is
 * under test. */
static bool ndc_capture_stderr(void (*fn)(void), char *out, size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/ndc_catchup_stderr_%d.log",
             (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        return false;
    }
    dup2(fileno(capf), STDERR_FILENO);

    fn();

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out && out_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t want = (size_t)sz < out_len - 1 ? (size_t)sz : out_len - 1;
            size_t got = fread(out, 1, want, capf);
            out[got] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return true;
}

struct ndc_map_probe {
    size_t sz;
    int err;
    void *mapping;
    const uint8_t *data;
};

static int ndc_check_missing_and_empty_block_files(char *dir, size_t dir_len,
                                                   char *blocks,
                                                   size_t blocks_len,
                                                   struct ndc_map_probe *p)
{
    int failures = 0;

    test_make_tmpdir(dir, dir_len, "node_db_catchup", "mmap");
    snprintf(blocks, blocks_len, "%s/blocks", dir);
    mkdir(blocks, 0755);

    p->sz = 99;
    p->err = 0;
    p->mapping = NULL;
    p->data = NULL;
    bool opened = node_db_catchup_test_block_mapping_open(
        dir, 7, &p->mapping, &p->data, &p->sz, &p->err);
    NDC_CHECK("missing block file is quiet ENOENT",
              !opened && p->mapping == NULL && p->data == NULL &&
              p->sz == 0 && p->err == ENOENT);

    char path[512];
    snprintf(path, sizeof(path), "%s/blk00008.dat", blocks);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
    p->sz = 99;
    p->err = 0;
    opened = node_db_catchup_test_block_mapping_open(
        dir, 8, &p->mapping, &p->data, &p->sz, &p->err);
    NDC_CHECK("empty block file is quiet EINVAL",
              !opened && p->mapping == NULL && p->data == NULL &&
              p->sz == 0 && p->err == EINVAL);
    return failures;
}

static int ndc_check_valid_block_file_maps(const char *dir, const char *blocks,
                                           struct ndc_map_probe *p)
{
    int failures = 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/blk00009.dat", blocks);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    const uint8_t bytes[] = {0xde, 0xad, 0xbe, 0xef};
    bool wrote = fd >= 0 &&
        write(fd, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes);
    if (fd >= 0) close(fd);
    p->sz = 0;
    p->err = 0;
    bool opened = node_db_catchup_test_block_mapping_open(
        dir, 9, &p->mapping, &p->data, &p->sz, &p->err);
    bool mapped = wrote && opened && p->mapping != NULL && p->data != NULL &&
                  p->sz == sizeof(bytes) && p->err == 0 &&
                  memcmp(p->data, bytes, sizeof(bytes)) == 0;
    node_db_catchup_test_block_mapping_close(p->mapping);
    NDC_CHECK("valid block file maps", mapped);
    return failures;
}

static int ndc_check_tail_fold_and_sparse_prefix(void)
{
    int failures = 0;

    NDC_CHECK("header target defers catchup for a two-block canonical gap",
              node_db_catchup_tail_fold_in_progress(102, 100));
    NDC_CHECK("header target defers catchup across a sparse active chain",
              node_db_catchup_tail_fold_in_progress(1000000, 7));
    NDC_CHECK("normal one-block live edge remains eligible",
              !node_db_catchup_tail_fold_in_progress(101, 100));
    NDC_CHECK("equal frontiers remain eligible",
              !node_db_catchup_tail_fold_in_progress(100, 100));
    NDC_CHECK("unknown header target does not invent a fold",
              !node_db_catchup_tail_fold_in_progress(-1, 100));
    NDC_CHECK("unknown H-star does not invent a fold",
              !node_db_catchup_tail_fold_in_progress(100, -1));

    NDC_CHECK("sparse proven prefix may advance projection cursor",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 0, -1, true, 2) == 2);
    NDC_CHECK("sparse prefix requires proven coins authority",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 0, -1, false, 2) == -1);
    NDC_CHECK("sparse prefix requires authority covering tip",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 0, -1, true, 1) == -1);
    NDC_CHECK("sparse prefix allows quiet missing body files",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 0, -1, true, 2) == 2);
    NDC_CHECK("sparse prefix refuses suspicious holes",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 1, 0, -1, true, 2) == -1);
    NDC_CHECK("sparse prefix stops before an interior missing active slot",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 1, 1, true, 2) == 0);
    NDC_CHECK("sparse prefix must cover the whole range",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 2, 0, 0, 2, 0, 0, -1, true, 2) == -1);
    NDC_CHECK("sparse prefix stops before a trailing missing active slot",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 1, 2, true, 2) == 1);
    NDC_CHECK("sparse prefix refuses a missing first active slot",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 1, 0, true, 2) == -1);
    NDC_CHECK("sparse prefix target remains bounded by proven authority",
              node_db_catchup_test_sparse_prefix_target(
                  0, 3, 3, 0, 0, 2, 0, 1, 2, true, 0) == -1);
    NDC_CHECK("sparse watcher waits for the sole missing tip slot",
              node_db_catchup_sparse_tip_slot_pending(true, 1, 2, false));
    NDC_CHECK("sparse watcher resumes once the tip slot resolves",
              !node_db_catchup_sparse_tip_slot_pending(true, 1, 2, true));
    NDC_CHECK("ordinary projections never enter sparse tip wait",
              !node_db_catchup_sparse_tip_slot_pending(false, 1, 2, false));
    /* Two-or-more missing TOP slots (chain_tip=3, projection_tip=1): a
     * fresh pass would publish the same projection_tip, so the watcher
     * suppresses the restart as for a single missing slot. */
    NDC_CHECK("sparse watcher waits when two-or-more top slots are missing",
              node_db_catchup_sparse_tip_slot_pending(true, 1, 3, false));
    /* Missing slot strictly interior while the next-needed slot IS present:
     * a fresh pass makes real progress, so the watcher allows the restart. */
    NDC_CHECK("sparse watcher allows restart when the next slot is present "
              "despite an interior hole",
              !node_db_catchup_sparse_tip_slot_pending(true, 1, 5, true));
    return failures;
}

/* A torn index can carry BLOCK_HAVE_DATA with a NULL phashBlock; that
 * must fail-closed with a named log, never SIGSEGV in sync_block_lean. */
static int ndc_check_hashless_sync_block_lean(void)
{
    int failures = 0;
    struct node_db ndb;
    bool opened = node_db_open(&ndb, ":memory:");
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.num_vtx = 1;
    blk.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (blk.vtx) {
        transaction_init(&blk.vtx[0]);
        transaction_alloc(&blk.vtx[0], 1, 1);
    }
    struct block_index torn;
    memset(&torn, 0, sizeof(torn));
    torn.nHeight = 1;
    torn.nStatus = BLOCK_HAVE_DATA;
    torn.phashBlock = NULL;
    bool guarded = opened && blk.vtx &&
        !node_db_catchup_test_sync_block_lean(&ndb, &blk, &torn);
    NDC_CHECK("sync_block_lean fails closed on a hash-less block index",
              guarded);
    block_free(&blk);
    if (opened) node_db_close(&ndb);
    return failures;
}

struct ndc_torn_walk {
    char dir2[256];
    struct uint256 block_hash;
    struct block_index torn;
    struct active_chain ac;
    struct node_db ndb;
    bool wrote;
    bool installed;
    bool opened;
};

/* Drive the full walk against a torn projection: a decodable block
 * reached through an active-chain slot whose phashBlock is NULL, with a
 * missing lower slot. The run must complete with a named lean-hole
 * outcome, never crash, never advance the tip onto that slot. */
static int ndc_torn_walk_first_pass(struct ndc_torn_walk *w)
{
    int failures = 0;
    test_make_tmpdir(w->dir2, sizeof(w->dir2), "node_db_catchup", "torn_walk");
    char blocks2[512];
    snprintf(blocks2, sizeof(blocks2), "%s/blocks", w->dir2);
    mkdir(blocks2, 0755);

    struct block b;
    block_init(&b);
    b.header.nVersion = 4;
    b.header.nTime = 1700000123u;
    b.header.nBits = 0x2000ffffu;
    b.header.hashPrevBlock.data[0] = 0x01;
    b.header.hashMerkleRoot.data[0] = 0x02;
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (b.vtx) {
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].sequence = 0xffffffffu;
        b.vtx[0].vout[0].value = 5000000000LL;
    }
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    w->wrote = b.vtx && write_block_to_disk(&b, &pos, w->dir2, msg_start);
    block_get_hash(&b, &w->block_hash);
    block_free(&b);

    memset(&w->torn, 0, sizeof(w->torn));
    w->torn.nHeight = 1;
    w->torn.nStatus = BLOCK_HAVE_DATA;
    w->torn.nFile = pos.nFile;
    w->torn.nDataPos = pos.nPos;
    w->torn.phashBlock = NULL;

    active_chain_init(&w->ac);
    w->installed = active_chain_install_tip_slot(&w->ac, &w->torn);

    char ndb_path[512];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", w->dir2);
    w->opened = node_db_open(&w->ndb, ndb_path);

    /* Pre-run sentinel: a SIGSEGV on the hash-less slot kills the
     * process here; reaching the assertions proves a named outcome. */
    int result = -99;
    if (w->wrote && w->installed && w->opened)
        result = node_db_catchup_service_run(&w->ndb, &w->ac, NULL, w->dir2);

    int tip = w->opened ? node_db_sync_get_tip_height(&w->ndb) : -1;
    NDC_CHECK("catchup survives a torn hash-less slot without crashing",
              w->wrote && w->installed && w->opened && result != -99);
    NDC_CHECK("catchup refuses to advance the projection onto a torn slot",
              tip < 1);
    return failures;
}

/* Repair only the torn identity and run the same block through the
 * real catchup transaction: advance_wallet_witnesses runs with
 * sync_in_batch=false while the catchup's plain BEGIN is open and
 * must not treat it as foreign. */
static int ndc_torn_walk_repaired_pass(struct ndc_torn_walk *w)
{
    int failures = 0;
    w->torn.phashBlock = &w->block_hash;
    int repaired_result = w->opened
        ? node_db_catchup_service_run(&w->ndb, &w->ac, NULL, w->dir2) : -1;
    int repaired_tip = w->opened ? node_db_sync_get_tip_height(&w->ndb) : -1;
    int64_t tree_height = -1;
    bool tree_persisted = w->opened &&
        node_db_state_get_int(&w->ndb, "sapling_tree_rebuild_height",
                              &tree_height);
    NDC_CHECK("catchup advances through its caller-owned plain transaction",
              repaired_result == 1 && repaired_tip == 1);
    NDC_CHECK("catchup commits the Sapling tree/height pair atomically",
              tree_persisted && tree_height == 1);

    if (w->opened) node_db_close(&w->ndb);
    active_chain_free(&w->ac);
    test_cleanup_tmpdir(w->dir2);
    return failures;
}

static int ndc_check_torn_hashless_walk(void)
{
    int failures = 0;
    struct ndc_torn_walk w;
    failures += ndc_torn_walk_first_pass(&w);
    failures += ndc_torn_walk_repaired_pass(&w);
    return failures;
}

enum { NDC_FIX_N = 5 };

struct ndc_fix_ctx {
    char dirF[256];
    char dirA[256];
    char dirB[256];
    char dirC[256];
    char dirD[256];
    char dirR[256];
    char dirS[256];
    char pathA[512];
    char pathB[512];
    char pathC[512];
    char pathD[512];
    char pathR[512];
    char pathS[512];
    struct uint256 hashes[NDC_FIX_N + 1];
    struct block_index slots[NDC_FIX_N + 1];
    struct active_chain ac;
    struct node_db ndbA;
    struct node_db ndbB;
    struct node_db ndbC;
    struct node_db ndbR;
    struct uint256 hash6;
    struct block_index slot6;
    bool built;
    bool openA;
    bool openB;
    bool openC;
    bool openR;
    bool sixth;
    int tipA;
    int maxA;
};

static int ndc_prepare_five_block_fixture(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    test_make_tmpdir(fx->dirF, sizeof(fx->dirF), "node_db_catchup", "fix");
    test_make_tmpdir(fx->dirA, sizeof(fx->dirA), "node_db_catchup", "batchA");
    test_make_tmpdir(fx->dirB, sizeof(fx->dirB), "node_db_catchup", "batchB");
    test_make_tmpdir(fx->dirC, sizeof(fx->dirC), "node_db_catchup", "snapC");
    test_make_tmpdir(fx->dirD, sizeof(fx->dirD), "node_db_catchup",
                     "continuousD");
    test_make_tmpdir(fx->dirR, sizeof(fx->dirR), "node_db_catchup", "reopenR");
    test_make_tmpdir(fx->dirS, sizeof(fx->dirS), "node_db_catchup", "reopenS");
    char blocksF[512];
    snprintf(blocksF, sizeof(blocksF), "%s/blocks", fx->dirF);
    mkdir(blocksF, 0755);

    struct disk_block_pos pos[NDC_FIX_N + 1];
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    fx->built = true;
    for (int h = 1; h <= NDC_FIX_N && fx->built; h++) {
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = 1700000123u + (uint32_t)h;
        b.header.nBits = 0x2000ffffu;
        b.header.hashPrevBlock.data[0] = (uint8_t)h;
        b.header.hashMerkleRoot.data[0] = (uint8_t)(0x40 + h);
        b.num_vtx = 1;
        b.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
        if (b.vtx) {
            transaction_init(&b.vtx[0]);
            transaction_alloc(&b.vtx[0], 1, 1);
            b.vtx[0].vin[0].sequence = 0xffffffffu;
            b.vtx[0].vout[0].value = 5000000000LL + h;
        }
        fx->built = b.vtx &&
            (disk_block_pos_init(&pos[h]),
             write_block_to_disk(&b, &pos[h], fx->dirF, msg_start)) &&
            (block_get_hash(&b, &fx->hashes[h]), true);
        block_free(&b);
    }

    active_chain_init(&fx->ac);
    for (int h = 1; h <= NDC_FIX_N && fx->built; h++) {
        memset(&fx->slots[h], 0, sizeof(fx->slots[h]));
        fx->slots[h].nHeight = h;
        fx->slots[h].nStatus = BLOCK_HAVE_DATA;
        fx->slots[h].nFile = pos[h].nFile;
        fx->slots[h].nDataPos = pos[h].nPos;
        fx->slots[h].phashBlock = &fx->hashes[h];
        fx->built = active_chain_install_tip_slot(&fx->ac, &fx->slots[h]);
    }
    NDC_CHECK("five-block fixture builds and installs", fx->built);

    snprintf(fx->pathA, sizeof(fx->pathA), "%s/node.db", fx->dirA);
    snprintf(fx->pathB, sizeof(fx->pathB), "%s/node.db", fx->dirB);
    snprintf(fx->pathC, sizeof(fx->pathC), "%s/node.db", fx->dirC);
    snprintf(fx->pathD, sizeof(fx->pathD), "%s/node.db", fx->dirD);
    snprintf(fx->pathR, sizeof(fx->pathR), "%s/node.db", fx->dirR);
    snprintf(fx->pathS, sizeof(fx->pathS), "%s/node.db", fx->dirS);
    return failures;
}

static int ndc_check_batch_cap_two(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* (c1) Batch cap 2 over 5 blocks: commits at indexed=2 and 4 plus
     * the final commit — multiple transactions, never one unbounded
     * batch. */
    fx->openA = fx->built && node_db_open(&fx->ndbA, fx->pathA);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_batch_size(2);
    int resA = fx->openA
        ? node_db_catchup_service_run(&fx->ndbA, &fx->ac, NULL, fx->dirF)
        : -1;
    fx->tipA = fx->openA ? node_db_sync_get_tip_height(&fx->ndbA) : -1;
    fx->maxA = fx->openA ? db_block_max_height(&fx->ndbA) : -1;
    int commitsA = node_db_catchup_lock_guard_test_batch_commits();
    NDC_CHECK("batch cap 2 indexes all five blocks",
              resA == NDC_FIX_N && fx->tipA == NDC_FIX_N &&
              fx->maxA == NDC_FIX_N);
    NDC_CHECK("batch cap 2 commits mid-walk at 2 and 4",
              commitsA == 2);
    return failures;
}

static int ndc_check_default_cap_final_state(int resB, int commitsB,
                                             int tipB, int tipA,
                                             int maxB, int maxA,
                                             bool treeA_ok, bool treeB_ok,
                                             int64_t treeA, int64_t treeB)
{
    int failures = 0;

    NDC_CHECK("default cap needs no mid-walk commit",
              resB == NDC_FIX_N && commitsB == 0);
    NDC_CHECK("commit granularity never changes the final state",
              tipB == tipA && maxB == maxA &&
              treeA_ok && treeB_ok && treeA == treeB);
    return failures;
}

static int ndc_check_default_cap_one_commit(struct ndc_fix_ctx *fx)
{
    /* (c2) Default cap (2000): one final commit only — and the final
     * state is identical to the multi-transaction run. */
    fx->openB = fx->built && node_db_open(&fx->ndbB, fx->pathB);
    node_db_catchup_lock_guard_test_reset();
    int resB = fx->openB
        ? node_db_catchup_service_run(&fx->ndbB, &fx->ac, NULL, fx->dirF)
        : -1;
    int tipB = fx->openB ? node_db_sync_get_tip_height(&fx->ndbB) : -1;
    int maxB = fx->openB ? db_block_max_height(&fx->ndbB) : -1;
    int commitsB = node_db_catchup_lock_guard_test_batch_commits();
    int64_t treeA = -1, treeB = -1;
    bool treeA_ok = fx->openA &&
        node_db_state_get_int(&fx->ndbA, "sapling_tree_rebuild_height",
                              &treeA);
    bool treeB_ok = fx->openB &&
        node_db_state_get_int(&fx->ndbB, "sapling_tree_rebuild_height",
                              &treeB);
    return ndc_check_default_cap_final_state(
        resB, commitsB, tipB, fx->tipA, maxB, fx->maxA,
        treeA_ok, treeB_ok, treeA, treeB);
}

static int ndc_check_busy_snapshot_restart(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* (b) Injected SQLITE_BUSY_SNAPSHOT write failure: the pass rolls
     * back and restarts the whole walk once (bounded), then completes
     * with the identical final state. */
    fx->openC = fx->built && node_db_open(&fx->ndbC, fx->pathC);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_force_snapshot_failures(1);
    int restarts_before =
        node_db_catchup_lock_guard_test_snapshot_restarts();
    int resC = fx->openC
        ? node_db_catchup_service_run(&fx->ndbC, &fx->ac, NULL, fx->dirF)
        : -1;
    int tipC = fx->openC ? node_db_sync_get_tip_height(&fx->ndbC) : -1;
    int restarts_after =
        node_db_catchup_lock_guard_test_snapshot_restarts();
    NDC_CHECK("BUSY_SNAPSHOT triggers exactly one whole-walk restart",
              restarts_after == restarts_before + 1);
    NDC_CHECK("the restarted walk completes with identical state",
              resC == NDC_FIX_N && tipC == fx->tipA);
    return failures;
}

static int ndc_check_transient_reopen_busy(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* (r1) ONE transient SQLITE_BUSY on the post-batch-commit BEGIN
     * IMMEDIATE. A wait cures it: the batch already committed and the
     * walk holds no snapshot, so the reopen retries in place and the
     * pass completes with the identical state. */
    fx->openR = fx->built && node_db_open(&fx->ndbR, fx->pathR);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    node_db_catchup_lock_guard_test_set_batch_size(2);
    node_db_catchup_test_force_reopen_busy(1);
    int resR = fx->openR
        ? node_db_catchup_service_run(&fx->ndbR, &fx->ac, NULL, fx->dirF)
        : -1;
    int tipR = fx->openR ? node_db_sync_get_tip_height(&fx->ndbR) : -1;
    int maxR = fx->openR ? db_block_max_height(&fx->ndbR) : -1;
    int attemptsR = node_db_catchup_test_reopen_attempts();
    NDC_CHECK("a transient busy reopen never aborts the walk",
              resR == NDC_FIX_N && tipR == NDC_FIX_N && maxR == NDC_FIX_N);
    /* Two mid-walk commits (blocks 2 and 4) means two reopens; the
     * injected busy costs exactly one extra BEGIN. */
    NDC_CHECK("the retry costs exactly one extra BEGIN attempt",
              attemptsR == 3);
    return failures;
}

static int ndc_check_reopen_busy_never_clears(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* (r2) A busy that never clears. The walk spends exactly
     * NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS BEGINs on it, names every
     * retry, then keeps the unchanged fail-closed abort — the budget
     * buys patience, it does not remove the wall. */
    struct node_db ndbS;
    bool openS = fx->built && node_db_open(&ndbS, fx->pathS);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    node_db_catchup_lock_guard_test_set_batch_size(2);
    node_db_catchup_test_force_reopen_busy(
        NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
    char logS[16384];
    g_cap_ndb = &ndbS;
    g_cap_chain = &fx->ac;
    g_cap_datadir = fx->dirF;
    g_cap_result = -99;
    bool capturedS = openS && ndc_capture_stderr(ndc_run_catchup_capture,
                                                 logS, sizeof(logS));
    int attemptsS = node_db_catchup_test_reopen_attempts();
    char firstS[64], lastS[64];
    snprintf(firstS, sizeof(firstS), "catchup: reopen busy, retry 1/%d",
             NODE_DB_CATCHUP_REOPEN_MAX_RETRIES);
    snprintf(lastS, sizeof(lastS), "catchup: reopen busy, retry %d/%d",
             NODE_DB_CATCHUP_REOPEN_MAX_RETRIES,
             NODE_DB_CATCHUP_REOPEN_MAX_RETRIES);
    NDC_CHECK("a busy that never clears still fails closed",
              capturedS && g_cap_result == -1 &&
              strstr(logS, "catchup: failed to reopen transaction after "
                           "batch commit") != NULL &&
              strstr(logS, "catchup: aborting (failed=1, restore_ok=1")
                  != NULL);
    NDC_CHECK("the reopen budget is spent exactly once, in full",
              attemptsS == NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
    NDC_CHECK("every retry is named in the log",
              capturedS && strstr(logS, firstS) != NULL &&
              strstr(logS, lastS) != NULL);
    NDC_CHECK("a real failed walk counts exactly one logical abort",
              node_db_catchup_lock_guard_test_abort_streak() == 1);

    /* (r2b) The plain fail-closed abort must pair its one
     * catchup_active_begin() with exactly one finish. LOG_ERR logs AND
     * returns, so the finish above the "aborting" site is this pass's
     * ONLY finish. Check the coarse active flag and the raw depth
     * (must land on 0, not -1). */
    NDC_CHECK("catchup reports inactive right after a plain failed pass",
              !node_db_catchup_service_active());
    NDC_CHECK("the active-depth counter is paired to zero, not -1",
              node_db_catchup_test_active_depth() == 0);

    /* A following real walk (the busy budget is spent) drains the
     * remaining work and lands the depth counter back on zero: the
     * fresh begin/finish is paired too. */
    int resS2 = openS
        ? node_db_catchup_service_run(&ndbS, &fx->ac, NULL, fx->dirF) : -1;
    NDC_CHECK("a following real walk drains the rest of the work",
              resS2 == NDC_FIX_N - 2);
    NDC_CHECK("a successful real walk resets the abort streak",
              node_db_catchup_lock_guard_test_abort_streak() == 0);
    NDC_CHECK("catchup reports inactive after the following real walk",
              !node_db_catchup_service_active());
    NDC_CHECK("the depth counter is still paired after a fresh begin",
              node_db_catchup_test_active_depth() == 0);

    node_db_catchup_test_reset_reopen();
    if (openS) node_db_close(&ndbS);
    return failures;
}

/* Clean close/reopen only; this does not simulate a crash or power loss. */
static bool ndc_restart_int_equal(sqlite3_stmt *a,sqlite3_stmt *b,int col)
{
    return sqlite3_column_type(a,col)==SQLITE_INTEGER && sqlite3_column_type(b,col)==SQLITE_INTEGER &&
        sqlite3_column_int64(a,col)==sqlite3_column_int64(b,col);
}
static bool ndc_restart_blob_equal(sqlite3_stmt *a,sqlite3_stmt *b,int col)
{
    if(sqlite3_column_type(a,col)!=SQLITE_BLOB || sqlite3_column_type(b,col)!=SQLITE_BLOB ||
       sqlite3_column_bytes(a,col)!=32 || sqlite3_column_bytes(b,col)!=32) return false;
    const void *x=sqlite3_column_blob(a,col),*y=sqlite3_column_blob(b,col);
    return x && y && !memcmp(x,y,32);
}
static bool ndc_restart_row_equal(sqlite3_stmt *a,sqlite3_stmt *b)
{
    return ndc_restart_int_equal(a,b,0) && ndc_restart_blob_equal(a,b,1) &&
        ndc_restart_blob_equal(a,b,2) && ndc_restart_int_equal(a,b,3);
}
static bool ndc_restart_projection_equal(sqlite3 *a,sqlite3 *b)
{
    const char *sql="SELECT height,hash,prev_hash,status FROM blocks ORDER BY height,hash";
    sqlite3_stmt *x=NULL,*y=NULL; bool ok=false; int rows=0;
    if(sqlite3_prepare_v2(a,sql,-1,&x,NULL)!=SQLITE_OK || sqlite3_prepare_v2(b,sql,-1,&y,NULL)!=SQLITE_OK) goto done;
    for(;;) {
        int rx=sqlite3_step(x),ry=sqlite3_step(y);
        if(rx==SQLITE_DONE && ry==SQLITE_DONE) { ok=rows==NDC_FIX_N; break; }
        if(rx!=SQLITE_ROW || ry!=SQLITE_ROW || !ndc_restart_row_equal(x,y)) break;
        rows++;
    }
done:
    if(x && sqlite3_finalize(x)!=SQLITE_OK) ok=false;
    if(y && sqlite3_finalize(y)!=SQLITE_OK) ok=false;
    return ok;
}
static bool ndc_restart_prefix(sqlite3 *db)
{
    sqlite3_stmt *s=NULL; bool ok=false;
    const char *sql="SELECT count(*),count(DISTINCT height),min(height),max(height) FROM blocks";
    if(sqlite3_prepare_v2(db,sql,-1,&s,NULL)!=SQLITE_OK) goto done;
    ok=sqlite3_step(s)==SQLITE_ROW && sqlite3_column_int(s,0)==2 && sqlite3_column_int(s,1)==2 &&
       sqlite3_column_int(s,2)==1 && sqlite3_column_int(s,3)==2 && sqlite3_step(s)==SQLITE_DONE;
done:
    if(s && sqlite3_finalize(s)!=SQLITE_OK) ok=false;
    return ok;
}
static int ndc_restart_check_result(struct node_db *resumed,struct node_db *fresh,int walked,int reference)
{
    int failures=0; uint8_t a[32],b[32];
    bool receipts=db_view_integrity_get(resumed,NDC_FIX_N,a) && db_view_integrity_get(fresh,NDC_FIX_N,b);
    NDC_CHECK("reopened walk resumes exactly remaining blocks",walked==NDC_FIX_N-2 && reference==NDC_FIX_N);
    NDC_CHECK("reopened projection matches fresh parent and status",ndc_restart_projection_equal(resumed->db,fresh->db));
    NDC_CHECK("reopened receipt matches fresh uninterrupted",receipts && !memcmp(a,b,32));
    NDC_CHECK("reopened walk leaves active depth zero",!node_db_catchup_service_active() && node_db_catchup_test_active_depth()==0);
    NDC_CHECK("reopened walk resets abort streak",node_db_catchup_lock_guard_test_abort_streak()==0);
    return failures;
}
struct ndc_restart_ctx {
    char dir[256],refdir[256],path[512],refpath[512];
    struct node_db ndb,reference;
    bool opened,ref_open;
};
static void ndc_restart_setup(struct ndc_restart_ctx *r)
{
    test_make_tmpdir(r->dir,sizeof(r->dir),"node_db_catchup","restart_durable");
    test_make_tmpdir(r->refdir,sizeof(r->refdir),"node_db_catchup","restart_reference");
    snprintf(r->path,sizeof(r->path),"%s/node.db",r->dir);
    snprintf(r->refpath,sizeof(r->refpath),"%s/node.db",r->refdir);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    node_db_catchup_lock_guard_test_set_batch_size(2);
}
static int ndc_restart_abort_and_reopen(struct ndc_fix_ctx *fx,struct ndc_restart_ctx *r)
{
    int failures=0;
    r->opened=fx->built && node_db_open(&r->ndb,r->path);
    node_db_catchup_test_force_reopen_busy(NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
    int first=r->opened?node_db_catchup_service_run(&r->ndb,&fx->ac,NULL,fx->dirF):-99;
    NDC_CHECK("restart fixture aborts after committed batch",first==-1 && node_db_catchup_test_reopen_attempts()==NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
    NDC_CHECK("restart abort pairs active depth",!node_db_catchup_service_active() && node_db_catchup_test_active_depth()==0);
    NDC_CHECK("restart abort records one streak",node_db_catchup_lock_guard_test_abort_streak()==1);
    if(r->opened) { node_db_close(&r->ndb); r->opened=false; }
    node_db_catchup_test_reset_reopen();
    r->opened=fx->built && node_db_open(&r->ndb,r->path);
    NDC_CHECK("reopened database retains exactly prefix two",r->opened && ndc_restart_prefix(r->ndb.db));
    return failures;
}
static int ndc_restart_resume(struct ndc_fix_ctx *fx,struct ndc_restart_ctx *r)
{
    int failures=0;
    int walked=r->opened?node_db_catchup_service_run(&r->ndb,&fx->ac,NULL,fx->dirF):-1;
    NDC_CHECK("resumed success resets streak before reference",walked==NDC_FIX_N-2 && node_db_catchup_lock_guard_test_abort_streak()==0);
    NDC_CHECK("resumed walk immediately leaves depth zero",!node_db_catchup_service_active() && node_db_catchup_test_active_depth()==0);
    r->ref_open=fx->built && node_db_open(&r->reference,r->refpath);
    int fresh=r->ref_open?node_db_catchup_service_run(&r->reference,&fx->ac,NULL,fx->dirF):-1;
    if(r->opened && r->ref_open) failures+=ndc_restart_check_result(&r->ndb,&r->reference,walked,fresh);
    else { NDC_CHECK("restart and reference databases open",false); }
    return failures;
}
static void ndc_restart_cleanup(struct ndc_restart_ctx *r)
{
    if(r->opened) node_db_close(&r->ndb);
    if(r->ref_open) node_db_close(&r->reference);
    node_db_catchup_test_reset_reopen(); node_db_catchup_lock_guard_test_reset();
    test_cleanup_tmpdir(r->dir); test_cleanup_tmpdir(r->refdir);
}
static int ndc_check_durable_reopen(struct ndc_fix_ctx *fx)
{
    struct ndc_restart_ctx r={0};
    ndc_restart_setup(&r);
    int failures=ndc_restart_abort_and_reopen(fx,&r);
    failures+=ndc_restart_resume(fx,&r);
    ndc_restart_cleanup(&r);
    return failures;
}

static int ndc_check_maintenance_defers_while_active(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* (r3) The other half of the same policy: db_maintenance is the
     * writer whose lock hold produced the busy above, so it yields
     * its tick while a walk is running and runs on the next call once
     * the walk is over. The yield is bounded — a multi-hour catchup
     * must not silence housekeeping for its whole duration. */
    node_db_catchup_test_set_active(true);
    bool deferred = fx->openB &&
        !db_maintenance_run_now(&fx->ndbB, "wal").ok;
    node_db_catchup_test_set_active(false);
    bool ran_after = fx->openB &&
        db_maintenance_run_now(&fx->ndbB, "wal").ok;
    NDC_CHECK("db_maintenance defers its tick while catchup is active",
              deferred);
    NDC_CHECK("db_maintenance runs on the next tick once catchup ends",
              ran_after);

    node_db_catchup_test_set_active(true);
    bool budget_held = fx->openB;
    for (int i = 0; i < DB_MAINT_MAX_CATCHUP_DEFERRALS && budget_held; i++)
        budget_held = !db_maintenance_run_now(&fx->ndbB, "wal").ok;
    bool ran_at_bound = fx->openB &&
        db_maintenance_run_now(&fx->ndbB, "wal").ok;
    node_db_catchup_test_set_active(false);
    NDC_CHECK("the courtesy holds for the whole deferral budget",
              budget_held);
    NDC_CHECK("housekeeping is never deferred forever", ran_at_bound);
    return failures;
}

static int ndc_check_abort_storm_parks_worker(void)
{
    int failures = 0;

    /* (park) Eight consecutive failed passes name the
     * node_db_catchup.abort_storm blocker and park the worker; a
     * pending block stays unindexed until an operator clears the
     * blocker (half-open), after which the next pass works. */
    blocker_module_init();
    blocker_reset_for_testing();
    node_db_catchup_lock_guard_test_reset();
    for (int i = 0; i < NODE_DB_CATCHUP_ABORT_STREAK_CAP; i++)
        node_db_catchup_lock_guard_note_outcome(true);
    NDC_CHECK("eight consecutive aborts raise the streak to the cap",
              node_db_catchup_lock_guard_test_abort_streak() ==
                  NODE_DB_CATCHUP_ABORT_STREAK_CAP);
    NDC_CHECK("the abort storm is a NAMED blocker",
              blocker_exists(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID));
    NDC_CHECK("the worker parks behind the named blocker",
              node_db_catchup_lock_guard_parked());
    return failures;
}

static int ndc_append_sixth_block(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* Real work pending (a 6th block) must stay undone while parked. */
    struct disk_block_pos pos6;
    struct block b6;
    block_init(&b6);
    b6.header.nVersion = 4;
    b6.header.nTime = 1700000123u + 6;
    b6.header.nBits = 0x2000ffffu;
    b6.header.hashPrevBlock.data[0] = 6;
    b6.header.hashMerkleRoot.data[0] = 0x46;
    b6.num_vtx = 1;
    b6.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (b6.vtx) {
        transaction_init(&b6.vtx[0]);
        transaction_alloc(&b6.vtx[0], 1, 1);
        b6.vtx[0].vin[0].sequence = 0xffffffffu;
        b6.vtx[0].vout[0].value = 5000000006LL;
    }
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    bool sixth = b6.vtx &&
        (disk_block_pos_init(&pos6),
         write_block_to_disk(&b6, &pos6, fx->dirF, msg_start));
    block_get_hash(&b6, &fx->hash6);
    block_free(&b6);
    memset(&fx->slot6, 0, sizeof(fx->slot6));
    fx->slot6.nHeight = NDC_FIX_N + 1;
    fx->slot6.nStatus = BLOCK_HAVE_DATA;
    fx->slot6.nFile = pos6.nFile;
    fx->slot6.nDataPos = pos6.nPos;
    fx->slot6.phashBlock = &fx->hash6;
    sixth = sixth && active_chain_install_tip_slot(&fx->ac, &fx->slot6);
    NDC_CHECK("sixth block extends the pending work", sixth);
    fx->sixth = sixth;
    return failures;
}

static int ndc_check_parked_then_half_open(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    int res_parked = fx->sixth && fx->openA
        ? node_db_catchup_service_run(&fx->ndbA, &fx->ac, NULL, fx->dirF)
        : -1;
    int tip_parked = fx->openA ? node_db_sync_get_tip_height(&fx->ndbA) : -1;
    NDC_CHECK("the parked worker does NOT re-run the failing pass",
              res_parked == 0 && tip_parked == NDC_FIX_N);

    blocker_clear(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID);
    NDC_CHECK("operator clear half-opens the worker",
              !node_db_catchup_lock_guard_parked() &&
              node_db_catchup_lock_guard_test_abort_streak() == 0);
    int res_halfopen = fx->sixth && fx->openA
        ? node_db_catchup_service_run(&fx->ndbA, &fx->ac, NULL, fx->dirF)
        : -1;
    int tip_halfopen = fx->openA
        ? node_db_sync_get_tip_height(&fx->ndbA) : -1;
    NDC_CHECK("the half-open pass resumes indexing",
              res_halfopen == 1 && tip_halfopen == NDC_FIX_N + 1);
    return failures;
}

static int ndc_check_resumed_matches_continuous(struct ndc_fix_ctx *fx)
{
    int failures = 0;

    /* Differential restart proof: a resumed 1..5 then 6 walk must
     * produce the same height-6 chained receipt as a continuous
     * 1..6 walk; a changed start-1 read makes them diverge. */
    node_db_catchup_lock_guard_test_reset();
    struct node_db ndbD;
    bool openD = fx->sixth && node_db_open(&ndbD, fx->pathD);
    int res_continuous = openD
        ? node_db_catchup_service_run(&ndbD, &fx->ac, NULL, fx->dirF) : -1;
    uint8_t resumed_receipt[32] = {0};
    uint8_t continuous_receipt[32] = {0};
    bool resumed_read = fx->openA && db_view_integrity_get(
        &fx->ndbA, NDC_FIX_N + 1, resumed_receipt);
    bool continuous_read = openD && db_view_integrity_get(
        &ndbD, NDC_FIX_N + 1, continuous_receipt);
    NDC_CHECK("resumed catchup receipt matches continuous chain",
              res_continuous == NDC_FIX_N + 1 && resumed_read &&
              continuous_read &&
              memcmp(resumed_receipt, continuous_receipt, 32) == 0);
    if (openD) node_db_close(&ndbD);
    return failures;
}

/* Writers get through while a walk runs.
 *
 * The walk runs as one db-worker job. A detached state writer (own
 * connection, 100 ms busy wait) and a plain write queued on the worker must
 * both complete BEFORE the walk ends: the batch commit hands over the lock
 * and the worker queue instead of reopening the next batch instantly. */
#define NDC_YIELD_MAX_ATTEMPTS 12
#define NDC_YIELD_HEIGHT_DELAY_MS 150

struct ndc_starve {
    struct db_service *svc;
    struct node_db *ndb;
    struct active_chain *ac;
    const char *datadir;
    _Atomic bool walk_done;
    _Atomic int walk_result;
    int detached_attempts;
    bool detached_ok_during_walk;
    bool queued_ok_during_walk;
    _Atomic bool noop_saw_walk;
};

static bool ndc_starve_walk(struct node_db *ndb, void *ctx)
{
    struct ndc_starve *st = ctx;
    atomic_store(&st->walk_result,
                 node_db_catchup_service_run(ndb, st->ac, NULL, st->datadir));
    atomic_store(&st->walk_done, true);
    return true;
}

static bool ndc_starve_noop(struct node_db *ndb, void *ctx)
{
    struct ndc_starve *st = ctx;

    (void)ndb;
    atomic_store(&st->noop_saw_walk, node_db_catchup_service_active());
    return true;
}

static void *ndc_starve_walk_thread(void *arg)
{
    struct ndc_starve *st = arg;
    (void)db_service_run_write(st->svc, ndc_starve_walk, st);
    return NULL;
}

static void *ndc_starve_queued_thread(void *arg)
{
    struct ndc_starve *st = arg;
    bool ok = db_service_run_write(st->svc, ndc_starve_noop, st);
    st->queued_ok_during_walk = ok && !atomic_load(&st->walk_done);
    return NULL;
}

static void ndc_starve_detached(struct ndc_starve *st)
{
    const uint8_t value[1] = {1};

    for (int i = 0; i < NDC_YIELD_MAX_ATTEMPTS; i++) {
        st->detached_attempts = i + 1;
        if (node_db_state_set_detached(st->ndb, "ndc.yield", value, 1)) {
            st->detached_ok_during_walk = !atomic_load(&st->walk_done);
            return;
        }
        platform_sleep_ms(20);
    }
}

static int ndc_check_walk_yields_to_writers(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct ndc_starve st = {.ac = &fx->ac, .datadir = fx->dirF};
    struct db_service svc;
    struct app_runtime_context rt = {.db_service = &svc};
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "yield");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    db_service_init(&svc);
    bool up = fx->built && node_db_open(&ndb, path) &&
              db_service_attach(&svc, &ndb) &&
              db_service_start_test_worker(&svc);
    st.svc = &svc;
    st.ndb = &ndb;
    if (up) {
        app_runtime_set_current(&rt);
        node_db_detached_writer_test_reset();
        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_lock_guard_test_set_batch_size(2);
        node_db_catchup_lock_guard_test_set_height_delay_ms(
            NDC_YIELD_HEIGHT_DELAY_MS);
        pthread_t walk, queued;
        bool w = pthread_create(&walk, NULL, ndc_starve_walk_thread, &st) == 0;
        for (int i = 0; i < 200 && !node_db_catchup_service_active(); i++)
            platform_sleep_ms(5);
        platform_sleep_ms(100);
        bool q = pthread_create(&queued, NULL, ndc_starve_queued_thread,
                                &st) == 0;
        ndc_starve_detached(&st);
        if (q) pthread_join(queued, NULL);
        if (w) pthread_join(walk, NULL);
        app_runtime_set_current(NULL);
        node_db_catchup_lock_guard_test_reset();
    }
    printf("walk yield: up=%d walk=%d detached_attempts=%d "
           "detached_during_walk=%d queued_during_walk=%d\n", up,
           atomic_load(&st.walk_result), st.detached_attempts,
           st.detached_ok_during_walk, st.queued_ok_during_walk);
    NDC_CHECK("the yielding walk still indexes every block",
              up && atomic_load(&st.walk_result) == NDC_FIX_N);
    NDC_CHECK("the detached writer really contended with the walk",
              up && st.detached_attempts >= 2);
    NDC_CHECK("a detached state_set lands while the walk is running",
              up && st.detached_ok_during_walk);
    NDC_CHECK("a queued worker write ran nested inside the running walk",
              up && st.queued_ok_during_walk &&
              atomic_load(&st.noop_saw_walk));
    if (up) {
        db_service_stop(&svc);
        node_db_close(&ndb);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Tip jobs during a bulk walk.
 *
 * With the threshold lowered the fixture walk runs in bulk mode, the mode a
 * seeded phone is in for hours. A job submitted bulk-safe (the wallet note and
 * the tip witness writes) must run between the batches of that walk and its
 * submitter must not wait for the pass; an ordinary queued job must still wait
 * for the walk, because bulk mode runs with synchronous=OFF. */
struct ndc_bulk {
    struct ndc_starve st;
    _Atomic bool safe_ran;
    _Atomic bool safe_saw_walk;
    _Atomic bool plain_ran_during_walk;
    _Atomic bool note_returned;
    _Atomic bool note_during_walk;
    _Atomic bool tip_job_during_walk;
    int64_t note_ms;
};

static bool ndc_bulk_safe_job(struct node_db *ndb, void *ctx)
{
    struct ndc_bulk *b = ctx;
    (void)ndb;
    atomic_store(&b->safe_saw_walk, node_db_catchup_service_active() &&
                                    !atomic_load(&b->st.walk_done));
    atomic_store(&b->safe_ran, true);
    return true;
}

static bool ndc_bulk_plain_job(struct node_db *ndb, void *ctx)
{
    struct ndc_bulk *b = ctx;
    (void)ndb;
    if (!atomic_load(&b->st.walk_done))
        atomic_store(&b->plain_ran_during_walk, true);
    return true;
}

/* The walk is held open (30 s bound in the seam), so wait for the job to run
 * rather than for a wall-clock window the loaded walk can miss. */
enum { NDC_TIP_WAIT_POLLS = 30000 / 5 };

/* Queue the production tip witness job and record whether it started while
 * the walk was still running. */
static void ndc_bulk_queue_tip_job(struct ndc_bulk *b)
{
    struct block_index parent, tipbi;
    struct uint256 hash = {{9}};
    struct block blk;
    block_init(&blk);
    memset(&parent, 0, sizeof(parent));
    memset(&tipbi, 0, sizeof(tipbi));
    parent.nHeight = 1;
    tipbi.nHeight = 2;
    tipbi.pprev = &parent;
    tipbi.phashBlock = &hash;
    int runs = node_db_sync_tip_witness_test_job_runs();
    bool queued = node_db_sync_advance_tip_witnesses_async(b->st.ndb, &blk,
                                                           &tipbi, NULL);
    for (int i = 0; i < NDC_TIP_WAIT_POLLS && queued &&
         node_db_sync_tip_witness_test_job_runs() == runs; i++)
        platform_sleep_ms(5);
    atomic_store(&b->tip_job_during_walk,
                 queued && node_db_sync_tip_witness_test_job_runs() > runs &&
                 !atomic_load(&b->st.walk_done));
    /* The walk was held open at its batch yield until now. */
    node_db_catchup_lock_guard_test_hold_walk(false);
}

static void *ndc_bulk_reducer_thread(void *arg)
{
    struct ndc_bulk *b = arg;
    uint8_t txid[32] = {0x66}, rcm[32] = {1}, memo[512] = {0};
    uint8_t ivk[32] = {2}, div[11] = {3}, pk[32] = {4}, cm[32] = {5};
    uint8_t nf[32] = {6};
    int64_t t0 = GetTimeMillis();
    (void)db_service_enqueue_write(b->st.svc, ndc_bulk_plain_job, b, NULL);
    (void)db_service_enqueue_write_bulk_safe(b->st.svc, ndc_bulk_safe_job, b,
                                             NULL);
    bool ok = node_db_sync_sapling_note_at_tip(
        b->st.ndb, txid, 0, 1000, rcm, memo, 512, ivk, div, pk, cm, nf, 5);
    b->note_ms = GetTimeMillis() - t0;
    atomic_store(&b->note_during_walk, !atomic_load(&b->st.walk_done));
    atomic_store(&b->note_returned, ok);
    ndc_bulk_queue_tip_job(b);
    return NULL;
}

static bool ndc_flush_job(struct node_db *ndb, void *ctx)
{
    (void)ndb;
    (void)ctx;
    return true;
}

/* Run a bulk walk and, while it runs, the reducer-side calls under test. */
static void ndc_bulk_run(struct ndc_bulk *b, struct db_service *svc,
                         struct app_runtime_context *rt)
{
    app_runtime_set_current(rt);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_batch_size(2);
    node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    node_db_catchup_lock_guard_test_set_height_delay_ms(
        NDC_YIELD_HEIGHT_DELAY_MS);
    /* Held at the walk's batch yield until the tip job is queued and seen. */
    node_db_catchup_lock_guard_test_hold_walk(true);
    pthread_t walk, reducer;
    bool w = pthread_create(&walk, NULL, ndc_starve_walk_thread, &b->st) == 0;
    for (int i = 0; i < 200 && !node_db_catchup_service_active(); i++)
        platform_sleep_ms(5);
    platform_sleep_ms(100);
    bool q = pthread_create(&reducer, NULL, ndc_bulk_reducer_thread, b) == 0;
    if (q)
        pthread_join(reducer, NULL);
    if (w)
        pthread_join(walk, NULL);
    (void)db_service_run_write(svc, ndc_flush_job, NULL);
    app_runtime_set_current(NULL);
    node_db_catchup_lock_guard_test_reset();
}

static int ndc_bulk_verify(struct ndc_bulk *b, bool up, struct node_db *ndb)
{
    int failures = 0;
    printf("bulk walk: up=%d walk=%d note_ms=%lld during=%d safe_ran=%d "
           "safe_saw_walk=%d plain_during=%d\n", up,
           atomic_load(&b->st.walk_result), (long long)b->note_ms,
           atomic_load(&b->note_during_walk), atomic_load(&b->safe_ran),
           atomic_load(&b->safe_saw_walk),
           atomic_load(&b->plain_ran_during_walk));
    NDC_CHECK("the bulk walk indexes every block",
              up && atomic_load(&b->st.walk_result) == NDC_FIX_N);
    NDC_CHECK("recording a note at the tip returns while the walk runs",
              up && atomic_load(&b->note_returned) &&
              atomic_load(&b->note_during_walk) && b->note_ms < 400);
    NDC_CHECK("a bulk-safe job runs between the batches of the walk",
              up && atomic_load(&b->safe_ran) &&
              atomic_load(&b->safe_saw_walk));
    NDC_CHECK("the queued tip witness job runs while the walk runs",
              up && atomic_load(&b->tip_job_during_walk));
    NDC_CHECK("an ordinary queued job waits for the walk",
              up && !atomic_load(&b->plain_ran_during_walk));
    NDC_CHECK("the note row exists once the queue drained",
              up && db_sapling_note_count_unspent(ndb) == 1);
    return failures;
}

static int ndc_check_bulk_walk_tip_jobs(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    static struct ndc_bulk b;
    struct db_service svc;
    struct app_runtime_context rt = {.db_service = &svc};
    struct node_db ndb;
    char dir[256], path[512];

    memset(&b, 0, sizeof(b));
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "bulk");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    db_service_init(&svc);
    bool up = fx->built && node_db_open(&ndb, path) &&
              db_service_attach(&svc, &ndb) &&
              db_service_start_test_worker(&svc);
    b.st.ac = &fx->ac;
    b.st.datadir = fx->dirF;
    b.st.svc = &svc;
    b.st.ndb = &ndb;
    if (up)
        ndc_bulk_run(&b, &svc, &rt);
    failures += ndc_bulk_verify(&b, up, &ndb);
    if (up) {
        db_service_stop(&svc);
        node_db_close(&ndb);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

enum { NDC_QR_HOLD_MS = 5000 };

struct ndc_qr {
    _Atomic bool started;
    _Atomic bool release;
};

static bool ndc_qr_hold(struct node_db *ndb, void *ctx)
{
    struct ndc_qr *q = ctx;
    (void)ndb;
    atomic_store(&q->started, true);
    for (int i = 0; i < NDC_QR_HOLD_MS && !atomic_load(&q->release); i++)
        platform_sleep_ms(1);
    return true;
}

/* A full db queue refuses the tip jobs at once; the reducer thread that
 * submits them never waits. */
static int ndc_check_tip_queue_refusal(void)
{
    int failures = 0;
    static struct ndc_qr q;
    struct db_service svc;
    struct app_runtime_context rt = {.db_service = &svc};
    struct node_db ndb;
    char dir[256], path[512];

    atomic_store(&q.started, false);
    atomic_store(&q.release, false);
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "qfull");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    db_service_init(&svc);
    bool up = node_db_open(&ndb, path) && db_service_attach(&svc, &ndb) &&
              db_service_start_test_worker(&svc);
    bool filled = false;
    if (up) {
        app_runtime_set_current(&rt);
        up = db_service_enqueue_write(&svc, ndc_qr_hold, &q, NULL);
        for (int i = 0; up && i < 500 && !atomic_load(&q.started); i++)
            platform_sleep_ms(2);
        for (int i = 0; i < 2 * DB_SERVICE_QUEUE_CAP && !filled; i++)
            filled = !db_service_enqueue_write(&svc, ndc_flush_job, NULL, NULL);
    }
    NDC_CHECK("the queue is full behind a running job", up && filled);
    struct block_index parent, tipbi;
    struct uint256 hash = {{9}};
    struct block blk;
    block_init(&blk);
    memset(&parent, 0, sizeof(parent));
    memset(&tipbi, 0, sizeof(tipbi));
    parent.nHeight = 1;
    tipbi.nHeight = 2;
    tipbi.pprev = &parent;
    tipbi.phashBlock = &hash;
    int64_t t0 = GetTimeMillis();
    NDC_CHECK("the tip witness job is refused",
              up && !node_db_sync_advance_tip_witnesses_async(&ndb, &blk,
                                                              &tipbi, NULL));
    uint8_t txid[32] = {0x67}, rcm[32] = {1}, memo[512] = {0};
    uint8_t ivk[32] = {2}, div[11] = {3}, pk[32] = {4}, cm[32] = {5};
    uint8_t nf[32] = {6};
    NDC_CHECK("the note write is refused",
              up && !node_db_sync_sapling_note_at_tip(
                        &ndb, txid, 0, 1000, rcm, memo, 512, ivk, div, pk, cm,
                        nf, 5));
    NDC_CHECK("neither call waited for the running job",
              up && GetTimeMillis() - t0 < NDC_QR_HOLD_MS / 2);
    atomic_store(&q.release, true);
    if (up) {
        (void)db_service_run_write(&svc, ndc_flush_job, NULL);
        app_runtime_set_current(NULL);
        db_service_stop(&svc);
        node_db_close(&ndb);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

/* A stretch of heights that index nothing must still release the lock. */
static int ndc_check_hole_stretch_releases_lock(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "holes");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    for (int h = 1; h <= 3; h++)
        fx->slots[h].nStatus &= ~BLOCK_HAVE_DATA;
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_batch_max_secs(0);
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    int commits = node_db_catchup_lock_guard_test_batch_commits();
    node_db_catchup_lock_guard_test_reset();
    for (int h = 1; h <= 3; h++)
        fx->slots[h].nStatus |= BLOCK_HAVE_DATA;
    printf("hole stretch: result=%d batch_commits=%d\n", res, commits);
    NDC_CHECK("blocks past the hole stretch are indexed", up && res == 2);
    NDC_CHECK("the hole stretch commits and releases the lock",
              up && commits >= 3);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* With nobody waiting, a walk of several batches takes no yield pause. */
static int ndc_check_idle_walk_never_sleeps(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "idle");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_detached_writer_test_reset();
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_batch_size(1);
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    int commits = node_db_catchup_lock_guard_test_batch_commits();
    int sleeps = node_db_catchup_lock_guard_test_yield_sleeps();
    node_db_catchup_lock_guard_test_reset();
    printf("idle walk: result=%d batch_commits=%d yield_sleeps=%d\n", res,
           commits, sleeps);
    NDC_CHECK("the idle walk commits several batches",
              up && res == NDC_FIX_N && commits >= 3);
    NDC_CHECK("an idle walk takes no yield sleep", up && sleeps == 0);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Holes after an indexed block, in one batch, must still release the lock.
 * The cap runs on a test clock the height delay advances, so the post-index
 * check after h=1 (800 ms into a 1 s cap) can never commit by itself. */
static int ndc_check_holes_after_rows_release_lock(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "rowsholes");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    for (int h = 2; h <= 4; h++)
        fx->slots[h].nStatus &= ~BLOCK_HAVE_DATA;
    node_db_detached_writer_test_reset();
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_use_fake_clock(true);
    node_db_catchup_lock_guard_test_set_batch_max_secs(1);
    node_db_catchup_lock_guard_test_set_height_delay_ms(400);
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    int row_commits = node_db_catchup_lock_guard_test_timed_row_commits();
    int tip = up ? node_db_sync_get_tip_height(&ndb) : -1;
    node_db_catchup_lock_guard_test_reset();
    for (int h = 2; h <= 4; h++)
        fx->slots[h].nStatus |= BLOCK_HAVE_DATA;
    printf("holes after rows: result=%d timed_row_commits=%d tip=%d\n", res,
           row_commits, tip);
    NDC_CHECK("the blocks around the hole stretch are indexed",
              up && res == 2 && tip == NDC_FIX_N);
    NDC_CHECK("holes after an indexed block commit that batch's rows",
              up && row_commits >= 1);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* A waiting detached writer lands during a walk whose batch cap is 3600 s:
 * the walk cycles early for it. */

struct ndc_waiter {
    struct node_db *ndb;
    bool ok;
    int attempts;
    _Atomic bool *walk_done;
    bool ok_during_walk;
};

static void *ndc_waiter_thread(void *arg)
{
    struct ndc_waiter *wt = arg;
    const uint8_t value[1] = {2};

    for (int i = 0; i < 200 && !node_db_catchup_service_active(); i++)
        platform_sleep_ms(5);
    platform_sleep_ms(100);
    while (!wt->ok && !atomic_load(wt->walk_done)) {
        wt->attempts++;
        wt->ok = node_db_state_set_detached(wt->ndb, "ndc.waiter", value, 1);
        if (!wt->ok)
            platform_sleep_ms(20);
    }
    wt->ok_during_walk = wt->ok && !atomic_load(wt->walk_done);
    return NULL;
}

static int ndc_check_waiting_writer_cycles_batch(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    _Atomic bool walk_done = false;
    struct ndc_waiter wt = {.ndb = &ndb, .walk_done = &walk_done};
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "waiter");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_detached_writer_test_reset();
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_batch_max_secs(3600);
    node_db_catchup_lock_guard_test_set_height_delay_ms(600);
    pthread_t t;
    bool started = up && pthread_create(&t, NULL, ndc_waiter_thread, &wt) == 0;
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    atomic_store(&walk_done, true);
    if (started) pthread_join(t, NULL);
    int wcommits = node_db_catchup_lock_guard_test_batch_commits();
    node_db_catchup_lock_guard_test_reset();
    printf("waiting writer: result=%d attempts=%d ok=%d during_walk=%d\n",
           res, wt.attempts, wt.ok, wt.ok_during_walk);
    NDC_CHECK("the walk with a 3600 s cap still indexes every block",
              up && res == NDC_FIX_N);
    NDC_CHECK("a waiting detached writer lands during the walk via an early cycle",
              up && wt.ok_during_walk && wt.attempts >= 2 && wcommits >= 1);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* With a writer always waiting, the sleep must not count as hold time: every
 * timed commit follows at least NODE_DB_CATCHUP_WAITER_MIN_HOLD_MS of real
 * hold after the reopen. The yield sleep advances the fake clock. */
static int ndc_hold_case(struct ndc_fix_ctx *fx, int batch_size)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "hold");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_detached_writer_test_reset();
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_use_fake_clock(true);
    if (batch_size > 0)
        node_db_catchup_lock_guard_test_set_batch_size(batch_size);
    node_db_catchup_lock_guard_test_set_batch_max_secs(3600);
    node_db_catchup_lock_guard_test_set_height_delay_ms(100);
    node_db_detached_writer_test_force_waiting(true);
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    node_db_detached_writer_test_force_waiting(false);
    int64_t hold = node_db_catchup_lock_guard_test_min_real_hold();
    int commits = node_db_catchup_lock_guard_test_batch_commits();
    node_db_catchup_lock_guard_test_reset();
    printf("yield hold: batch=%d result=%d commits=%d min_real_hold_ms=%lld\n",
           batch_size, res, commits, (long long)hold);
    NDC_CHECK("the walk with a writer always waiting still finishes",
              up && res == NDC_FIX_N && commits >= 1);
    if (batch_size > 0)
        NDC_CHECK("post-index commits re-stamp the hold after the sleep",
                  up && commits == NDC_FIX_N);
    else
        NDC_CHECK("the yield sleep does not count as hold time",
                  up && hold >= NODE_DB_CATCHUP_WAITER_MIN_HOLD_MS);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int ndc_check_yield_sleep_not_hold_time(struct ndc_fix_ctx *fx)
{
    return ndc_hold_case(fx, 0) + ndc_hold_case(fx, 1);
}

/* A walk that dies right after its first timed commit leaves that batch
 * durable with the cursor on its last block; the next run resumes from it. */
static int ndc_check_timed_commit_survives_abort(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "resume");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_detached_writer_test_reset();
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    node_db_catchup_lock_guard_test_use_fake_clock(true);
    node_db_catchup_lock_guard_test_set_batch_max_secs(1);
    node_db_catchup_lock_guard_test_set_height_delay_ms(400);
    node_db_catchup_test_force_reopen_busy(NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
    int first = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                   : 0;
    int tip1 = up ? node_db_sync_get_tip_height(&ndb) : -1;
    int max1 = up ? db_block_max_height(&ndb) : -1;
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    blocker_reset_for_testing();
    int second = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                    : 0;
    int tip2 = up ? node_db_sync_get_tip_height(&ndb) : -1;
    printf("timed commit abort: first=%d tip1=%d second=%d tip2=%d\n", first,
           tip1, second, tip2);
    NDC_CHECK("the aborted walk left its first timed batch durable at h=1",
              up && first <= 0 && tip1 == 1);
    NDC_CHECK("the h=1 block row is durable after the abort",
              up && max1 == 1);
    NDC_CHECK("the next walk resumes and reaches the tip",
              up && second == NDC_FIX_N - 1 && tip2 == NDC_FIX_N);
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── An unreadable projection tip is not an absent one ──────────────────
 * A failed read of sync_projection_tip_height used to come back as the "no
 * tip" sentinel, so a synced node walked its whole chain from genesis in bulk
 * mode and dropped every secondary index. A one-shot SQLite authorizer
 * refuses the next node_state read, failing the tip read with a real
 * SQLITE_AUTH, and counts DROP INDEX statements, which only turbo mode
 * prepares. */
struct ndc_tip_auth {
    int deny_reads;
    int denied;
    int index_drops;
    int sync_off;
    int index_creates;
};

static int ndc_tip_authorizer(void *arg, int action, const char *table,
                              const char *column, const char *db_name,
                              const char *trigger)
{
    struct ndc_tip_auth *auth = arg;
    (void)db_name;
    (void)trigger;
    if (action == SQLITE_DROP_INDEX)
        auth->index_drops++;
    if (action == SQLITE_CREATE_INDEX)
        auth->index_creates++;
    if (action == SQLITE_PRAGMA && table && column &&
        strcasecmp(table, "synchronous") == 0 && strcasecmp(column, "OFF") == 0)
        auth->sync_off++;
    if (action != SQLITE_READ || auth->deny_reads <= 0 || !table ||
        strcmp(table, "node_state") != 0)
        return SQLITE_OK;
    auth->deny_reads--;
    auth->denied++;
    return SQLITE_DENY;
}

/* The explorer indexes the 2026-11-03 phone boot had to rebuild. */
static int ndc_explorer_index_count(struct node_db *ndb)
{
    static const char sql[] =
        "SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN "
        "('idx_txo_addr','idx_txo_height','idx_txo_hodl_scan',"
        "'idx_txi_prev','idx_txi_prev_height','idx_txi_height')";
    sqlite3_stmt *stmt = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static int ndc_count_substr(const char *text, const char *needle)
{
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = strstr(text, needle); p; p = strstr(p + len, needle))
        n++;
    return n;
}

/* One catchup pass under the authorizer, its stderr captured into log. */
static int ndc_tip_auth_run(struct node_db *ndb, struct ndc_fix_ctx *fx,
                            struct ndc_tip_auth *auth, char *log,
                            size_t log_len)
{
    g_cap_ndb = ndb;
    g_cap_chain = &fx->ac;
    g_cap_datadir = fx->dirF;
    g_cap_result = -99;
    bool installed =
        sqlite3_set_authorizer(ndb->db, ndc_tip_authorizer, auth) == SQLITE_OK;
    bool captured = installed &&
        ndc_capture_stderr(ndc_run_catchup_capture, log, log_len);
    sqlite3_set_authorizer(ndb->db, NULL, NULL);
    return captured ? g_cap_result : -99;
}

/* A failed tip read runs no pass: no walk from genesis, no turbo mode, every
 * index kept, one warning naming the key and the SQLite error. The next pass
 * reads the real tip and walks only the block it is behind. */
static int ndc_check_unreadable_tip_skips_pass(struct node_db *ndb,
                                               struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct ndc_tip_auth auth = {.deny_reads = 1};
    char log[16384];
    int res = ndc_tip_auth_run(ndb, fx, &auth, log, sizeof(log));
    int tip = node_db_sync_get_tip_height(ndb);
    printf("unreadable tip: result=%d tip=%d denied=%d index_drops=%d\n",
           res, tip, auth.denied, auth.index_drops);
    NDC_CHECK("the tip read is refused exactly once", auth.denied == 1);
    NDC_CHECK("an unreadable tip starts no pass from genesis",
              res == 0 && tip == NDC_FIX_N - 1);
    NDC_CHECK("an unreadable tip never enters turbo mode",
              auth.index_drops == 0);
    NDC_CHECK("an unreadable tip keeps every explorer index",
              ndc_explorer_index_count(ndb) == 6);
    NDC_CHECK("an unreadable tip logs one warning with key and error",
              ndc_count_substr(log, "projection tip read failed") == 1 &&
              strstr(log, "key=sync_projection_tip_height") != NULL &&
              strstr(log, "prohibited") != NULL);

    struct ndc_tip_auth retry = {0};
    res = ndc_tip_auth_run(ndb, fx, &retry, log, sizeof(log));
    NDC_CHECK("the next pass resumes from the real tip",
              res == 1 && node_db_sync_get_tip_height(ndb) == NDC_FIX_N &&
              retry.index_drops == 0);
    return failures;
}

/* An absent key still means "no tip" (the -reindex-explorer reset): the pass
 * walks from genesis, over the bulk threshold in turbo mode, and normal mode
 * rebuilds the indexes after it. */
static int ndc_check_absent_tip_walks_from_genesis(struct node_db *ndb,
                                                   struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct ndc_tip_auth auth = {0};
    char log[16384];
    int64_t stored = 0;
    bool absent =
        node_db_state_delete(ndb, "sync_projection_tip_height") &&
        !node_db_state_get_int(ndb, "sync_projection_tip_height", &stored);
    int res = absent ? ndc_tip_auth_run(ndb, fx, &auth, log, sizeof(log))
                     : -99;
    int tip = node_db_sync_get_tip_height(ndb);
    printf("absent tip: result=%d tip=%d index_drops=%d\n", res, tip,
           auth.index_drops);
    NDC_CHECK("an absent tip key walks the chain from genesis",
              absent && res == NDC_FIX_N && tip == NDC_FIX_N);
    NDC_CHECK("the genesis walk is a bulk pass in turbo mode",
              auth.index_drops > 0);
    NDC_CHECK("normal mode rebuilds the explorer indexes after it",
              ndc_explorer_index_count(ndb) == 6);
    return failures;
}

static int ndc_check_tip_read_failure(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];

    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "tipread");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_catchup_lock_guard_test_reset();
    int res = up ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF)
                 : -1;
    /* One block behind the chain, as a synced node is between blocks. */
    bool behind = up && res == NDC_FIX_N &&
        node_db_sync_set_tip(&ndb, fx->hashes[NDC_FIX_N - 1].data,
                             NDC_FIX_N - 1);
    NDC_CHECK("tip-read fixture is one block behind with its indexes",
              behind && ndc_explorer_index_count(&ndb) == 6);
    /* A walk from genesis covers NDC_FIX_N + 1 heights and is a bulk pass;
     * the one-block pass is not. */
    node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    if (behind) {
        failures += ndc_check_unreadable_tip_skips_pass(&ndb, fx);
        failures += ndc_check_absent_tip_walks_from_genesis(&ndb, fx);
    }
    node_db_catchup_lock_guard_test_reset();
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

enum { NDC_SECONDARY_INDEXES = 19 };

/* The secondary indexes node_db_ibd_turbo_mode drops (database_modes.c). */
static int ndc_secondary_index_count(struct node_db *ndb)
{
    static const char sql[] =
        "SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN "
        "('idx_utxo_address','idx_utxo_value','idx_utxo_height',"
        "'idx_utxo_height_value','idx_tx_block','idx_tx_height',"
        "'idx_txo_addr','idx_txo_height','idx_txo_hodl_scan','idx_txi_prev',"
        "'idx_txi_prev_height','idx_txi_height','idx_ss_nf','idx_ss_height',"
        "'idx_so_height','idx_js_height','idx_spnf_height',"
        "'idx_opret_height','idx_opret_slp')";
    sqlite3_stmt *stmt = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

/* One pass from genesis under the authorizer, with `ms` registered as the
 * runtime main_state; NULL registers no runtime. */
static int ndc_genesis_pass(struct node_db *ndb, struct ndc_fix_ctx *fx,
                            struct main_state *ms, struct ndc_tip_auth *auth)
{
    char log[16384];
    struct app_runtime_context rt = {.main_state = ms};
    if (!node_db_state_delete(ndb, "sync_projection_tip_height"))
        return -99;
    app_runtime_set_current(ms ? &rt : NULL);
    int res = ndc_tip_auth_run(ndb, fx, auth, log, sizeof(log));
    app_runtime_set_current(NULL);
    return res;
}

/* A main_state whose tip reads as validated and recent, so
 * is_initial_block_download() returns false for it. */
static bool ndc_at_tip_main_state(struct main_state *ms,
                                  struct block_index *tip)
{
    main_state_init(ms);
    memset(tip, 0, sizeof(*tip));
    memset(tip->nChainWork.pn, 0xff, sizeof(tip->nChainWork.pn));
    ms->nMaxTipAge = INT64_MAX / 2;
    return active_chain_install_tip_slot(&ms->chain_active, tip);
}

/* ── A node serving its tip keeps node.db's indexes ────────────────────
 * 2026-11-03: a phone at its tip ran a catch-up pass from height 1 in turbo
 * mode and dropped idx_txo_addr with the other secondary indexes; the wallet
 * restore that followed scanned the whole node.db for each derived address.
 * The pass now asks the registered main_state. During initial block download
 * it still drops the indexes; at a validated tip it prepares no DROP INDEX and
 * no synchronous=OFF. is_initial_block_download() latches false once it reads
 * a recent tip, so the download fixture runs first. */
static int ndc_check_serving_tip_keeps_indexes(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "serving");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    int fresh = up ? ndc_secondary_index_count(&ndb) : -1;
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_bulk_threshold(2);

    struct main_state ibd;
    main_state_init(&ibd);
    struct ndc_tip_auth in_ibd = {0};
    int res = up ? ndc_genesis_pass(&ndb, fx, &ibd, &in_ibd) : -99;
    printf("download pass: result=%d index_drops=%d sync_off=%d indexes=%d\n",
           res, in_ibd.index_drops, in_ibd.sync_off, fresh);
    NDC_CHECK("a fresh node.db carries every secondary index",
              fresh == NDC_SECONDARY_INDEXES);
    NDC_CHECK("a bulk pass during initial block download runs in turbo mode",
              res == NDC_FIX_N && in_ibd.index_drops > 0);
    NDC_CHECK("normal mode rebuilds the indexes after the download pass",
              up && ndc_secondary_index_count(&ndb) == NDC_SECONDARY_INDEXES);

    struct main_state at_tip;
    struct block_index tip;
    bool tipped = ndc_at_tip_main_state(&at_tip, &tip);
    struct ndc_tip_auth serving = {0};
    res = up && tipped ? ndc_genesis_pass(&ndb, fx, &at_tip, &serving) : -99;
    printf("serving pass: result=%d index_drops=%d sync_off=%d tip=%d\n",
           res, serving.index_drops, serving.sync_off,
           up ? node_db_sync_get_tip_height(&ndb) : -1);
    NDC_CHECK("a bulk pass on a node serving its tip indexes every block",
              res == NDC_FIX_N && node_db_sync_get_tip_height(&ndb) == NDC_FIX_N);
    NDC_CHECK("that pass never drops an index or turns synchronous off",
              tipped && serving.index_drops == 0 && serving.sync_off == 0);
    NDC_CHECK("every secondary index is in sqlite_master after that pass",
              up && ndc_secondary_index_count(&ndb) == NDC_SECONDARY_INDEXES);

    main_state_free(&at_tip);
    main_state_free(&ibd);
    node_db_catchup_lock_guard_test_reset();
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── Another writer's open transaction yields the pass ─────────────────
 * The 2026-11-03 phone log holds 14 "catchup: BEGIN failed — aborting"
 * passes, each "cannot start a transaction within a transaction": the db
 * worker, the wallet and RPC readers share node.db's one connection. Each
 * pass counted toward the abort-streak park, and a bulk pass had already
 * entered turbo mode inside the other writer's transaction. Such a pass now
 * yields: no mode change, no abort, the other transaction untouched, and the
 * next pass walks from the cursor. */
static int ndc_check_foreign_txn_yields(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512], log[16384];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "foreign");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    bool held = up && sqlite3_exec(ndb.db, "BEGIN IMMEDIATE", NULL, NULL,
                                   NULL) == SQLITE_OK;
    struct ndc_tip_auth auth = {0};
    int res = held ? ndc_tip_auth_run(&ndb, fx, &auth, log, sizeof(log)) : -99;
    bool still_held = held && !sqlite3_get_autocommit(ndb.db);
    int yields = node_db_catchup_lock_guard_test_open_yields();
    int streak = node_db_catchup_lock_guard_test_abort_streak();
    printf("foreign transaction: result=%d index_drops=%d sync_off=%d "
           "yields=%d streak=%d held=%d\n", res, auth.index_drops,
           auth.sync_off, yields, streak, still_held);
    NDC_CHECK("a pass inside another writer's transaction yields unwalked",
              held && res == 0);
    NDC_CHECK("the yielding pass enters no turbo mode",
              held && auth.index_drops == 0 && auth.sync_off == 0);
    NDC_CHECK("the yield is not an aborted pass", yields == 1 && streak == 0);
    NDC_CHECK("the other writer's transaction is left open", still_held);

    bool released = still_held &&
        sqlite3_exec(ndb.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    struct ndc_tip_auth next = {0};
    res = released ? ndc_tip_auth_run(&ndb, fx, &next, log, sizeof(log)) : -99;
    NDC_CHECK("the next pass walks from the cursor once the writer is done",
              res == NDC_FIX_N &&
              node_db_sync_get_tip_height(&ndb) == NDC_FIX_N &&
              node_db_catchup_lock_guard_test_open_yields() == 0);
    node_db_catchup_lock_guard_test_reset();
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Another writer's BEGIN lands between the pass's turbo entry and its own
 * BEGIN IMMEDIATE: the pass then yields with turbo mode entered. */
static void ndc_race_foreign_begin(struct node_db *ndb)
{
    sqlite3_exec(ndb->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
}

/* ── A yield after turbo entry must not restore inside the foreign txn ──
 * The restore (node_db_normal_mode) would run PRAGMA synchronous (refused
 * inside a transaction, so synchronous stays OFF) and CREATE INDEX inside the
 * other writer's transaction. The restore is owed instead, and runs at the
 * start of the next pass that finds the connection idle. */
static int ndc_check_yield_after_turbo_defers_restore(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    char dir[256], path[512], log[16384];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "owed");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool up = fx->built && node_db_open(&ndb, path);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    node_db_catchup_test_set_after_turbo_hook(ndc_race_foreign_begin);
    struct ndc_tip_auth auth = {0};
    int res = up ? ndc_tip_auth_run(&ndb, fx, &auth, log, sizeof(log)) : -99;
    bool held = up && !sqlite3_get_autocommit(ndb.db);
    int sync_in_txn = up ? node_db_synchronous_level(&ndb) : -1;
    printf("yield after turbo: result=%d held=%d index_drops=%d "
           "index_creates=%d sync=%d\n", res, held, auth.index_drops,
           auth.index_creates, sync_in_txn);
    NDC_CHECK("the pass yields with the foreign transaction still open",
              res == 0 && held && auth.index_drops > 0);
    NDC_CHECK("no index is created inside the foreign transaction",
              auth.index_creates == 0);

    bool released = held &&
        sqlite3_exec(ndb.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    struct ndc_tip_auth next = {0};
    res = released ? ndc_tip_auth_run(&ndb, fx, &next, log, sizeof(log)) : -99;
    printf("owed restore: result=%d sync=%d indexes=%d creates=%d\n", res,
           up ? node_db_synchronous_level(&ndb) : -1,
           up ? ndc_secondary_index_count(&ndb) : -1, next.index_creates);
    NDC_CHECK("the next idle pass walks and finishes",
              released && res == NDC_FIX_N);
    NDC_CHECK("synchronous is back to NORMAL once the restore ran",
              up && node_db_synchronous_level(&ndb) == 1);
    NDC_CHECK("every secondary index is back after the owed restore",
              up && ndc_secondary_index_count(&ndb) == NDC_SECONDARY_INDEXES);
    node_db_catchup_test_set_after_turbo_hook(NULL);
    node_db_catchup_lock_guard_test_reset();
    if (up) node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

static void ndc_release_five_block_fixture(struct ndc_fix_ctx *fx)
{
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_test_reset_reopen();
    blocker_reset_for_testing();
    if (fx->openA) node_db_close(&fx->ndbA);
    if (fx->openB) node_db_close(&fx->ndbB);
    if (fx->openC) node_db_close(&fx->ndbC);
    if (fx->openR) node_db_close(&fx->ndbR);
    active_chain_free(&fx->ac);
    test_cleanup_tmpdir(fx->dirF);
    test_cleanup_tmpdir(fx->dirA);
    test_cleanup_tmpdir(fx->dirB);
    test_cleanup_tmpdir(fx->dirC);
    test_cleanup_tmpdir(fx->dirD);
    test_cleanup_tmpdir(fx->dirR);
    test_cleanup_tmpdir(fx->dirS);
}

static int ndc_fork_row_count(struct node_db *ndb, const uint8_t hash[32],
                              const uint8_t *prev)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = prev ? "SELECT count(*) FROM blocks WHERE hash=? AND prev_hash=?"
                           : "SELECT count(*) FROM blocks WHERE hash=?";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
    if (prev) sqlite3_bind_blob(stmt, 2, prev, 32, SQLITE_TRANSIENT);
    int count = sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return count;
}

static int ndc_fork_status(struct node_db *ndb, const uint8_t hash[32])
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT status FROM blocks WHERE hash=?",
                           -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_TRANSIENT);
    int status = sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return status;
}

static int ndc_check_competing_fork_parent(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:")) return 1;
    struct db_block parent = {0}, child = {0};
    parent.hash[0] = 0x11; parent.height = 1; parent.status = 3;
    parent.prev_hash[0] = 0x33; parent.merkle_root[0] = 0x44;
    parent.time = 1700000123u; parent.bits = 0x2000ffffu;
    uint8_t solution = 1; parent.solution = &solution; parent.solution_len = 1;
    child.hash[0] = 0x22; child.height = 2; child.status = 3;
    child.merkle_root[0] = 0x55; child.time = parent.time; child.bits = parent.bits;
    child.solution = &solution; child.solution_len = 1;
    memcpy(child.prev_hash, parent.hash, 32);
    bool seeded = db_block_save(&ndb, &parent) && db_block_save(&ndb, &child);
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000123u;
    blk.header.nBits = 0x2000ffffu;
    blk.header.hashPrevBlock.data[0] = 0x33;
    blk.header.hashMerkleRoot.data[0] = 0x44;
    struct uint256 competing;
    block_get_hash(&blk, &competing);
    struct block_index index = {0};
    index.nHeight = 1; index.nStatus = BLOCK_HAVE_DATA;
    index.phashBlock = &competing;
    int before_parent = ndc_fork_row_count(&ndb, parent.hash, NULL);
    int before_child = ndc_fork_row_count(&ndb, child.hash, parent.hash);
    bool trigger = sqlite3_exec(ndb.db, "CREATE TRIGGER fail_competing BEFORE INSERT ON blocks "
        "BEGIN SELECT RAISE(ABORT, 'fixture insert failure'); END", NULL, NULL, NULL) == SQLITE_OK;
    bool began = sqlite3_exec(ndb.db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    bool refused = seeded && trigger && began &&
        !node_db_catchup_test_sync_block_lean(&ndb, &blk, &index);
    bool rolled = sqlite3_exec(ndb.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    NDC_CHECK("insert failure rollback preserves the original fork and child",
              refused && rolled);
    NDC_CHECK("rollback retains parent", ndc_fork_row_count(&ndb, parent.hash, NULL) == 1);
    NDC_CHECK("rollback restores status", ndc_fork_status(&ndb, parent.hash) == 3);
    NDC_CHECK("rollback retains child link", ndc_fork_row_count(&ndb, child.hash, parent.hash) == 1);
    NDC_CHECK("rollback excludes competing row", ndc_fork_row_count(&ndb, competing.data, NULL) == 0);
    bool dropped = sqlite3_exec(ndb.db, "DROP TRIGGER fail_competing", NULL, NULL, NULL) == SQLITE_OK;
    bool saved = dropped && node_db_catchup_test_sync_block_lean(&ndb, &blk, &index);
    int after_parent = ndc_fork_row_count(&ndb, parent.hash, NULL);
    int after_child = ndc_fork_row_count(&ndb, child.hash, parent.hash);
    int after_competing = ndc_fork_row_count(&ndb, competing.data, NULL);
    printf("fork witness: seeded=%d saved=%d before_parent=%d before_child=%d "
           "after_parent=%d after_child=%d after_competing=%d\n",
           seeded, saved, before_parent, before_child, after_parent,
           after_child, after_competing);
    NDC_CHECK("catchup preserves the existing fork parent and child",
              seeded && saved && before_parent == 1 && before_child == 1);
    NDC_CHECK("both fork rows remain", after_parent == 1 && after_competing == 1);
    NDC_CHECK("child link remains", after_child == 1);
    NDC_CHECK("old fork demoted", ndc_fork_status(&ndb, parent.hash) == BLOCK_VALID_TREE);
    NDC_CHECK("new fork canonical", ndc_fork_status(&ndb, competing.data) >= 3);
    bool saved_again = node_db_catchup_test_sync_block_lean(&ndb, &blk, &index);
    NDC_CHECK("repeating catchup preserves both forks and child",
              saved_again);
    NDC_CHECK("repeat retains parent", ndc_fork_row_count(&ndb, parent.hash, NULL) == 1);
    NDC_CHECK("repeat retains demotion", ndc_fork_status(&ndb, parent.hash) == BLOCK_VALID_TREE);
    NDC_CHECK("repeat retains child link", ndc_fork_row_count(&ndb, child.hash, parent.hash) == 1);
    NDC_CHECK("repeat retains competitor", ndc_fork_row_count(&ndb, competing.data, NULL) == 1);
    block_free(&blk);
    node_db_close(&ndb);
    return failures;
}

static bool ndc_seed_service_conflict(struct node_db *ndb, struct db_block *parent,
                                      struct db_block *child)
{
    static uint8_t solution = 1;
    memset(parent, 0, sizeof(*parent));
    memset(child, 0, sizeof(*child));
    parent->hash[0] = 0xa1; parent->height = 1; parent->status = 3;
    parent->prev_hash[0] = 0xa0; parent->merkle_root[0] = 0xa2;
    parent->time = 1700000123u; parent->bits = 0x2000ffffu;
    parent->solution = &solution; parent->solution_len = 1;
    child->hash[0] = 0xb1; child->height = 2; child->status = 3;
    memcpy(child->prev_hash, parent->hash, 32);
    child->merkle_root[0] = 0xb2; child->time = parent->time;
    child->bits = parent->bits; child->solution = &solution; child->solution_len = 1;
    return db_block_save(ndb, parent) && db_block_save(ndb, child);
}

struct ndc_insert_failure_probe { int calls; int old_status; };

static void ndc_abort_competing_insert(sqlite3_context *ctx, int argc,
                                       sqlite3_value **argv)
{
    struct ndc_insert_failure_probe *probe = sqlite3_user_data(ctx);
    probe->calls++;
    probe->old_status = argc == 1 ? sqlite3_value_int(argv[0]) : -1;
    sqlite3_result_error(ctx, "fixture insert failure", -1);
}

static int ndc_check_service_conflict_rollback(struct ndc_fix_ctx *fx)
{
    int failures = 0;
    struct node_db ndb;
    struct db_block parent, child;
    struct ndc_insert_failure_probe probe = {0};
    if (!node_db_open(&ndb, ":memory:")) return 1;
    bool seeded = ndc_seed_service_conflict(&ndb, &parent, &child);
    bool registered = sqlite3_create_function_v2(ndb.db, "fixture_abort", 1,
        SQLITE_UTF8, &probe, ndc_abort_competing_insert, NULL, NULL, NULL) == SQLITE_OK;
    bool trigger = registered && sqlite3_exec(ndb.db,
        "CREATE TRIGGER fail_competing BEFORE INSERT ON blocks "
        "WHEN NEW.height=1 AND NEW.hash<>X'A100000000000000000000000000000000000000000000000000000000000000' "
        "BEGIN SELECT fixture_abort((SELECT status FROM blocks WHERE "
        "hash=X'A100000000000000000000000000000000000000000000000000000000000000')); END",
        NULL, NULL, NULL) == SQLITE_OK;
    int result = seeded && trigger && fx->built
        ? node_db_catchup_service_run(&ndb, &fx->ac, NULL, fx->dirF) : -99;
    int parent_count = ndc_fork_row_count(&ndb, parent.hash, NULL);
    int parent_status = ndc_fork_status(&ndb, parent.hash);
    int child_count = ndc_fork_row_count(&ndb, child.hash, parent.hash);
    int competing_count = ndc_fork_row_count(&ndb, fx->hashes[1].data, NULL);
    int tip = node_db_sync_get_tip_height(&ndb);
    printf("service rollback: seeded=%d trigger=%d result=%d calls=%d demoted_status=%d parent=%d status=%d "
           "child=%d competing=%d tip=%d\n", seeded, trigger, result, probe.calls, probe.old_status,
           parent_count, parent_status, child_count, competing_count, tip);
    NDC_CHECK("full catchup rolls back a failed competing insert",
              seeded && trigger && result <= 0 && result != -99);
    NDC_CHECK("injected failure observed demotion", probe.calls == 1 && probe.old_status == BLOCK_VALID_TREE);
    NDC_CHECK("service rollback retains parent", parent_count == 1 && parent_status == 3);
    NDC_CHECK("service rollback retains child", child_count == 1);
    NDC_CHECK("service rollback excludes competitor", competing_count == 0);
    NDC_CHECK("service rollback does not advance tip", tip < 1);
    node_db_close(&ndb);
    return failures;
}

static int ndc_check_shielded_values(int64_t balance, const char *label)
{
    int failures = 0;
    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:")) return 1;
    struct js_description js = {0};
    js.vpub_old = 17;
    js.vpub_new = 5;
    struct transaction tx = {0};
    tx.hash.data[0] = 0x61;
    tx.value_balance = balance;
    tx.v_joinsplit = &js;
    tx.num_joinsplit = 1;
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000123u;
    blk.header.nBits = 0x2000ffffu;
    blk.header.hashPrevBlock.data[0] = 0x33;
    blk.header.hashMerkleRoot.data[0] = 0x44;
    blk.vtx = &tx;
    blk.num_vtx = 1;
    struct uint256 hash;
    block_get_hash(&blk, &hash);
    struct block_index parent = {0}, index = {0};
    parent.nChainSproutValue = 1000;
    parent.nChainSaplingValue = 2000;
    parent.has_chain_sprout_value = true;
    parent.has_chain_sapling_value = true;
    index.pprev = &parent;
    index.nHeight = 1;
    index.nStatus = BLOCK_HAVE_DATA;
    index.phashBlock = &hash;
    int64_t expected_sprout = 0, expected_sapling = 0;
    connect_block_shielded_values(&blk, &expected_sprout, &expected_sapling);
    uint8_t direct_receipt[32] = {0}, saved_receipt[32] = {0};
    int64_t explorer_sprout = 0, explorer_sapling = 0;
    bool saved = node_db_catchup_test_sync_block_lean(&ndb, &blk, &index);
    bool receipt_found = db_view_integrity_get(&ndb, 1, saved_receipt);
    bool projected = explorer_index_block(&ndb, &blk, &index, NULL, direct_receipt,
                                          &explorer_sprout, &explorer_sapling);
    printf("shielded receipt %s ", label);
    for (size_t i = 0; i < sizeof(saved_receipt); i++) printf("%02x", saved_receipt[i]);
    printf(" explorer_sprout=%lld explorer_sapling=%lld\n",
           (long long)explorer_sprout, (long long)explorer_sapling);
    NDC_CHECK("explorer projection retains historical values", projected && explorer_sprout == expected_sprout && explorer_sapling == balance);
    NDC_CHECK("catchup retains explorer receipt", projected && receipt_found && memcmp(direct_receipt, saved_receipt, 32) == 0);
    struct db_block row = {0};
    bool found = saved && db_block_find_by_hash(&ndb, hash.data, &row);
    printf("shielded witness %s saved=%d found=%d sprout=%lld expected=%lld sapling=%lld expected=%lld\n",
           label, saved, found, (long long)row.sprout_value,
           (long long)expected_sprout, (long long)row.sapling_value,
           (long long)expected_sapling);
    NDC_CHECK("shielded witness saved exact row", saved && found);
    NDC_CHECK("shielded witness sprout delta", found && row.sprout_value == expected_sprout);
    NDC_CHECK("shielded witness sapling delta", found && row.sapling_value == expected_sapling);
    node_db_close(&ndb);
    return failures;
}

/* ── Sapling tree stays at the tip while old heights are walked ───────
 * A node that backfills old bodies walks heights far below the persisted
 * tree. The walk must not append their outputs to it, and a persisted copy
 * that disagrees with its header root must be replaced from the reducer
 * frontier or left alone, never extended. */
/* Fixture heights are NDC_SAP_OFF + 1 .. NDC_SAP_OFF + NDC_SAP_N on the test
 * network, whose Sapling activation is NDC_SAP_OFF. */
enum { NDC_SAP_N = 4, NDC_SAP_OFF = 20 };

enum ndc_sap_mutation { NDC_MUT_NONE, NDC_MUT_ZERO_ROOT_3, NDC_MUT_NO_SLOT_3 };

static int64_t ndc_sap_h(int64_t local)
{
    return local < 0 ? local : local + NDC_SAP_OFF;
}

struct ndc_sap_fix {
    char dir[256];
    struct uint256 hashes[NDC_SAP_N + 1];
    struct uint256 roots[NDC_SAP_N + 1];
    struct block_index slots[NDC_SAP_N + 1];
    struct active_chain ac;
    struct uint256 cm_real;
    struct uint256 cm_stray;
    bool built;
};

static void ndc_sap_tree_blob(const struct uint256 *cms, size_t n,
                              struct byte_stream *out)
{
    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    for (size_t i = 0; i < n; i++)
        incremental_tree_append(&t, &cms[i]);
    stream_init(out, 4096);
    incremental_tree_serialize(&t, out);
}

static bool ndc_sap_make_block(struct block *b, int h, const struct uint256 *cm)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1700000200u + (uint32_t)h;
    b->header.nBits = 0x2000ffffu;
    b->header.hashPrevBlock.data[0] = (uint8_t)h;
    b->header.hashMerkleRoot.data[0] = (uint8_t)(0x50 + h);
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (!b->vtx)
        return false;
    transaction_init(&b->vtx[0]);
    transaction_alloc(&b->vtx[0], 1, 1);
    b->vtx[0].vin[0].sequence = 0xffffffffu;
    b->vtx[0].vout[0].value = 5000000000LL + h;
    if (!cm)
        return true;
    b->vtx[0].overwintered = true;
    b->vtx[0].version = SAPLING_TX_VERSION;
    b->vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
    b->vtx[0].v_shielded_output =
        calloc(1, sizeof(struct output_description)); // raw-alloc-ok:test-fixture
    if (!b->vtx[0].v_shielded_output)
        return false;
    b->vtx[0].num_shielded_output = 1;
    b->vtx[0].v_shielded_output[0].cm = *cm;
    return true;
}

/* Heights 1..4; only height 2 carries a Sapling output. */
static bool ndc_sap_build(struct ndc_sap_fix *f, const char *label,
                          enum ndc_sap_mutation mut)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "node_db_catchup", label);
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", f->dir);
    mkdir(blocks, 0755);
    f->cm_real.data[0] = 0x11;
    f->cm_stray.data[0] = 0x77;
    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    struct disk_block_pos pos[NDC_SAP_N + 1];
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    f->built = true;
    for (int h = 1; h <= NDC_SAP_N && f->built; h++) {
        struct block b;
        f->built = ndc_sap_make_block(&b, h, h == 2 ? &f->cm_real : NULL);
        if (f->built && h == 2)
            incremental_tree_append(&t, &f->cm_real);
        incremental_tree_root(&t, &f->roots[h]);
        disk_block_pos_init(&pos[h]);
        f->built = f->built && write_block_to_disk(&b, &pos[h], f->dir, msg_start);
        block_get_hash(&b, &f->hashes[h]);
        block_free(&b);
    }
    active_chain_init(&f->ac);
    for (int h = 1; h <= NDC_SAP_N && f->built; h++) {
        memset(&f->slots[h], 0, sizeof(f->slots[h]));
        f->slots[h].nHeight = NDC_SAP_OFF + h;
        f->slots[h].nStatus = BLOCK_HAVE_DATA;
        f->slots[h].nFile = pos[h].nFile;
        f->slots[h].nDataPos = pos[h].nPos;
        f->slots[h].phashBlock = &f->hashes[h];
        f->slots[h].hashFinalSaplingRoot = f->roots[h];
        if (mut == NDC_MUT_ZERO_ROOT_3 && h == 3)
            memset(f->slots[h].hashFinalSaplingRoot.data, 0, 32);
        if (mut == NDC_MUT_NO_SLOT_3 && h == 3)
            continue;
        f->built = active_chain_install_tip_slot(&f->ac, &f->slots[h]);
    }
    return f->built;
}

static bool ndc_sap_seed(struct node_db *ndb, const struct uint256 *cms,
                         size_t n, int64_t height)
{
    struct byte_stream ts;
    ndc_sap_tree_blob(cms, n, &ts);
    bool ok = node_db_state_set(ndb, "sapling_tree", ts.data, ts.size) &&
              node_db_state_set_int(ndb, "sapling_tree_rebuild_height", height);
    stream_free(&ts);
    return ok;
}

static bool ndc_sap_read(struct node_db *ndb, size_t *size,
                         struct uint256 *root, int64_t *height)
{
    uint8_t buf[8192];
    size_t len = 0;
    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    if (!node_db_state_get(ndb, "sapling_tree", buf, sizeof(buf), &len) ||
        len == 0 ||
        !node_db_state_get_int(ndb, "sapling_tree_rebuild_height", height))
        return false;
    struct byte_stream ts;
    stream_init_from_data(&ts, buf, len);
    if (!incremental_tree_deserialize(&t, &ts))
        return false;
    *size = incremental_tree_size(&t);
    incremental_tree_root(&t, root);
    return true;
}

enum ndc_sap_seed_kind { NDC_SEED_NONE, NDC_SEED_EMPTY, NDC_SEED_GOOD, NDC_SEED_WRONG };

struct ndc_sap_case {
    const char *name;
    enum ndc_sap_seed_kind seed;
    int64_t seed_height;
    bool anchor;     /* reducer frontier {cm_real} at height 2 */
    int cursor;      /* projection cursor before the walk */
    long want_size;  /* -1: no persisted tree */
    int64_t want_height;
};

static bool ndc_sap_seed_case(struct ndc_sap_fix *f, struct node_db *ndb,
                              const struct ndc_sap_case *c)
{
    struct uint256 wrong[2] = {f->cm_real, f->cm_stray};
    switch (c->seed) {
    case NDC_SEED_NONE: return true;
    case NDC_SEED_EMPTY:
        return ndc_sap_seed(ndb, NULL, 0, ndc_sap_h(c->seed_height));
    case NDC_SEED_GOOD:
        return ndc_sap_seed(ndb, &f->cm_real, 1, ndc_sap_h(c->seed_height));
    case NDC_SEED_WRONG:
        return ndc_sap_seed(ndb, wrong, 2, ndc_sap_h(c->seed_height));
    }
    return false;
}

/* The reducer frontier goes into the real progress store; the walk reads it
 * through progress_store_open_reader(), the production path. */
static bool ndc_sap_open_store(struct ndc_sap_fix *f, const char *name,
                              bool anchor, int64_t activation)
{
    sqlite3 *db = NULL;
    char sdir[512];
    snprintf(sdir, sizeof(sdir), "%s/%s.store", f->dir, name);
    mkdir(sdir, 0755);
    if (!progress_store_open(sdir) || !(db = progress_store_db()) ||
        !anchor_kv_ensure_schema(db) ||
        !anchor_kv_initialize_history(db, activation))
        return false;
    if (!anchor)
        return true;
    struct incremental_merkle_tree good;
    sapling_tree_init(&good);
    incremental_tree_append(&good, &f->cm_real);
    return anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &good,
                              ndc_sap_h(2));
}

static int ndc_sap_verify(const struct ndc_sap_fix *f, const struct ndc_sap_case *c,
                          struct node_db *ndb, bool seeded, int rc)
{
    int failures = 0;
    size_t size = 0;
    int64_t height = -1;
    struct uint256 root = {0};
    bool read = seeded && ndc_sap_read(ndb, &size, &root, &height);
    printf("sapling walk %s: rc=%d read=%d size=%zu height=%lld\n", c->name,
           rc, read, size, (long long)height);
    NDC_CHECK("sapling walk completes", seeded && rc >= 0);
    if (c->want_size < 0) {
        NDC_CHECK("sapling walk persists no tree", seeded && !read);
        return failures;
    }
    NDC_CHECK("sapling tree size is the true size",
              read && size == (size_t)c->want_size);
    NDC_CHECK("sapling tree height is the walk height",
              read && height == ndc_sap_h(c->want_height));
    if (c->want_size == 1)
        NDC_CHECK("sapling tree root equals the header root",
                  read && memcmp(root.data,
                                 f->roots[c->want_height].data, 32) == 0);
    return failures;
}

static int ndc_sap_run(struct ndc_sap_fix *f, const struct ndc_sap_case *c)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.db", f->dir, c->name);
    struct node_db ndb;
    bool opened = node_db_open(&ndb, path);
    bool store = ndc_sap_open_store(f, c->name, c->anchor, 0);
    bool seeded = opened && store && ndc_sap_seed_case(f, &ndb, c) &&
        (c->cursor == 0 ||
         node_db_sync_set_tip(&ndb, f->hashes[c->cursor].data,
                              (int)ndc_sap_h(c->cursor)));
    int rc = seeded ? node_db_catchup_service_run(&ndb, &f->ac, NULL, f->dir)
                    : -99;
    int failures = ndc_sap_verify(f, c, &ndb, seeded, rc);
    if (store)
        progress_store_close();
    if (opened)
        node_db_close(&ndb);
    return failures;
}

/* An empty tree is the right tree only before Sapling activates. Past it, a
 * parent header without a root (zeroed, or absent from the chain) is damage,
 * not the pre-Sapling state: the walk must not start a tree there. */
static int ndc_check_sapling_empty_tree_needs_activation(void)
{
    static const struct ndc_sap_case c = {
        "empty_no_parent_root", NDC_SEED_NONE, -1, false, 3, -1, -1};
    static const enum ndc_sap_mutation muts[] = {
        NDC_MUT_ZERO_ROOT_3, NDC_MUT_NO_SLOT_3};
    int failures = 0;
    for (size_t i = 0; i < sizeof(muts) / sizeof(muts[0]); i++) {
        struct ndc_sap_fix f = {0};
        bool built = ndc_sap_build(&f, i == 0 ? "zeroroot" : "noslot",
                                   muts[i]);
        NDC_CHECK("sapling variant fixture builds", built);
        if (built)
            failures += ndc_sap_run(&f, &c);
        active_chain_free(&f.ac);
        test_cleanup_tmpdir(f.dir);
    }
    return failures;
}

static int ndc_check_sapling_tree_not_extended_by_old_heights(void)
{
    int failures = 0;
    struct ndc_sap_fix f = {0};
    chain_params_select(CHAIN_TESTNET); /* Sapling active from NDC_SAP_OFF */
    NDC_CHECK("sapling fixture builds",
              ndc_sap_build(&f, "sapling", NDC_MUT_NONE));
    static const struct ndc_sap_case cases[] = {
        /* A correct tip-sized tree; the walk revisits heights 1..4. */
        {"backfill", NDC_SEED_GOOD, 4, false, 0, 1, 4},
        /* A wrong copy replaced by the verified reducer frontier. */
        {"repair", NDC_SEED_WRONG, 4, true, 0, 1, 4},
        /* A wrong copy with no verified source is left untouched. */
        {"unrepairable", NDC_SEED_WRONG, 4, false, 0, 2, 4},
        /* A valid copy two heights behind the walk, bridged by header root. */
        {"gap_bridge", NDC_SEED_GOOD, 2, false, 3, 1, 4},
        /* A valid old copy, moved forward from the reducer frontier. */
        {"gap_anchor", NDC_SEED_EMPTY, 1, true, 3, 1, 4},
        /* No copy and no recorded height past Sapling: nothing is built. */
        {"empty_past_activation", NDC_SEED_NONE, -1, false, 3, -1, -1},
    };
    if (f.built)
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            failures += ndc_sap_run(&f, &cases[i]);
    active_chain_free(&f.ac);
    test_cleanup_tmpdir(f.dir);
    failures += ndc_check_sapling_empty_tree_needs_activation();
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── -catchup-from-seed ────────────────────────────────────────────────
 * The fixture chain has four blocks and the reducer store was adopted at seed
 * height 2 with the frontier of that height. With the option off a pass walks
 * every height as before. With it on the pass starts at height 3, leaves the
 * rows below untouched and absent, moves the cursor to the tip and continues
 * the Sapling tree from the seed frontier. */
static int ndc_seed_rows(struct node_db *ndb, const struct ndc_sap_fix *f,
                         bool want1, bool want2)
{
    struct db_block row = {0};
    int failures = 0;
    NDC_CHECK("seed walk: the block above the seed is indexed",
              db_block_find_by_hash(ndb, f->hashes[3].data, &row) &&
              db_block_find_by_hash(ndb, f->hashes[4].data, &row));
    NDC_CHECK("seed walk: height 1 row presence",
              db_block_find_by_hash(ndb, f->hashes[1].data, &row) == want1);
    NDC_CHECK("seed walk: height 2 row presence",
              db_block_find_by_hash(ndb, f->hashes[2].data, &row) == want2);
    return failures;
}

/* What the store and the option say about the seed before the pass runs. */
static int ndc_seed_pre(bool store, bool option, int64_t activation)
{
    int failures = 0;
    NDC_CHECK("seed walk: the store reports its seed height",
              store && node_db_catchup_seed_height() ==
                           (activation > 0 ? (int)activation : -1));
    NDC_CHECK("seed walk: the skipped prefix is expected only with the option",
              store && node_db_catchup_seed_prefix_expected() ==
                           (option && activation > 0));
    return failures;
}

/* What the pass left in node.db. */
static int ndc_seed_post(struct ndc_sap_fix *f, struct node_db *ndb, int rc,
                         int want_rc)
{
    int failures = 0;
    size_t size = 0;
    int64_t height = -1;
    struct uint256 root = {0};
    NDC_CHECK("seed walk: the pass indexes the expected blocks",
              rc == want_rc);
    NDC_CHECK("seed walk: the cursor reaches the tip",
              node_db_sync_get_tip_height(ndb) == (int)ndc_sap_h(NDC_SAP_N));
    NDC_CHECK("seed walk: the Sapling tree is the true tree at the tip",
              ndc_sap_read(ndb, &size, &root, &height) && size == 1 &&
              height == ndc_sap_h(NDC_SAP_N) &&
              memcmp(root.data, f->roots[NDC_SAP_N].data, 32) == 0);
    return failures;
}

/* What the pass decided about the option: when it walked a wallet prefix, the
 * prefix is not expected absent and the option is not effective. */
static int ndc_seed_effective(bool option, int64_t activation,
                              const struct wallet *w, bool walked_low)
{
    int failures = 0;
    bool wallet_walked = w && walked_low;
    NDC_CHECK("seed walk: a walked wallet prefix is no longer expected absent",
              node_db_catchup_seed_prefix_expected() ==
                  (option && activation > 0 && !wallet_walked));
    NDC_CHECK("seed walk: the effective option is off when the prefix is walked",
              !w || node_db_catchup_from_seed_effective() == !walked_low);
    return failures;
}

static int ndc_seed_case(struct ndc_sap_fix *f, const char *name, bool option,
                         int64_t activation, int cursor, int want_rc,
                         bool want_low_rows,
                         struct wallet *w)
{
    int failures = 0;
    /* activation and cursor are fixture-local heights; 0 means none. */
    activation = activation > 0 ? ndc_sap_h(activation) : 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.db", f->dir, name);
    struct node_db ndb;
    bool opened = node_db_open(&ndb, path);
    bool store = ndc_sap_open_store(f, name, true, activation);
    bool seeded = opened && store &&
        (cursor == 0 ||
         node_db_sync_set_tip(&ndb, f->hashes[cursor].data,
                              (int)ndc_sap_h(cursor)));
    node_db_catchup_set_from_seed(option);
    failures += ndc_seed_pre(store, option, activation);
    int rc = seeded ? node_db_catchup_service_run(&ndb, &f->ac, w, f->dir)
                    : -99;
    if (seeded)
        failures += ndc_seed_effective(option, activation, w, want_low_rows);
    node_db_catchup_set_from_seed(false);
    printf("seed walk %s: rc=%d\n", name, rc);
    NDC_CHECK("seed walk: the pass ran", seeded);
    if (seeded) {
        failures += ndc_seed_post(f, &ndb, rc, want_rc);
        if (cursor == 0)
            failures += ndc_seed_rows(&ndb, f, want_low_rows, want_low_rows);
    }
    if (store)
        progress_store_close();
    if (opened)
        node_db_close(&ndb);
    return failures;
}

/* A wallet that holds a key and may own notes at or below the seed must not
 * have that range skipped: the walk is what records its notes. A wallet whose
 * birthday floor is above the seed is skipped as before. */
static int ndc_seed_wallet_cases(struct ndc_sap_fix *f)
{
    int failures = 0;
    /* sizeof(struct wallet) is about 66 MiB: on the stack it overflows the
     * 64 MiB hard stack limit macOS allows (Linux raises it to unlimited),
     * so the SIGSEGV hit under the sanitizer builds on Darwin. */
    struct wallet *w = zcl_calloc(1, sizeof(*w), "ndc_seed_wallet");
    NDC_CHECK("seed walk: the wallet fixture allocates", w != NULL);
    if (!w) return failures;
    wallet_init(w);
    w->keystore.keys[0].used = true;
    w->keystore.num_keys = 1;
    NDC_CHECK("seed walk: a wallet with an unknown birthday needs the prefix",
              node_db_catchup_prefix_needed(2, 1, 0));
    NDC_CHECK("seed walk: a wallet born above the seed does not",
              !node_db_catchup_prefix_needed(2, 1, 3));
    NDC_CHECK("seed walk: a wallet without keys does not",
              !node_db_catchup_prefix_needed(2, 0, 0));
    NDC_CHECK("seed walk: no seed needs no prefix",
              !node_db_catchup_prefix_needed(-1, 1, 0));
    /* Birthday unknown: height 1 and 2 are indexed despite the option. */
    failures += ndc_seed_case(f, "wallet_below_seed", true, 2, 0, NDC_SAP_N,
                              true, w);
    /* Birthday above the seed: the prefix is skipped. */
    w->initial_scan_floor = (int)ndc_sap_h(3);
    failures += ndc_seed_case(f, "wallet_above_seed", true, 2, 0, 2, false,
                              w);
    wallet_free(w);
    free(w);
    return failures;
}

static int ndc_check_start_at_seed(void)
{
    int failures = 0;
    struct ndc_sap_fix f = {0};
    chain_params_select(CHAIN_TESTNET); /* Sapling active from NDC_SAP_OFF */
    NDC_CHECK("seed fixture builds", ndc_sap_build(&f, "seed", NDC_MUT_NONE));
    NDC_CHECK("first height: option off keeps the cursor",
              node_db_catchup_first_height(0, 2, false) == 0);
    NDC_CHECK("first height: the seed moves a lower cursor above it",
              node_db_catchup_first_height(0, 2, true) == 3);
    NDC_CHECK("first height: a cursor above the seed is kept",
              node_db_catchup_first_height(5, 2, true) == 5);
    NDC_CHECK("first height: no seed keeps the cursor",
              node_db_catchup_first_height(0, -1, true) == 0);
    if (f.built) {
        /* Default: all four heights are walked, as before. */
        failures += ndc_seed_case(&f, "default_off", false, 2, 0, NDC_SAP_N,
                                  true, NULL);
        /* Option on: heights 3 and 4 only; rows 1 and 2 are never written. */
        failures += ndc_seed_case(&f, "from_seed", true, 2, 0, 2, false, NULL);
        /* Option on, cursor already above the seed: unchanged. */
        failures += ndc_seed_case(&f, "cursor_above_seed", true, 2, 3, 1,
                                  false, NULL);
        /* Option on, store adopted from genesis: nothing to skip. */
        failures += ndc_seed_case(&f, "no_seed", true, 0, 0, NDC_SAP_N, true,
                                  NULL);
        /* Option on, wallet with keys: the prefix is walked. */
        failures += ndc_seed_wallet_cases(&f);
    }
    active_chain_free(&f.ac);
    test_cleanup_tmpdir(f.dir);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

static bool ndc_tip_note(struct node_db *ndb, uint8_t tag,
                         const struct uint256 *cm, int height)
{
    uint8_t txid[32] = {tag}, rcm[32] = {tag, 1}, memo[512] = {0};
    uint8_t ivk[32] = {9, tag}, div[11] = {tag}, pk_d[32] = {7, tag};
    uint8_t nf[32] = {5, tag};
    return node_db_sync_sapling_note(ndb, txid, 0, 1000, rcm, memo, 512, ivk,
                                     div, pk_d, cm->data, nf, height);
}

static bool ndc_tip_witness(struct node_db *ndb, uint8_t tag, int *height,
                            struct uint256 *root, uint8_t **blob, size_t *len)
{
    uint8_t txid[32] = {tag};
    struct incremental_merkle_tree proto;
    sapling_tree_init(&proto);
    if (!db_sapling_note_load_witness(ndb, txid, 0, blob, len, height) || !*blob)
        return false;
    struct incremental_witness w;
    struct byte_stream ws;
    stream_init_from_data(&ws, *blob, *len);
    if (!incremental_witness_deserialize(&w, &ws,
            SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, proto.combine,
            proto.uncommitted))
        return false;
    incremental_witness_root(&w, root);
    return true;
}

/* ── Wallet witnesses at the tip, independent of the catchup walk ─────
 * A seeded node: anchor history starts at the seed (height 3) and the
 * projection cursor is far behind. Chain A has four blocks with outputs at
 * 4 (three outputs over two transactions, the wallet note in the middle),
 * 5, and 7; chain B replaces block 6 and 7 of A. Block bodies come from a
 * table through the reader seam, as the disk reader does in production. */
enum { NT_A3, NT_A4, NT_A5, NT_A6, NT_A7, NT_B6, NT_B7, NT_NODES };
enum { NT_NOTE = 0x60, NT_LATE = 0x70 };

struct nt_node {
    struct block_index bi;
    struct block blk;
    struct transaction tx[2];
    struct uint256 root;
};

struct nt_fix {
    struct nt_node n[NT_NODES];
    struct uint256 cm[48];
    int refuse; /* node whose body the reader refuses, or -1 */
    bool with_b; /* store the replacement chain's anchor row */
};

static bool nt_outputs(struct nt_node *nd, int tx, int count,
                       struct uint256 *cms, struct incremental_merkle_tree *t)
{
    transaction_init(&nd->tx[tx]);
    if (count == 0)
        return true;
    nd->tx[tx].v_shielded_output =
        calloc((size_t)count, sizeof(struct output_description)); // raw-alloc-ok:test-fixture
    if (!nd->tx[tx].v_shielded_output)
        return false;
    nd->tx[tx].num_shielded_output = (size_t)count;
    for (int i = 0; i < count; i++) {
        nd->tx[tx].v_shielded_output[i].cm = cms[i];
        incremental_tree_append(t, &cms[i]);
    }
    return true;
}

/* One block: out0 + out1 outputs over up to two transactions, taking
 * commitments from cm[first..]; appended to t; anchor row at its height. */
static bool nt_block(struct nt_fix *f, int id, int prev, int h, int out0,
                     int out1, int first, struct incremental_merkle_tree *t,
                     sqlite3 *db)
{
    struct nt_node *nd = &f->n[id];
    bool ok = nt_outputs(nd, 0, out0, &f->cm[first], t) &&
              nt_outputs(nd, 1, out1, &f->cm[first + out0], t);
    incremental_tree_root(t, &nd->root);
    nd->bi.nHeight = h;
    nd->bi.hashFinalSaplingRoot = nd->root;
    nd->bi.pprev = prev < 0 ? NULL : &f->n[prev].bi;
    block_init(&nd->blk);
    nd->blk.vtx = nd->tx;
    nd->blk.num_vtx = 2;
    if (out0 + out1 > 0 && h != 7 && (f->with_b || id != NT_B6))
        ok = ok && anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, t, h);
    return ok;
}

static bool nt_build(struct nt_fix *f, sqlite3 *db)
{
    struct incremental_merkle_tree t, after5;
    sapling_tree_init(&t);
    for (int i = 1; i < 48; i++) {
        f->cm[i].data[0] = (uint8_t)i;
        f->cm[i].data[1] = 0x77;
    }
    f->refuse = -1;
    incremental_tree_append(&t, &f->cm[1]);
    incremental_tree_append(&t, &f->cm[2]);
    bool ok = anchor_kv_ensure_schema(db) && anchor_kv_initialize_history(db, 3);
    ok = ok && nt_block(f, NT_A3, -1, 3, 0, 0, 0, &t, db) &&
         anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &t, 3);
    ok = ok && nt_block(f, NT_A4, NT_A3, 4, 1, 2, 3, &t, db);
    ok = ok && nt_block(f, NT_A5, NT_A4, 5, 1, 0, 6, &t, db);
    after5 = t;
    ok = ok && nt_block(f, NT_A6, NT_A5, 6, 0, 0, 0, &t, db);
    ok = ok && nt_block(f, NT_A7, NT_A6, 7, 1, 0, 7, &t, db);
    t = after5;
    ok = ok && nt_block(f, NT_B6, NT_A5, 6, 1, 0, 40, &t, db);
    ok = ok && nt_block(f, NT_B7, NT_B6, 7, 0, 0, 0, &t, db);
    return ok;
}

static void nt_free(struct nt_fix *f)
{
    for (int i = 0; i < NT_NODES; i++)
        for (int j = 0; j < 2; j++)
            free(f->n[i].tx[j].v_shielded_output);
}

static bool nt_read(void *ctx, const struct block_index *bi, struct block *out)
{
    struct nt_fix *f = ctx;
    for (int i = 0; i < NT_NODES; i++) {
        const struct nt_node *nd = &f->n[i];
        if (i == f->refuse || nd->bi.nHeight != bi->nHeight ||
            !uint256_eq(&nd->root, &bi->hashFinalSaplingRoot))
            continue;
        block_init(out);
        out->vtx = calloc(2, sizeof(*out->vtx)); // raw-alloc-ok:test-fixture
        if (!out->vtx)
            return false;
        out->num_vtx = 2;
        return transaction_copy(&out->vtx[0], &nd->tx[0]) &&
               transaction_copy(&out->vtx[1], &nd->tx[1]);
    }
    return false;
}

struct nt_run {
    struct nt_fix *f;
    struct node_db *ndb;
    char label[64];
};

static bool nt_tip(struct nt_run *r, int id)
{
    struct sync_block_reader rd = { nt_read, r->f };
    struct block blk = r->f->n[id].blk;
    return node_db_sync_advance_tip_witnesses_with(
        r->ndb, &blk, &r->f->n[id].bi, NULL, &rd);
}

/* The note's witness: stored at the node's height and equal to its root. */
static bool nt_current(struct nt_run *r, uint8_t tag, int id)
{
    int wh = -1;
    struct uint256 root = {0};
    uint8_t *blob = NULL;
    size_t len = 0;
    bool got = ndc_tip_witness(r->ndb, tag, &wh, &root, &blob, &len);
    free(blob);
    return got && wh == r->f->n[id].bi.nHeight &&
           uint256_eq(&root, &r->f->n[id].root);
}

static int nt_summary(struct nt_run *r, int id, int ready, int missing,
                      int stale)
{
    struct db_sapling_witness_summary s;
    return db_sapling_note_witness_summary(r->ndb, r->f->n[id].bi.nHeight,
                                           &s) &&
           s.ready_notes == ready && s.missing_notes == missing &&
           s.stale_notes == stale;
}

/* A node.db, a progress store, and the wallet notes of a scenario. */
static bool nt_open(struct nt_run *r, struct node_db *ndb, char *dir,
                    const char *name, bool late_note)
{
    char path[512];
    test_make_tmpdir(dir, 256, "node_db_catchup", name);
    snprintf(path, sizeof(path), "%s/node.db", dir);
    r->ndb = ndb;
    snprintf(r->label, sizeof(r->label), "%s", name);
    return node_db_open(ndb, path) && progress_store_open(dir) &&
           nt_build(r->f, progress_store_db()) &&
           ndc_tip_note(ndb, NT_NOTE, &r->f->cm[4], 4) &&
           (!late_note || ndc_tip_note(ndb, NT_LATE, &r->f->cm[6], 5)) &&
           node_db_sync_set_tip(ndb, r->f->n[NT_A3].root.data, 1);
}

static void nt_close(struct nt_run *r, char *dir)
{
    progress_store_close();
    node_db_close(r->ndb);
    nt_free(r->f);
    test_cleanup_tmpdir(dir);
}

#define NT_SCENARIO(NAME, LATE, WITH_B) \
    static struct nt_fix f; \
    struct node_db ndb; \
    struct nt_run r = { &f, &ndb, {0} }; \
    char dir[256]; \
    int failures = 0; \
    memset(&f, 0, sizeof(f)); \
    f.with_b = (WITH_B); \
    bool up = nt_open(&r, &ndb, dir, NAME, LATE); \
    NDC_CHECK(NAME " fixture builds", up);

/* Three outputs over two transactions, the note in the middle, then later
 * blocks with and without outputs. */
static int nt_check_three_outputs(void)
{
    NT_SCENARIO("tip_three_outputs", true, false)
    static const int steps[] = { NT_A4, NT_A5, NT_A6, NT_A7 };
    for (size_t i = 0; i < 4 && up; i++) {
        NDC_CHECK("tip step succeeds", nt_tip(&r, steps[i]));
        NDC_CHECK("the note's witness equals the header root",
                  nt_current(&r, NT_NOTE, steps[i]));
        if (steps[i] >= NT_A5)
            NDC_CHECK("a note found one block later is witnessed too",
                      nt_current(&r, NT_LATE, steps[i]));
    }
    NDC_CHECK("the walk's cursor did not move",
              up && node_db_sync_get_tip_height(&ndb) == 1);
    NDC_CHECK("no note is missing or stale", up && nt_summary(&r, NT_A7, 2, 0, 0));
    nt_close(&r, dir);
    return failures;
}

/* Blocks 5 and 6 never reached the tip path; block 7 replays them, and a
 * note whose block was missed gets its witness. */
static int nt_check_missed_blocks(void)
{
    NT_SCENARIO("tip_missed_blocks", true, false)
    NDC_CHECK("block 4 witnessed", up && nt_tip(&r, NT_A4));
    NDC_CHECK("block 7 after a gap succeeds", up && nt_tip(&r, NT_A7));
    NDC_CHECK("the note catches up to 7", up && nt_current(&r, NT_NOTE, NT_A7));
    NDC_CHECK("the missed note is witnessed", up && nt_current(&r, NT_LATE, NT_A7));
    NDC_CHECK("nothing is stale", up && nt_summary(&r, NT_A7, 2, 0, 0));
    nt_close(&r, dir);
    return failures;
}

/* A note below the reducer's oldest frontier cannot be replayed. It must not
 * hold the other notes back: they reach the tip, and it is reported. */
static int nt_check_note_below_history(void)
{
    NT_SCENARIO("tip_below_history", false, false)
    enum { NT_OLD = 0x50 };
    NDC_CHECK("the old note is recorded",
              up && ndc_tip_note(&ndb, NT_OLD, &f.cm[10], 2));
    NDC_CHECK("block 4 succeeds", up && nt_tip(&r, NT_A4));
    NDC_CHECK("block 7 after a gap succeeds", up && nt_tip(&r, NT_A7));
    NDC_CHECK("the newer note reaches 7", up && nt_current(&r, NT_NOTE, NT_A7));
    NDC_CHECK("the old note is reported as needing a rescan",
              up && node_db_sync_tip_witness_needs_rescan() == 1);
    NDC_CHECK("the last note spent clears the rescan count",
              up && sqlite3_exec(ndb.db, "UPDATE wallet_sapling_notes SET "
                                   "spent_txid=x'01'", NULL, NULL, NULL) ==
                         SQLITE_OK &&
              nt_tip(&r, NT_A7) &&
              node_db_sync_tip_witness_needs_rescan() == 0);
    nt_close(&r, dir);
    return failures;
}

/* An unreadable body leaves witnesses behind, the summary says so, and the
 * next call with the body readable repairs them. */
static int nt_check_unreadable_body(void)
{
    NT_SCENARIO("tip_unreadable_body", true, false)
    NDC_CHECK("block 4 witnessed", up && nt_tip(&r, NT_A4));
    f.refuse = NT_A5;
    NDC_CHECK("block 7 still advances the tip", up && nt_tip(&r, NT_A7));
    NDC_CHECK("one note is stale and one missing",
              up && nt_summary(&r, NT_A7, 0, 1, 1));
    f.refuse = -1;
    NDC_CHECK("a later call replays", up && nt_tip(&r, NT_A7));
    NDC_CHECK("both repaired", up && nt_summary(&r, NT_A7, 2, 0, 0) &&
              nt_current(&r, NT_NOTE, NT_A7));
    nt_close(&r, dir);
    return failures;
}

/* Block A6 is replaced by B6: the wallet drops its witnesses at the
 * disconnected height and the tip path rebuilds them on chain B. */
static int nt_check_reorg_disconnect(void)
{
    NT_SCENARIO("tip_reorg_disconnect", false, true)
    for (int id = NT_A4; id <= NT_A6 && up; id++)
        NDC_CHECK("chain A witnessed", nt_tip(&r, id) && nt_current(&r, NT_NOTE, id));
    bool keep[2] = { false, false };
    struct block lost = f.n[NT_A6].blk;
    NDC_CHECK("disconnect succeeds",
              up && node_db_sync_wallet_disconnect_block(&ndb, &lost, keep, 6));
    NDC_CHECK("the witness at the disconnected height is gone",
              up && nt_summary(&r, NT_A6, 0, 1, 0));
    NDC_CHECK("chain B block succeeds", up && nt_tip(&r, NT_B7));
    NDC_CHECK("the witness is rebuilt on chain B",
              up && nt_current(&r, NT_NOTE, NT_B7));
    nt_close(&r, dir);
    return failures;
}

/* The same reorg when the disconnect hook never ran: the witness at the old
 * tip has the right height but the wrong root, and is dropped. */
static int nt_check_reorg_without_disconnect(void)
{
    NT_SCENARIO("tip_reorg_unhooked", false, true)
    for (int id = NT_A4; id <= NT_A6 && up; id++)
        NDC_CHECK("chain A witnessed", nt_tip(&r, id));
    NDC_CHECK("chain B block succeeds", up && nt_tip(&r, NT_B7));
    NDC_CHECK("the witness from the abandoned chain is not kept",
              up && !nt_current(&r, NT_NOTE, NT_B7) &&
              nt_summary(&r, NT_B7, 0, 1, 0));
    NDC_CHECK("it is rebuilt on the next call",
              up && nt_tip(&r, NT_B7) && nt_current(&r, NT_NOTE, NT_B7));
    nt_close(&r, dir);
    return failures;
}

/* Bodies for the long-chain scenario: the fixture's blocks up to height 5,
 * empty blocks above. */
static bool nt_read_long(void *ctx, const struct block_index *bi,
                         struct block *out)
{
    block_init(out);
    if (bi->nHeight < 6)
        return nt_read(ctx, bi, out);
    out->vtx = calloc(2, sizeof(*out->vtx)); // raw-alloc-ok:test-fixture
    if (!out->vtx)
        return false;
    out->num_vtx = 2;
    transaction_init(&out->vtx[0]);
    transaction_init(&out->vtx[1]);
    return true;
}

enum { NT_LONG_FIRST = 6, NT_LONG_BLOCKS = 300 };

/* A note found at height 4 whose witness a reorg cleared, with the tip 301
 * blocks later: more than one replay call covers. Every call advances the
 * witness by a bounded number of blocks and the second reaches the tip. */
static int nt_check_long_reorg(void)
{
    NT_SCENARIO("tip_long_reorg", false, false)
    static struct block_index lc[NT_LONG_BLOCKS];
    static struct transaction empty[2];
    struct block tipblk;
    block_init(&tipblk);
    tipblk.vtx = empty;
    tipblk.num_vtx = 2;
    transaction_init(&empty[0]);
    transaction_init(&empty[1]);
    memset(lc, 0, sizeof(lc));
    for (int i = 0; i < NT_LONG_BLOCKS; i++) {
        lc[i].nHeight = NT_LONG_FIRST + i;
        lc[i].hashFinalSaplingRoot = f.n[NT_A5].root;
        lc[i].pprev = i == 0 ? &f.n[NT_A5].bi : &lc[i - 1];
    }
    const struct block_index *tip = &lc[NT_LONG_BLOCKS - 1];
    struct sync_block_reader rd = { nt_read_long, &f };
    NDC_CHECK("blocks 4 and 5 witnessed", up && nt_tip(&r, NT_A4) &&
              nt_tip(&r, NT_A5));
    NDC_CHECK("the reorg clears the witness",
              up && db_sapling_note_clear_witnesses_from(&ndb, 4));
    NDC_CHECK("the first call after the reorg succeeds",
              up && node_db_sync_advance_tip_witnesses_with(
                        &ndb, &tipblk, tip, NULL, &rd));
    int wh = -1;
    struct uint256 root = {0};
    uint8_t *blob = NULL;
    size_t len = 0;
    bool got = up && ndc_tip_witness(&ndb, NT_NOTE, &wh, &root, &blob, &len);
    free(blob);
    NDC_CHECK("it moved forward by a bounded number of blocks, not to the tip",
              got && wh > 5 && wh < tip->nHeight);
    NDC_CHECK("the second call reaches the tip",
              up && node_db_sync_advance_tip_witnesses_with(
                        &ndb, &tipblk, tip, NULL, &rd));
    blob = NULL;
    got = up && ndc_tip_witness(&ndb, NT_NOTE, &wh, &root, &blob, &len);
    free(blob);
    NDC_CHECK("the witness is at the tip and equals its header root",
              got && wh == tip->nHeight &&
              uint256_eq(&root, &f.n[NT_A5].root));
    nt_close(&r, dir);
    return failures;
}

static int ndc_check_tip_witnesses(void)
{
    return nt_check_three_outputs() + nt_check_missed_blocks() +
           nt_check_unreadable_body() + nt_check_note_below_history() +
           nt_check_reorg_disconnect() +
           nt_check_reorg_without_disconnect() + nt_check_long_reorg();
}

#ifndef _WIN32
struct ndc_replay_fixture {
    char dir[256], dbpath[320], logpath[320];
    struct wallet *wallet;
    struct main_state state;
    struct block_index slots[3];
    struct uint256 hashes[3], root, note_txid, spend_txid;
    int height_offset;
    bool fresh_spend;
    struct incremental_merkle_tree tree;
    uint8_t true_nf[32];
};

static bool ndc_replay_encrypt(struct ndc_replay_fixture *f, struct output_description *out,
                               const uint8_t d[11], const uint8_t pk[32], const uint8_t rcm[32])
{
    uint8_t pt[564] = {0}, esk[32] = {2}, shared[32], key[32];
    pt[0] = 1; memcpy(pt + 1, d, 11); pt[12] = 10; memcpy(pt + 20, rcm, 32);
    bool ok = sapling_compute_cm(d, pk, 10, rcm, out->cm.data) &&
        sapling_ka_derivepublic(d, esk, out->ephemeral_key.data) &&
        sapling_ka_agree(pk, esk, shared) &&
        sapling_kdf(key, shared, out->ephemeral_key.data) &&
        sapling_note_encrypt(key, pt, sizeof(pt), out->enc_ciphertext);
    const struct sapling_key_entry *ke = &f->wallet->sapling_keys.keys[0];
    ok = ok && sapling_compute_nf(d, pk, 10, rcm, ke->xfvk.fvk.ak,
                                   ke->xfvk.fvk.nk, 1, f->true_nf);
    memory_cleanse(pt, sizeof(pt)); memory_cleanse(shared, sizeof(shared));
    memory_cleanse(key, sizeof(key));
    return ok;
}

static void ndc_replay_fixture_parent(struct ndc_replay_fixture *f, int height)
{
    if (height > 1) f->slots[height].pprev = &f->slots[height - 1];
}

static bool ndc_replay_write_fixture_block(struct ndc_replay_fixture *f, int height,
                                           const uint8_t d[11], const uint8_t pk[32])
{
    struct block b;
    block_init(&b);
    b.header.nVersion = 4; b.header.nTime = 1700000000u + (unsigned)height;
    b.header.nBits = 0x2000ffffu;
    b.header.hashPrevBlock = f->hashes[height - 1];
    b.num_vtx = 1;
    b.vtx = zcl_calloc(1, sizeof(*b.vtx), "replay fixture tx");
    if (!b.vtx) return false;
    struct transaction *tx = b.vtx;
    transaction_init(tx);
    bool ok = transaction_alloc(tx, 1, 1);
    tx->version = SAPLING_TX_VERSION; tx->overwintered = true;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    if (height == 1) {
        tx->v_shielded_output = zcl_calloc(2, sizeof(*tx->v_shielded_output), "replay fixture outputs");
        ok = ok && tx->v_shielded_output;
        tx->num_shielded_output = ok ? 2 : 0;
        uint8_t rcm1[32] = {2}, rcm2[32] = {1};
        if (ok) ok = sapling_compute_cm(d, pk, 9, rcm1, tx->v_shielded_output[0].cm.data) &&
                     ndc_replay_encrypt(f, &tx->v_shielded_output[1], d, pk, rcm2);
        if (ok) {
            incremental_tree_append(&f->tree, &tx->v_shielded_output[0].cm);
            incremental_tree_append(&f->tree, &tx->v_shielded_output[1].cm);
            incremental_tree_root(&f->tree, &f->root);
        }
    } else {
        tx->v_shielded_spend = zcl_calloc(1, sizeof(*tx->v_shielded_spend), "replay fixture spend");
        ok = ok && tx->v_shielded_spend;
        tx->num_shielded_spend = ok ? 1 : 0;
        if (ok) memcpy(tx->v_shielded_spend[0].nullifier.data, f->true_nf, 32);
    }
    if (ok) {
        b.header.hashFinalSaplingRoot = f->root;
        transaction_compute_hash(tx);
        b.header.hashMerkleRoot = tx->hash;
        if (height == 1) f->note_txid = tx->hash;
        else f->spend_txid = tx->hash;
    }
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    const unsigned char magic[4] = {0x24,0xe9,0x27,0x64};
    if (ok) ok = write_block_to_disk(&b, &pos, f->dir, magic);
    if (ok) {
        block_get_hash(&b, &f->hashes[height]);
        struct block_index *slot = &f->slots[height];
        block_index_init(slot); slot->nHeight = height + f->height_offset; slot->nFile = pos.nFile;
        slot->nDataPos = pos.nPos; slot->nStatus = BLOCK_HAVE_DATA;
        slot->hashBlock = f->hashes[height]; slot->phashBlock = &slot->hashBlock; slot->hashFinalSaplingRoot = f->root;
        ndc_replay_fixture_parent(f, height);
        ok = active_chain_install_tip_slot(&f->state.chain_active, slot);
    }
    block_free(&b);
    return ok;
}

static bool ndc_replay_child(struct ndc_replay_fixture *f)
{
    event_log_t *log = event_log_open(f->logpath);
    if (!log) return false;
    wallet_projection_set_event_log(log);
    struct node_db db = {0};
    if (!node_db_open(&db, f->dbpath)) return false;
    struct db_service svc;
    db_service_init(&svc);
    bool ok = db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    struct sapling_replay_result r = {0};
    if (ok) r = node_db_catchup_sapling_replay(&svc, &db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    ok = ok && r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 2 && r.notes_found == 1;
    struct db_sapling_note *notes = NULL;
    int n = ok ? db_sapling_note_list_unspent_alloc(&db, &notes) : -1;
    ok = ok && n == 1 && notes && memcmp(notes[0].nullifier, f->true_nf, 32) != 0;
    struct incremental_witness witness;
    incremental_witness_init(&witness, &f->tree);
    struct wallet_rpc_context ctx = {.wallet = f->wallet, .main_state = &f->state,
                                      .node_db = &db, .datadir = f->dir};
    struct wallet_witness_outcome out;
    bool active = true;
    if (ok) ok = rescan_test_commit(&ctx, &f->tree, &witness, &active, notes, 1, 1,
                                     2, &f->hashes[2], &f->root, &out) &&
                 out.status == WALLET_WITNESS_COMPLETE;
    free(notes);
    /* Caller exits without closing SQLite, modeling process death. */
    return ok;
}

static bool ndc_replay_missing_cases(struct ndc_replay_fixture *f,
    struct db_service *svc, struct node_db *db, bool ok)
{
    int saved_file = f->slots[1].nFile;
    f->slots[1].nFile = -1;
    struct sapling_replay_result r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    f->slots[1].nFile = saved_file;
    ok = ok && r.status == SAPLING_REPLAY_INCOMPLETE && r.last_complete == 0;
    struct wallet *empty = zcl_calloc(1, sizeof(*empty), "replay keyless wallet");
    if (!empty) return false;
    wallet_init(empty);
    r = node_db_catchup_sapling_replay(svc, db, &f->state, empty,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    ok = ok && r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE;
    wallet_free(empty); free(empty);
    return ok;
}

static bool ndc_replay_refusal_cases(struct ndc_replay_fixture *f,
    struct db_service *svc, struct node_db *db, event_log_t *log, const uint8_t digest[32])
{
    uint8_t wrong_hash[32], wrong_keys[32];
    memcpy(wrong_hash, f->hashes[2].data, 32); wrong_hash[0] ^= 1;
    memcpy(wrong_keys, digest, 32); wrong_keys[0] ^= 1;
    int changes = sqlite3_total_changes(db->db);
    uint64_t log_size = event_log_size(log);
    struct sapling_replay_result r = node_db_catchup_sapling_replay(
        svc, db, &f->state, f->wallet, f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, wrong_keys);
    bool ok = r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE && r.last_complete == 0 &&
              sqlite3_total_changes(db->db) == changes && event_log_size(log) == log_size;
    r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, digest);
    ok = ok && r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 2 &&
         memcmp(r.key_digest, digest, 32) == 0;
    r = node_db_catchup_sapling_replay(
        svc, db, &f->state, f->wallet, f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, wrong_hash, NULL);
    ok = ok && r.status == SAPLING_REPLAY_CHAIN_CHANGED && r.last_complete == 0 &&
              r.start_height == 1 && r.end_height == 2 && r.phase == SAPLING_REPLAY_DISCOVER;
    r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_SPENDS, f->hashes[2].data, wrong_keys);
    ok = ok && r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE && r.last_complete == 0;
    return ndc_replay_missing_cases(f, svc, db, ok);
}

static bool ndc_replay_witness_unchanged(struct node_db *db, const uint8_t txid[32],
    const uint8_t *before, size_t bn, int bh)
{
    uint8_t *after = NULL; size_t an = 0; int ah = -1;
    bool ok = db_sapling_note_load_witness(db, txid, 1, &after, &an, &ah) &&
              bn == an && bh == ah && memcmp(before, after, bn) == 0;
    free(after);
    return ok;
}

static void ndc_epk_keys(struct sapling_key_entry *keys, const struct sapling_key_entry *real,
                         size_t count, int owner, bool sparse)
{
    for (size_t i = 0; i < count; ++i) {
        keys[i] = *real;
        memset(keys[i].ivk, 0, sizeof(keys[i].ivk));
        keys[i].ivk[0] = (uint8_t)(i + 2);
        if (!memcmp(keys[i].ivk, real->ivk, 32)) keys[i].ivk[1] = 1;
        keys[i].used = !sparse || i % 3 == 0 || (int)i == owner;
    }
    if (owner >= 0 && (size_t)owner < count) keys[owner] = *real;
}

/* Exercise the production trial-decrypt path with a real encrypted fixture note. */
static bool ndc_epk_try(struct ndc_replay_fixture *f, struct node_db *db,
    struct transaction *tx, size_t count, int owner, bool sparse, int expected)
{
    struct sapling_key_entry *keys = zcl_calloc(20, sizeof(*keys), "epk replay keys");
    if (!keys) return false;
    const struct sapling_key_entry *real = &f->wallet->sapling_keys.keys[0];
    ndc_epk_keys(keys, real, count, owner, sparse);
    struct sapling_replay_delivery delivery = {0};
    int found = -1;
    bool begun = node_db_begin(db);
    bool ok = begun && node_db_catchup_replay_sapling_decrypt(db, tx, keys, count, 1, &found, &delivery);
    if (begun && !node_db_rollback(db)) ok = false;
    db_sapling_replay_delivery_clear(&delivery);
    struct catchup_parallel_state parallel = {0};
    int parallel_found = -1;
    begun = node_db_begin(db);
    bool parallel_ok = begun && node_db_catchup_replay_sapling_decrypt_parallel(db, tx, keys,
        count, 1, &parallel_found, &delivery, &parallel);
    if (begun && !node_db_rollback(db)) parallel_ok = false;
    db_sapling_replay_delivery_clear(&delivery);
    node_db_catchup_parallel_free(&parallel);
    memory_cleanse(keys, 20 * sizeof(*keys)); free(keys);
    return ok && parallel_ok && found == expected && parallel_found == found;
}

static bool ndc_epk_parallel_first(bool fail_init, bool fail_run)
{
    return fail_init || fail_run || node_db_catchup_parallel_test_selected() == 3;
}

static bool ndc_epk_parallel_case(struct ndc_replay_fixture *f, struct node_db *db,
    struct transaction *tx, bool fail_init, bool fail_run)
{
    struct sapling_key_entry *keys = zcl_calloc(20, sizeof(*keys), "duplicate replay keys");
    if (!keys) return false;
    keys[3] = f->wallet->sapling_keys.keys[0];
    keys[13] = keys[3];
    struct catchup_parallel_state parallel = {0};
    struct sapling_replay_delivery delivery = {0};
    int found = -1;
    node_db_catchup_parallel_test_faults(fail_init, fail_run);
    bool begun = node_db_begin(db);
    bool ok = begun && node_db_catchup_replay_sapling_decrypt_parallel(db, tx, keys, 20,
        1, &found, &delivery, &parallel);
    bool first = ndc_epk_parallel_first(fail_init, fail_run);
    bool injected = !fail_run || node_db_catchup_parallel_test_run_failed();
    bool fallback = !fail_init || (parallel.attempted && !parallel.pool);
    bool rolled_back = begun && node_db_rollback(db);
    node_db_catchup_parallel_test_faults(false, false);
    db_sapling_replay_delivery_clear(&delivery);
    node_db_catchup_parallel_free(&parallel);
    memory_cleanse(keys, 20 * sizeof(*keys)); free(keys);
    return begun && rolled_back && first && injected && fallback && (fail_run ? !ok : ok && found == 1);
}

static bool ndc_epk_note_state(struct node_db *db, const uint8_t txid[32], uint8_t state[65])
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT nullifier,spent_txid FROM wallet_sapling_notes WHERE txid=? AND output_index=1";
    if (sqlite3_prepare_v2(db->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB && sqlite3_column_bytes(s, 0) == 32;
    memset(state, 0, 65);
    if (ok) {
        memcpy(state, sqlite3_column_blob(s, 0), 32);
        int type = sqlite3_column_type(s, 1);
        if (type == SQLITE_BLOB && sqlite3_column_bytes(s, 1) == 32) {
            state[32] = 1; memcpy(state + 33, sqlite3_column_blob(s, 1), 32);
        } else if (type != SQLITE_NULL) ok = false;
    }
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}

struct ndc_parallel_evidence {
    uint8_t note[32], event[512];
    size_t event_len, delivery_count, committed;
    enum event_log_type event_type;
};

struct ndc_parallel_witness {
    uint8_t digest[32];
    size_t length;
    int height;
    bool present;
};

static struct ndc_parallel_witness ndc_parallel_witness(struct node_db *db, const uint8_t txid[32])
{
    struct ndc_parallel_witness result = {0};
    uint8_t *bytes = NULL;
    result.present = db_sapling_note_load_witness(db, txid, 1, &bytes, &result.length, &result.height);
    if (result.present) {
        struct sha3_256_ctx hash;
        sha3_256_init(&hash);
        sha3_256_write(&hash, bytes, result.length);
        sha3_256_finalize(&hash, result.digest);
    }
    free(bytes);
    return result;
}

static bool ndc_parallel_witness_same(const struct ndc_parallel_witness *a,
                                      const struct ndc_parallel_witness *b)
{
    return a->present == b->present && (!a->present ||
        (a->length == b->length && a->height == b->height && !memcmp(a->digest, b->digest, 32)));
}

static bool ndc_parallel_note_digest(struct node_db *db, const uint8_t txid[32], uint8_t out[32])
{
    static const char sql[] = "SELECT txid,output_index,value,rcm,memo,ivk,diversifier,pk_d,cm,"
        "nullifier,block_height,spent_txid,address,source FROM wallet_sapling_notes WHERE txid=? AND output_index=1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(stmt, 1, txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (int i = 0; ok && i < 14; ++i) {
        int type = sqlite3_column_type(stmt, i);
        int64_t integer = type == SQLITE_INTEGER ? sqlite3_column_int64(stmt, i) : 0;
        int length = type == SQLITE_INTEGER ? (int)sizeof(integer) : sqlite3_column_bytes(stmt, i);
        const void *bytes = type == SQLITE_INTEGER ? (const void *)&integer : sqlite3_column_blob(stmt, i);
        sha3_256_write(&hash, (const uint8_t *)&type, sizeof(type));
        sha3_256_write(&hash, (const uint8_t *)&length, sizeof(length));
        if (length && !bytes) ok = false;
        if (ok && length) sha3_256_write(&hash, bytes, (size_t)length);
    }
    if (ok) ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (ok) sha3_256_finalize(&hash, out);
    if (sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    return ok;
}

static bool ndc_parallel_copy_db(struct node_db *target, struct node_db *source)
{
    sqlite3_backup *backup = sqlite3_backup_init(target->db, "main", source->db, "main");
    if (!backup) return false;
    int step = sqlite3_backup_step(backup, -1);
    return sqlite3_backup_finish(backup) == SQLITE_OK && step == SQLITE_DONE;
}

static bool ndc_parallel_before(struct node_db *db, struct ndc_replay_fixture *f, bool fresh,
    bool ok, uint8_t note[32], struct ndc_parallel_witness *witness)
{
    *witness = ndc_parallel_witness(db, f->note_txid.data);
    if (ok) ok = fresh ? db_sapling_note_count_all(db) == 0 :
        witness->present && ndc_parallel_note_digest(db, f->note_txid.data, note);
    return ok;
}

static bool ndc_parallel_after(struct node_db *db, struct ndc_replay_fixture *f, bool fresh,
    bool ok, const uint8_t note[32], const struct ndc_parallel_witness *before,
    const struct ndc_parallel_evidence *out)
{
    struct ndc_parallel_witness after = ndc_parallel_witness(db, f->note_txid.data);
    if (ok) ok = fresh ? db_sapling_note_count_all(db) == 1 :
        !memcmp(note, out->note, 32) && ndc_parallel_witness_same(before, &after);
    return ok;
}

static bool ndc_parallel_deliver(struct node_db *db, event_log_t *log,
    struct sapling_replay_delivery *delivery, bool begun, bool ok, struct ndc_parallel_evidence *out)
{
    out->delivery_count = delivery->count;
    bool committed = ok && node_db_commit(db);
    if (begun && !committed && !node_db_rollback(db)) ok = false;
    ok = ok && committed;
    out->committed = delivery->committed;
    uint64_t offset = log ? event_log_size(log) : 0;
    if (ok) ok = delivery->count == 1 && delivery->committed == 1 && db_sapling_replay_delivery_flush(delivery);
    if (ok) ok = event_log_read(log, offset, &out->event_type, out->event, sizeof(out->event), &out->event_len) == 0;
    return ok;
}

static bool ndc_parallel_evidence(struct ndc_replay_fixture *f, struct node_db *source,
    struct transaction *tx, const struct sapling_key_entry *keys, int workers, bool fresh,
    unsigned sequence, struct ndc_parallel_evidence *out)
{
    char dbpath[512], logpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/parity-%u-%d-%d.db", f->dir, sequence, workers, (int)fresh);
    snprintf(logpath, sizeof(logpath), "%s/parity-%u-%d-%d.log", f->dir, sequence, workers, (int)fresh);
    struct node_db db = {0};
    if (!node_db_open(&db, dbpath)) return false;
    event_log_t *old_log = wallet_projection_event_log();
    event_log_t *log = event_log_open(logpath);
    bool ok = log && (fresh || ndc_parallel_copy_db(&db, source));
    if (ok) wallet_projection_set_event_log(log);
    uint8_t before_note[32];
    struct ndc_parallel_witness before_witness;
    ok = ndc_parallel_before(&db, f, fresh, ok, before_note, &before_witness);
    struct sapling_replay_delivery delivery = {0};
    struct catchup_parallel_state parallel = {0};
    int found = -1;
    node_db_catchup_parallel_test_workers(workers);
    bool begun = ok && node_db_begin(&db);
    if (begun) ok = node_db_catchup_replay_sapling_decrypt_parallel(&db, tx, keys, 20,
        1, &found, &delivery, workers ? &parallel : NULL);
    else ok = false;
    if (ok && workers) ok = node_db_catchup_parallel_test_worker_count(&parallel) == workers;
    if (ok) ok = found == 1 && ndc_parallel_note_digest(&db, f->note_txid.data, out->note);
    ok = ndc_parallel_after(&db, f, fresh, ok, before_note, &before_witness, out);
    ok = ndc_parallel_deliver(&db, log, &delivery, begun, ok, out);
    node_db_catchup_parallel_test_workers(0);
    node_db_catchup_parallel_free(&parallel);
    db_sapling_replay_delivery_clear(&delivery);
    wallet_projection_set_event_log(old_log);
    if (log) event_log_close(log);
    node_db_close(&db);
    return ok;
}

static bool ndc_parallel_parity(struct ndc_replay_fixture *f, struct node_db *db, struct transaction *tx)
{
    static unsigned sequence;
    struct sapling_key_entry *keys = zcl_calloc(20, sizeof(*keys), "parallel parity keys");
    if (!keys) return false;
    for (size_t i = 0; i < 20; ++i) {
        keys[i] = f->wallet->sapling_keys.keys[0];
        memset(keys[i].ivk, 0, sizeof(keys[i].ivk));
        keys[i].ivk[0] = (uint8_t)(i + 2);
    }
    keys[19] = f->wallet->sapling_keys.keys[0];
    struct ndc_parallel_evidence baseline = {0}, candidate = {0};
    unsigned run = ++sequence;
    bool ok = true;
    for (int fresh = 0; ok && fresh <= 1; ++fresh) {
        memset(&baseline, 0, sizeof(baseline));
        ok = ndc_parallel_evidence(f, db, tx, keys, 0, fresh != 0, run, &baseline);
        for (int workers = 1; ok && workers <= 4; workers *= 2) {
            memset(&candidate, 0, sizeof(candidate));
            ok = ndc_parallel_evidence(f, db, tx, keys, workers, fresh != 0, run, &candidate) &&
                baseline.delivery_count == candidate.delivery_count && baseline.committed == candidate.committed &&
                !memcmp(baseline.note, candidate.note, sizeof(baseline.note)) &&
                baseline.event_type == candidate.event_type && baseline.event_len == candidate.event_len &&
                !memcmp(baseline.event, candidate.event, baseline.event_len);
        }
    }
    memory_cleanse(keys, 20 * sizeof(*keys)); free(keys);
    return ok;
}

/* This child creates its own database handle and drains the pool after shutdown. */
static bool ndc_parallel_signal_child(struct ndc_replay_fixture *f)
{
    struct node_db db = {0};
    if (!node_db_open(&db, f->dbpath)) return false;
    struct block b;
    block_init(&b);
    struct zcl_result read = node_db_catchup_read_authenticated_block(f->dir,
        f->slots[1].nFile, f->slots[1].nDataPos, &f->hashes[1], &b);
    struct sapling_key_entry *keys = zcl_calloc(20, sizeof(*keys), "signal replay keys");
    bool ok = read.ok && b.num_vtx == 1 && keys;
    if (ok) keys[19] = f->wallet->sapling_keys.keys[0];
    struct ndc_parallel_evidence result = {0};
    node_db_catchup_parallel_test_signal(true);
    if (ok) ok = ndc_parallel_evidence(f, &db, &b.vtx[0], keys, 4, false, 999, &result);
    node_db_catchup_parallel_test_signal(false);
    ok = ok && thread_registry_shutdown_requested();
    if (keys) { memory_cleanse(keys, 20 * sizeof(*keys)); free(keys); }
    block_free(&b);
    node_db_close(&db);
    return ok;
}

static bool ndc_epk_key_cases(struct ndc_replay_fixture *f, struct node_db *db, struct transaction *tx)
{
    return ndc_epk_parallel_case(f, db, tx, false, false) &&
        ndc_epk_parallel_case(f, db, tx, true, false) &&
        ndc_epk_parallel_case(f, db, tx, false, true) &&
        ndc_epk_try(f, db, tx, 0, -1, false, 0) &&
        ndc_epk_try(f, db, tx, 1, 0, false, 1) &&
        ndc_epk_try(f, db, tx, 20, 0, false, 1) &&
        ndc_epk_try(f, db, tx, 20, 10, false, 1) &&
        ndc_epk_try(f, db, tx, 20, 19, false, 1) &&
        ndc_epk_try(f, db, tx, 20, 19, true, 1) &&
        ndc_epk_try(f, db, tx, 20, -1, false, 0);
}
static bool ndc_epk_edge_cases(struct ndc_replay_fixture *f, struct node_db *db, struct transaction *tx)
{
    uint8_t *epk = tx->v_shielded_output[1].ephemeral_key.data;
    memset(epk, 0xff, 32); /* Invalid field encoding. */
    bool ok = ndc_epk_try(f, db, tx, 20, 19, false, 0);
    memset(epk, 0, 32); epk[0] = 1; /* Identity encoding. */
    if (ok) ok = ndc_epk_try(f, db, tx, 20, 19, false, 0);
    memset(epk, 0, 32); /* Small-order encoding. */
    if (ok) ok = ndc_epk_try(f, db, tx, 20, 19, false, 0);
    return ok;
}
static bool ndc_epk_matrix(struct ndc_replay_fixture *f, struct node_db *db,
    const uint8_t *witness, size_t witness_len, int witness_height)
{
    struct block b; block_init(&b);
    struct zcl_result read = node_db_catchup_read_authenticated_block(f->dir,
        f->slots[1].nFile, f->slots[1].nDataPos, &f->hashes[1], &b);
    bool ok = read.ok && b.num_vtx == 1 && b.vtx[0].num_shielded_output == 2;
    int unspent = db_sapling_note_count_unspent(db);
    uint8_t before[65], after[65];
    if (ok) ok = ndc_epk_note_state(db, f->note_txid.data, before);
    if (ok) ok = ndc_parallel_parity(f, db, &b.vtx[0]);
    if (ok) ok = ndc_epk_key_cases(f, db, &b.vtx[0]);
    if (ok) ok = ndc_epk_edge_cases(f, db, &b.vtx[0]);
    ok = ok && ndc_epk_note_state(db, f->note_txid.data, after) && !memcmp(before, after, sizeof(before)) &&
        db_sapling_note_count_unspent(db) == unspent &&
        ndc_replay_witness_unchanged(db, f->note_txid.data, witness, witness_len, witness_height);
    block_free(&b);
    return ok;
}

static bool ndc_replay_delivery_failures(struct ndc_replay_fixture *f, struct db_service *svc,
                                         struct node_db *db, event_log_t *log)
{
    bool ok = true;
    struct sapling_replay_result r = {0};
    int event_fd = event_log_test_fd(log);
    event_log_test_set_fd(log, -1);
    if (ok) r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    event_log_test_set_fd(log, event_fd);
    if (ok) ok = r.status == SAPLING_REPLAY_EVENT_UNAVAILABLE && r.last_complete == 0;
    event_log_test_set_force_per_append(0);
    event_log_set_deferred_sync(log, true);
    event_log_test_set_fd(log, -1);
    if (ok) r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    event_log_test_set_fd(log, event_fd);
    if (ok) ok = r.status == SAPLING_REPLAY_EVENT_UNAVAILABLE && r.last_complete == 0;
    event_log_test_set_force_per_append(-1);
    return ok;
}

static bool ndc_replay_spent_result(struct sapling_replay_result r, struct node_db *db)
{
    return r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 2 &&
           db_sapling_note_count_unspent(db) == 0;
}

static void ndc_replay_fork_after_read(void *ctx)
{
    struct ndc_replay_fixture *f = ctx;
    zcl_mutex_lock(&f->state.cs_main);
    f->slots[2].pprev = NULL;
    zcl_mutex_unlock(&f->state.cs_main);
}

static bool ndc_replay_reference_complete(struct sapling_replay_result r,
    const struct ndc_replay_fixture *f, const uint8_t identity[32])
{
    return r.status == SAPLING_REPLAY_COMPLETE && r.last_complete == 1 &&
        r.reference_height == 2 && memcmp(r.reference_hash, f->hashes[2].data, 32) == 0 &&
        memcmp(r.scan_identity, identity, 32) == 0;
}

/* Mutations are applied once between authenticated read and the locked check. */
struct ndc_identity_probe { struct wallet *wallet; int which; bool fired; };
struct ndc_identity_saved {
    size_t keys, watching, scripts;
    struct key_entry key;
    struct watching_entry watch;
    struct script_entry script;
};
static void ndc_identity_flip_low(struct wallet *w, int which)
{
    switch (which) {
    case 0: w->has_master_key = !w->has_master_key; break;
    case 1: w->hd_account ^= 1; break;
    case 2: w->hd_external_counter ^= 1; break;
    case 3: w->hd_internal_counter ^= 1; break;
    case 4: w->keystore.num_keys ^= 1; break;
    case 5: w->keystore.keys[0].used = !w->keystore.keys[0].used; break;
    case 6: w->keystore.keys[0].keyid.id.data[0] ^= 1; break;
    case 7: w->keystore.num_watching ^= 1; break;
    case 8: w->keystore.watching[0].used = !w->keystore.watching[0].used; break;
    case 9: w->keystore.watching[0].keyid.id.data[0] ^= 1; break;
    }
}
static void ndc_identity_flip_middle(struct wallet *w, int which)
{
    switch (which) {
    case 10: w->keystore.num_scripts ^= 1; break;
    case 11: w->keystore.scripts[0].used = !w->keystore.scripts[0].used; break;
    case 12: w->keystore.scripts[0].script_id.data[0] ^= 1; break;
    case 13: w->keystore.scripts[0].redeem_script.size ^= 1; break;
    case 14: w->keystore.scripts[0].redeem_script.data[0] ^= 1; break;
    case 15: w->sapling_keys.has_seed = !w->sapling_keys.has_seed; break;
    case 16: w->sapling_keys.next_child_index ^= 1; break;
    case 17: w->sapling_keys.num_keys ^= 1; break;
    case 18: w->sapling_keys.keys[0].used = !w->sapling_keys.keys[0].used; break;
    case 19: w->sapling_keys.keys[0].child_index ^= 1; break;
    }
}
static void ndc_identity_flip_high(struct wallet *w, int which)
{
    switch (which) {
    case 20: w->sapling_keys.keys[0].ivk[0] ^= 1; break;
    case 21: w->sapling_keys.keys[0].xfvk.fvk.ak[0] ^= 1; break;
    case 22: w->sapling_keys.keys[0].xfvk.fvk.nk[0] ^= 1; break;
    case 23: w->sapling_keys.locked = !w->sapling_keys.locked; break;
    case 24: w->sapling_keys.num_unscannable ^= 1; break;
    case 25: w->sapling_keys.num_damaged ^= 1; break;
    case 26: w->keystore.scripts[0].redeem_script.size ^= (MAX_SCRIPT_SIZE + 1); break;
    case 27: w->keystore.num_keys ^= (MAX_KEYSTORE_KEYS + 2); break;
    case 28: w->keystore.num_watching ^= (MAX_KEYSTORE_WATCHING + 2); break;
    case 29: w->keystore.num_scripts ^= (MAX_KEYSTORE_SCRIPTS + 2); break;
    case 30: w->sapling_keys.num_keys ^= (MAX_SAPLING_KEYS + 2); break;
    }
}
static void ndc_identity_flip(struct wallet *w, int which)
{
    zcl_mutex_lock(&w->cs);
    zcl_mutex_lock(&w->keystore.cs);
    zcl_mutex_lock(&w->sapling_keys.cs);
    if (which < 10) ndc_identity_flip_low(w, which);
    else if (which < 20) ndc_identity_flip_middle(w, which);
    else ndc_identity_flip_high(w, which);
    zcl_mutex_unlock(&w->sapling_keys.cs);
    zcl_mutex_unlock(&w->keystore.cs);
    zcl_mutex_unlock(&w->cs);
}
static void ndc_identity_mutate_once(void *opaque)
{
    struct ndc_identity_probe *probe = opaque;
    if (!probe->fired) { probe->fired = true; ndc_identity_flip(probe->wallet, probe->which); }
}
static void ndc_identity_seed(struct wallet *w, struct ndc_identity_saved *saved)
{
    saved->keys = w->keystore.num_keys;
    saved->watching = w->keystore.num_watching;
    saved->scripts = w->keystore.num_scripts;
    saved->key = w->keystore.keys[0];
    saved->watch = w->keystore.watching[0];
    saved->script = w->keystore.scripts[0];
    w->keystore.num_keys = w->keystore.num_watching = w->keystore.num_scripts = 1;
    w->keystore.keys[0].used = true;
    w->keystore.watching[0].used = true;
    w->keystore.scripts[0].used = true;
    w->keystore.scripts[0].redeem_script.size = 2;
}
static void ndc_identity_unseed(struct wallet *w, const struct ndc_identity_saved *saved)
{
    w->keystore.num_keys = saved->keys;
    w->keystore.num_watching = saved->watching;
    w->keystore.num_scripts = saved->scripts;
    w->keystore.keys[0] = saved->key;
    w->keystore.watching[0] = saved->watch;
    w->keystore.scripts[0] = saved->script;
}
static bool ndc_identity_refused(enum sapling_replay_status status)
{
    return status == SAPLING_REPLAY_WALLET_CHANGED || status == SAPLING_REPLAY_KEYS_UNAVAILABLE;
}
static bool ndc_identity_one(struct ndc_replay_fixture *f, struct db_service *svc,
                             struct node_db *db, wallet_projection_t *projection, int which, bool after_delivery)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    sqlite3_int64 changes = sqlite3_total_changes64(db->db);
    uint64_t log_size = event_log_size(wallet_projection_event_log());
    struct ndc_identity_probe p = {.wallet = f->wallet, .which = which};
    if (after_delivery) node_db_sapling_replay_test_revalidate_hooks(ndc_identity_mutate_once, NULL, &p);
    else node_db_sapling_replay_test_after_read(ndc_identity_mutate_once, &p);
    struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    node_db_sapling_replay_test_revalidate_hooks(NULL, NULL, NULL);
    if (p.fired) ndc_identity_flip(f->wallet, which);
    if (!p.fired || !ndc_identity_refused(r.status) || r.last_complete != 0 ||
        wallet_readiness_get(f->wallet).state != WALLET_READINESS_PENDING) return false;
    if (!after_delivery)
        return sqlite3_total_changes64(db->db) == changes && event_log_size(wallet_projection_event_log()) == log_size;
    if (wallet_projection_catch_up(projection) == UINT64_MAX) return false;
    uint64_t projected = wallet_projection_note_count(projection);
    int64_t value = wallet_projection_total_value_zat(projection);
    int notes = db_sapling_note_count_unspent(db);
    r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    return r.status == SAPLING_REPLAY_COMPLETE && db_sapling_note_count_unspent(db) == notes &&
        wallet_projection_catch_up(projection) != UINT64_MAX &&
        wallet_projection_note_count(projection) == projected &&
        wallet_projection_total_value_zat(projection) == value;
}
struct ndc_capture_race {
    struct ndc_identity_probe probe;
    uint8_t *expected;
    bool updated;
};
static void ndc_capture_mutate(void *opaque)
{
    struct ndc_capture_race *race = opaque;
    ndc_identity_mutate_once(&race->probe);
    race->updated = wallet_scan_identity(race->probe.wallet, race->expected);
}
static bool ndc_capture_race_one(struct ndc_replay_fixture *f, struct db_service *svc,
                                 struct node_db *db, int which)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    sqlite3_int64 changes = sqlite3_total_changes64(db->db);
    uint64_t size = event_log_size(wallet_projection_event_log());
    struct ndc_capture_race race = {.probe = {.wallet = f->wallet, .which = which}, .expected = identity};
    node_db_sapling_replay_test_after_keys(ndc_capture_mutate, &race);
    struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    node_db_sapling_replay_test_after_keys(NULL, NULL);
    if (race.probe.fired) ndc_identity_flip(f->wallet, which);
    return race.probe.fired && race.updated && r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE &&
        r.last_complete == 0 && sqlite3_total_changes64(db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == size &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}
static void ndc_global_lock(void *opaque)
{
    bool *fired = opaque;
    *fired = true;
    wallet_lock_note_encrypted_at_rest();
    wallet_lock_lock(NULL);
}
static bool ndc_global_lock_one(struct ndc_replay_fixture *f, struct db_service *svc,
                                struct node_db *db, bool after_delivery)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    sqlite3_int64 changes = sqlite3_total_changes64(db->db);
    uint64_t size = event_log_size(wallet_projection_event_log());
    bool fired = false;
    if (after_delivery) node_db_sapling_replay_test_revalidate_hooks(ndc_global_lock, NULL, &fired);
    else node_db_sapling_replay_test_after_read(ndc_global_lock, &fired);
    struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    node_db_sapling_replay_test_revalidate_hooks(NULL, NULL, NULL);
    bool locked = wallet_lock_is_locked();
    wallet_lock_reset_for_test();
    bool unchanged = after_delivery || (sqlite3_total_changes64(db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == size);
    return fired && locked && unchanged && r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE &&
        r.last_complete == 0 && wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}
static bool ndc_non_strict_key_one(struct ndc_replay_fixture *f, struct db_service *svc,
                                   struct node_db *db, int which, bool after_delivery)
{
    sqlite3_int64 changes = sqlite3_total_changes64(db->db);
    uint64_t size = event_log_size(wallet_projection_event_log());
    struct ndc_identity_probe p = {.wallet = f->wallet, .which = which};
    if (after_delivery) node_db_sapling_replay_test_revalidate_hooks(ndc_identity_mutate_once, NULL, &p);
    else node_db_sapling_replay_test_after_read(ndc_identity_mutate_once, &p);
    struct sapling_replay_result r = node_db_catchup_sapling_replay(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, SAPLING_REPLAY_DISCOVER, f->hashes[1].data, NULL);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    node_db_sapling_replay_test_revalidate_hooks(NULL, NULL, NULL);
    if (p.fired) ndc_identity_flip(f->wallet, which);
    bool unchanged = after_delivery || (sqlite3_total_changes64(db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == size);
    return p.fired && unchanged && r.status == SAPLING_REPLAY_KEYS_UNAVAILABLE && r.last_complete == 0;
}
static bool ndc_non_strict_key_cases(struct ndc_replay_fixture *f, struct db_service *svc,
                                     struct node_db *db)
{
    for (int which = 20; which <= 22; ++which)
        if (!ndc_non_strict_key_one(f, svc, db, which, false) ||
            !ndc_non_strict_key_one(f, svc, db, which, true)) return false;
    return true;
}

static bool ndc_key_compare_cases(struct ndc_replay_fixture *f, struct db_service *svc,
                                  struct node_db *db)
{
    return ndc_capture_race_one(f, svc, db, 20) &&
        ndc_capture_race_one(f, svc, db, 21) && ndc_capture_race_one(f, svc, db, 22) &&
        ndc_global_lock_one(f, svc, db, false) && ndc_global_lock_one(f, svc, db, true) &&
        ndc_non_strict_key_cases(f, svc, db);
}

static bool ndc_identity_capture_once(struct ndc_replay_fixture *f, struct db_service *svc,
                                      struct node_db *db)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    zcl_alloc_fault_fail_nth("wallet scan snapshot", 2);
    struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[2].data, identity, NULL);
    bool once = zcl_alloc_fault_armed_label() && r.status == SAPLING_REPLAY_COMPLETE;
    zcl_alloc_fault_clear();
    sqlite3_int64 before = sqlite3_total_changes64(db->db);
    uint64_t log_size = event_log_size(wallet_projection_event_log());
    zcl_alloc_fault_fail_next("wallet scan snapshot");
    r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    zcl_alloc_fault_clear();
    return once && r.status == SAPLING_REPLAY_WALLET_CHANGED &&
        sqlite3_total_changes64(db->db) == before && event_log_size(wallet_projection_event_log()) == log_size;
}
static bool ndc_identity_replay_cases(struct ndc_replay_fixture *f, struct db_service *svc,
    struct node_db *db, const uint8_t *witness, size_t witness_size, int witness_height)
{
    if (f->wallet->sapling_keys.num_keys != 1 || !f->wallet->sapling_keys.keys[0].used) return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/identity-projection.db", f->dir);
    wallet_projection_t *projection = wallet_projection_open(path, wallet_projection_event_log());
    if (!projection) return false;
    struct ndc_identity_saved saved;
    ndc_identity_seed(f->wallet, &saved);
    bool ok = ndc_identity_capture_once(f, svc, db) && ndc_key_compare_cases(f, svc, db);
    for (int which = 0; ok && which <= 30; ++which)
        ok = ndc_identity_one(f, svc, db, projection, which, false) &&
             ndc_identity_one(f, svc, db, projection, which, true);
    ndc_identity_unseed(f->wallet, &saved);
    wallet_projection_close(projection);
    return ok && ndc_replay_witness_unchanged(db, f->note_txid.data, witness, witness_size, witness_height);
}

static bool ndc_replay_reference_cases(struct ndc_replay_fixture *f,
    struct db_service *svc, struct node_db *db)
{
    uint8_t identity[32], wrong[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    memcpy(wrong, identity, 32); wrong[0] ^= 1;
    sqlite3_int64 before = sqlite3_total_changes64(db->db);
    struct sapling_replay_result r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, wrong, NULL);
    bool ok = r.status == SAPLING_REPLAY_WALLET_CHANGED && r.last_complete == 0 &&
        sqlite3_total_changes64(db->db) == before;
    struct block_index *parent = f->slots[2].pprev;
    f->slots[2].pprev = NULL;
    r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    f->slots[2].pprev = parent;
    ok = ok && r.status == SAPLING_REPLAY_CHAIN_CHANGED && r.last_complete == 0 &&
        sqlite3_total_changes64(db->db) == before &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
    node_db_sapling_replay_test_after_read(ndc_replay_fork_after_read, f);
    r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    f->slots[2].pprev = parent;
    ok = ok && r.status == SAPLING_REPLAY_CHAIN_CHANGED && r.last_complete == 0 &&
        sqlite3_total_changes64(db->db) == before &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
    r = node_db_catchup_sapling_replay_at_reference(
        svc, db, &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[1].data, identity, NULL);
    return ok && ndc_replay_reference_complete(r, f, identity);
}

struct ndc_revalidate_busy {
    struct main_state *state;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    pthread_t thread;
    bool entered, release, started, forced;
};
static void *ndc_revalidate_lock(void *opaque)
{
    struct ndc_revalidate_busy *b = opaque;
    zcl_mutex_lock(&b->state->cs_main);
    pthread_mutex_lock(&b->mu);
    b->entered = true;
    pthread_cond_broadcast(&b->cond);
    while (!b->release) pthread_cond_wait(&b->cond, &b->mu);
    pthread_mutex_unlock(&b->mu);
    zcl_mutex_unlock(&b->state->cs_main);
    return NULL;
}
static void ndc_revalidate_before(void *opaque)
{
    struct ndc_revalidate_busy *b = opaque;
    if (b->forced) return;
    b->forced = true;
    b->started = pthread_create(&b->thread, NULL, ndc_revalidate_lock, b) == 0;
    if (!b->started) return;
    pthread_mutex_lock(&b->mu);
    while (!b->entered) pthread_cond_wait(&b->cond, &b->mu);
    pthread_mutex_unlock(&b->mu);
}
static void ndc_revalidate_after(void *opaque)
{
    struct ndc_revalidate_busy *b = opaque;
    if (!b->started) return;
    pthread_mutex_lock(&b->mu);
    b->release = true;
    pthread_cond_broadcast(&b->cond);
    pthread_mutex_unlock(&b->mu);
    pthread_join(b->thread, NULL);
    b->started = false;
}
static bool ndc_cutover_post_delivery_busy(struct boot_cutover_replay *r)
{
    struct ndc_revalidate_busy b = {.state = r->ctx->main_state};
    if (pthread_mutex_init(&b.mu, NULL) || pthread_cond_init(&b.cond, NULL)) return false;
    alarm(10);
    node_db_sapling_replay_test_revalidate_hooks(ndc_revalidate_before, NULL, &b);
    enum boot_cutover_replay_status status = boot_cutover_replay_step(r);
    node_db_sapling_replay_test_revalidate_hooks(NULL, NULL, NULL);
    ndc_revalidate_after(&b);
    alarm(0);
    pthread_cond_destroy(&b.cond);
    pthread_mutex_destroy(&b.mu);
    return b.forced && b.entered && status == BOOT_CUTOVER_BUSY &&
        r->phase == BOOT_CUTOVER_DISCOVER && r->next == r->floor;
}

static bool ndc_cutover_endpoint_busy(struct boot_cutover_replay *r)
{
    struct ndc_revalidate_busy b = {.state = r->ctx->main_state};
    if (pthread_mutex_init(&b.mu, NULL) || pthread_cond_init(&b.cond, NULL)) return false;
    alarm(10);
    boot_cutover_replay_test_after_current(ndc_revalidate_before, &b);
    enum boot_cutover_replay_status status = boot_cutover_replay_step(r);
    boot_cutover_replay_test_after_current(NULL, NULL);
    ndc_revalidate_after(&b);
    alarm(0);
    pthread_cond_destroy(&b.cond);
    pthread_mutex_destroy(&b.mu);
    return b.entered && status == BOOT_CUTOVER_BUSY &&
        r->phase == BOOT_CUTOVER_DISCOVER && r->next == r->floor;
}

static bool ndc_cutover_completed_busy(struct boot_cutover_replay *r)
{
    struct ndc_revalidate_busy b = {.state = r->ctx->main_state};
    if (pthread_mutex_init(&b.mu, NULL) || pthread_cond_init(&b.cond, NULL)) return false;
    alarm(10);
    boot_cutover_replay_test_before_postcheck(ndc_revalidate_before, &b);
    enum boot_cutover_replay_status status = boot_cutover_replay_step(r);
    boot_cutover_replay_test_before_postcheck(NULL, NULL);
    ndc_revalidate_after(&b);
    alarm(0);
    pthread_cond_destroy(&b.cond);
    pthread_mutex_destroy(&b.mu);
    return b.entered && status == BOOT_CUTOVER_BUSY && r->pending_complete &&
        r->phase == BOOT_CUTOVER_TRANSPARENT &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS && !r->pending_complete &&
        r->phase == BOOT_CUTOVER_DISCOVER;
}

static bool ndc_cutover_persistent_busy(struct boot_cutover_replay *r)
{
    struct ndc_revalidate_busy b = {.state = r->ctx->main_state};
    if (pthread_mutex_init(&b.mu, NULL) || pthread_cond_init(&b.cond, NULL)) return false;
    alarm(10);
    ndc_revalidate_before(&b);
    int64_t since = 0;
    unsigned retries = 0;
    while (b.entered && boot_cutover_replay_step(r) == BOOT_CUTOVER_BUSY &&
           boot_test_pending_busy_backoff(&since, 0, 100)) ++retries;
    int64_t expired = platform_time_monotonic_ms() - 1;
    bool deadline_refused = !boot_test_pending_busy_backoff(&since, expired, 100);
    ndc_revalidate_after(&b);
    alarm(0);
    pthread_cond_destroy(&b.cond);
    pthread_mutex_destroy(&b.mu);
    return b.entered && retries > 0 && deadline_refused &&
        r->phase == BOOT_CUTOVER_DISCOVER && r->next == r->floor;
}

struct ndc_busy_worker {
    struct db_service *svc;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    bool entered, release, started;
    int reads;
    pthread_t thread;
};
static bool ndc_busy_hold(struct node_db *db, void *opaque)
{
    (void)db;
    struct ndc_busy_worker *b = opaque;
    pthread_mutex_lock(&b->mu);
    b->entered = true;
    pthread_cond_broadcast(&b->cond);
    while (!b->release) pthread_cond_wait(&b->cond, &b->mu);
    pthread_mutex_unlock(&b->mu);
    return true;
}
static void *ndc_busy_thread(void *opaque)
{
    struct ndc_busy_worker *b = opaque;
    (void)db_service_run_write(b->svc, ndc_busy_hold, b);
    return NULL;
}
static void ndc_busy_after_read(void *opaque)
{
    struct ndc_busy_worker *b = opaque;
    if (++b->reads != 2) return;
    b->started = pthread_create(&b->thread, NULL, ndc_busy_thread, b) == 0;
    if (!b->started) return;
    pthread_mutex_lock(&b->mu);
    while (!b->entered) pthread_cond_wait(&b->cond, &b->mu);
    pthread_mutex_unlock(&b->mu);
}
static bool ndc_cutover_resume_digest(struct boot_cutover_replay *r)
{
    uint8_t digest[32], zero[32] = {0};
    memcpy(digest, r->key_digest, sizeof(digest));
    if (!memcmp(digest, zero, sizeof(digest))) return false;
    int next = r->next;
    int changes = sqlite3_total_changes(r->ctx->node_db->db);
    uint64_t size = event_log_size(wallet_projection_event_log());
    r->key_digest[0] ^= 1;
    enum boot_cutover_replay_status refused = boot_cutover_replay_step(r);
    r->key_digest[0] ^= 1;
    bool live_refused = refused == BOOT_CUTOVER_RETRY && r->next == next &&
        !memcmp(r->key_digest, digest, sizeof(digest)) &&
        sqlite3_total_changes(r->ctx->node_db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == size;
    r->checkpoint_resume = true;
    r->key_digest[0] ^= 1;
    enum boot_cutover_replay_status fallback = boot_cutover_replay_step(r);
    return live_refused && fallback == BOOT_CUTOVER_BUSY && !r->checkpoint_resume &&
        r->next == r->floor && !memcmp(r->key_digest, zero, sizeof(zero)) &&
        sqlite3_total_changes(r->ctx->node_db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == size;
}


static bool ndc_cutover_partial_busy(struct boot_cutover_replay *r, struct db_service *svc)
{
    struct ndc_busy_worker b = {.svc = svc};
    if (pthread_mutex_init(&b.mu, NULL) || pthread_cond_init(&b.cond, NULL)) return false;
    alarm(10);
    node_db_sapling_replay_test_after_read(ndc_busy_after_read, &b);
    enum boot_cutover_replay_status status = boot_cutover_replay_step(r);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    pthread_mutex_lock(&b.mu);
    b.release = true;
    pthread_cond_broadcast(&b.cond);
    pthread_mutex_unlock(&b.mu);
    if (b.started) pthread_join(b.thread, NULL);
    alarm(0);
    pthread_cond_destroy(&b.cond);
    pthread_mutex_destroy(&b.mu);
    return b.started && b.entered && status == BOOT_CUTOVER_BUSY &&
        r->phase == BOOT_CUTOVER_DISCOVER && r->next == r->floor + 1 &&
        ndc_cutover_resume_digest(r) &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_WITNESS;
}

static bool ndc_busy_witness_same(struct node_db *db, struct ndc_replay_fixture *f,
                                  const uint8_t *witness, size_t len,
                                  int height, bool saved)
{
    uint8_t *after = NULL;
    size_t after_len = 0;
    int after_height = -1;
    bool after_saved = db_sapling_note_load_witness(db, f->note_txid.data, 1,
                                                    &after, &after_len, &after_height);
    bool same = saved == after_saved && (!saved ||
        (len == after_len && height == after_height && !memcmp(witness, after, len)));
    free(after);
    return same;
}

static bool ndc_busy_projection_same(wallet_projection_t *projection,
                                     uint64_t count, int64_t value)
{
    return count == wallet_projection_note_count(projection) &&
        value == wallet_projection_total_value_zat(projection);
}

static void ndc_stop_after_step(void)
{
    thread_registry_request_shutdown();
}

static bool ndc_stop_busy_priority(void)
{
    int64_t since = 100;
    if (boot_test_pending_busy_at(&since, 300, 1000, 200, false, true) != BOOT_BUSY_STOPPED)
        return false;
    if (boot_test_pending_busy_at(&since, 200, 1000, 200, false, true) != BOOT_BUSY_FAILED)
        return false;
    if (boot_test_pending_busy_at(&since, 300, 1000, 200, true, true) != BOOT_BUSY_FAILED)
        return false;
    if (boot_test_pending_busy_at(&since, 300, 1000, 0, false, true) != BOOT_BUSY_FAILED)
        return false;
    return boot_test_pending_busy_at(&since, 3000, 100, 200, false, true) == BOOT_BUSY_FAILED;
}

static bool ndc_stop_loop_child(struct boot_cutover_replay *r, bool fail)
{
    struct wallet_cutover_binding before, after;
    struct wallet_discover_checkpoint checkpoint_before = {0}, checkpoint_after = {0};
    enum wallet_cutover_status state = wallet_sqlite_cutover_read(r->ctx->wallet_db, &before);
    int checkpoint_state = wallet_sqlite_discover_checkpoint_read(r->ctx->wallet_db, &checkpoint_before);
    int changes = sqlite3_total_changes(r->ctx->node_db->db);
    uint64_t events = event_log_size(wallet_projection_event_log());
    if (fail) r->endpoint.hash.data[0] ^= 1;
    else {
        r->phase = BOOT_CUTOVER_TRANSPARENT;
        r->pending_complete = true;
        r->pending_end = r->endpoint.height - 1;
    }
    boot_test_pending_step_hook(ndc_stop_after_step);
    enum boot_pending_replay_result result = boot_test_pending_loop(r);
    boot_test_pending_step_hook(NULL);
    int after_state = wallet_sqlite_discover_checkpoint_read(r->ctx->wallet_db, &checkpoint_after);
    return result == (fail ? BOOT_PENDING_FAILED : BOOT_PENDING_STOPPED) &&
        state == WALLET_CUTOVER_PENDING && wallet_sqlite_cutover_read(r->ctx->wallet_db, &after) == state &&
        wallet_cutover_binding_equal(&before, &after) && checkpoint_state == after_state &&
        (checkpoint_state != WALLET_DISCOVER_FOUND ||
         !memcmp(&checkpoint_before, &checkpoint_after, sizeof(checkpoint_before))) &&
        sqlite3_total_changes(r->ctx->node_db->db) == changes &&
        event_log_size(wallet_projection_event_log()) == events;
}

static bool ndc_stop_loop_case(struct boot_cutover_replay *r, bool fail)
{
    pid_t child = fork();
    if (!child) {
        alarm(10);
        _exit(ndc_stop_loop_child(r, fail) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool ndc_cutover_busy_preflight(struct boot_cutover_replay *r)
{
    return ndc_stop_busy_priority() && ndc_stop_loop_case(r, false) &&
        ndc_stop_loop_case(r, true) && ndc_cutover_persistent_busy(r) &&
        ndc_cutover_endpoint_busy(r) && ndc_cutover_post_delivery_busy(r);
}

static bool ndc_cutover_busy_checks(struct boot_cutover_replay *r, struct ndc_replay_fixture *f)
{
    struct node_db *db = r->ctx->node_db;
    if (!ndc_cutover_busy_preflight(r)) return false;
    uint8_t *witness = NULL; size_t len = 0; int height = -1;
    bool saved = db_sapling_note_load_witness(db, f->note_txid.data, 1, &witness, &len, &height);
    int notes = db_sapling_note_count_all(db), unspent = db_sapling_note_count_unspent(db);
    char path[512]; snprintf(path, sizeof(path), "%s/busy-projection.db", f->dir);
    wallet_projection_t *projection = wallet_projection_open(path, wallet_projection_event_log());
    if (!projection) { free(witness); return false; }
    bool first_catchup = wallet_projection_catch_up(projection) != UINT64_MAX;
    uint64_t count = wallet_projection_note_count(projection);
    int64_t value = wallet_projection_total_value_zat(projection);
    bool resumed = ndc_cutover_partial_busy(r, r->service);
    bool second_catchup = wallet_projection_catch_up(projection) != UINT64_MAX;
    bool witness_same = ndc_busy_witness_same(db, f, witness, len, height, saved);
    bool same = resumed && first_catchup && second_catchup &&
        count == 1 && value == 10 && (f->fresh_spend || saved) &&
        notes == db_sapling_note_count_all(db) &&
        unspent == db_sapling_note_count_unspent(db) &&
        witness_same &&
        ndc_busy_projection_same(projection, count, value);
    wallet_projection_close(projection);
    free(witness);
    return same;
}

static bool ndc_cutover_complete(struct boot_cutover_replay *r, struct ndc_replay_fixture *f, struct node_db *fresh)
{
    return ndc_cutover_completed_busy(r) &&
        ndc_cutover_busy_checks(r, f) &&
        (!fresh || db_sapling_note_count_unspent(fresh) == 1) &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_SPENDS &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_COMPLETE &&
        !r->spends_empty &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}

static bool ndc_cutover_invalidation(struct boot_cutover_replay *r,
    struct wallet_rpc_context *ctx, struct db_service *svc,
    const struct wallet_cutover_binding *binding,
    const struct wallet_witness_endpoint *endpoint, const uint8_t identity[32])
{
    boot_cutover_replay_clear(r);
    struct boot_cutover_replay fresh;
    memset(&fresh, 0xff, sizeof(fresh));
    if (boot_cutover_replay_init(&fresh, NULL, svc, binding, 1, endpoint, identity) ||
        boot_cutover_replay_step(&fresh) != BOOT_CUTOVER_STALE ||
        boot_cutover_replay_init(r, NULL, svc, binding, 1, endpoint, identity) ||
        boot_cutover_replay_step(r) != BOOT_CUTOVER_STALE ||
        !boot_cutover_replay_init(r, ctx, svc, binding, 1, endpoint, identity)) return false;
    zcl_mutex_lock(&ctx->wallet->cs);
    ctx->wallet->readiness.epoch++;
    zcl_mutex_unlock(&ctx->wallet->cs);
    return boot_cutover_replay_step(r) == BOOT_CUTOVER_STALE &&
        wallet_readiness_get(ctx->wallet).state == WALLET_READINESS_PENDING;
}

static bool ndc_published_note(struct node_db *db, const struct ndc_replay_fixture *f)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT value,block_height,spent_txid FROM wallet_sapling_notes WHERE txid=? AND output_index=1";
    if (sqlite3_prepare_v2(db->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, f->note_txid.data, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int64(s, 0) == 10 &&
        sqlite3_column_int(s, 1) == f->slots[1].nHeight && sqlite3_column_type(s, 2) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 2) == 32 &&
        memcmp(sqlite3_column_blob(s, 2), f->spend_txid.data, 32) == 0 &&
        sqlite3_step(s) == SQLITE_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}


struct ndc_publish_case {
    struct coins_kv_read_snapshot *snapshot;
    struct coins_kv_read_snapshot_info info;
    struct wallet_cutover_v2_plan plan;
    struct db_wallet_utxo_cutover_delivery delivery;
    struct wpr *relay;
    struct wpr_pending_guard guard;
    bool opened;
};

static bool ndc_publish_coins(struct ndc_replay_fixture *f, struct ndc_publish_case *c)
{
    c->opened = progress_store_open(f->dir);
    sqlite3 *coins = c->opened ? progress_store_db() : NULL;
    const uint8_t unrelated[32] = {0xa5}, script[1] = {0x51};
    bool ok = coins && coins_kv_ensure_schema(coins) && shielded_pool_kv_ensure_schema(coins) &&
        coins_kv_add(coins, unrelated, 0, 1, 1, false, script, sizeof(script)) &&
        coins_kv_mark_migration_complete(coins) &&
        sqlite3_exec(coins, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        coins_kv_set_applied_height_in_tx(coins, f->slots[2].nHeight + 1) && coins_kv_bump_authority_generation_in_tx(coins) &&
        sqlite3_exec(coins, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok && coins) (void)sqlite3_exec(coins, "ROLLBACK", NULL, NULL, NULL);
    c->snapshot = ok ? coins_kv_read_snapshot_open(&c->info) : NULL;
    return c->snapshot != NULL;
}

static bool ndc_publish_guard(struct ndc_replay_fixture *f, struct node_db *db, struct ndc_publish_case *c)
{
    c->relay = zcl_calloc(1, sizeof(*c->relay), "cutover fixture relay");
    if (!c->relay) return false;
    wpr_init(c->relay);
    if (!wallet_cutover_v2_plan_init(&c->plan, MAX_WALLET_TX)) return false;
    struct wpr_env env = {.wallet = f->wallet, .node_db = db, .main_state = &f->state, .datadir = f->dir};
    wpr_configure(c->relay, WPR_MODE_PUBLIC, &env);
    struct wpr_pending_record record; size_t count = 0;
    enum wpr_pending_read_status status = wpr_pending_proof_begin(c->relay, &c->guard, &record, 1, &count);
    return (status == WPR_PENDING_OK || status == WPR_PENDING_ABSENT) && count == 0;
}

static bool ndc_publish_relay_released(struct wpr *relay);

static bool ndc_publish_pool(struct boot_cutover_replay *replay,
    struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct wallet_cutover_binding binding;
    if (boot_wallet_cutover_publish(replay, &c->guard, c->snapshot,
                                   &c->info, &c->plan, &c->delivery) ||
        wallet_readiness_get(replay->ctx->wallet).state != WALLET_READINESS_PENDING ||
        wallet_sqlite_cutover_read(ws, &binding) != WALLET_CUTOVER_PENDING) return false;
    wpr_pending_proof_end(&c->guard);
    coins_kv_read_snapshot_abort(c->snapshot);
    c->snapshot = NULL;
    if (boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery) ||
        c->delivery.committed || !ndc_publish_relay_released(c->relay) ||
        wallet_readiness_get(replay->ctx->wallet).state != WALLET_READINESS_PENDING ||
        wallet_sqlite_cutover_read(ws, &binding) != WALLET_CUTOVER_PENDING) return false;
    return shielded_pool_kv_put(progress_store_db(), replay->endpoint.height, 0, 0);
}

static void *ndc_publish_probe_relay(void *opaque)
{
    struct wpr *relay = opaque;
    if (!zcl_mutex_trylock(&relay->lock)) return NULL;
    zcl_mutex_unlock(&relay->lock);
    return relay;
}

static bool ndc_publish_relay_released(struct wpr *relay)
{
    pthread_t thread;
    if (pthread_create(&thread, NULL, ndc_publish_probe_relay, relay)) return false;
    void *result = NULL;
    if (pthread_join(thread, &result)) abort();
    return result == relay;
}

static bool ndc_publish_delivery_acknowledged(const struct db_wallet_utxo_cutover_delivery *delivery)
{
    return delivery->armed ? delivery->committed :
        (delivery->count == 0 && !delivery->committed);
}

void boot_cutover_publish_test_before_final(void (*hook)(void *), void *ctx);
unsigned boot_cutover_publish_test_empty_refusals(void);
static void ndc_archive_mutate_canonical(void *opaque)
{
    struct block_index *tip = opaque;
    tip->hashFinalSaplingRoot.data[0] ^= 1;
}

struct ndc_archive_lock_holder {
    zcl_mutex_t *lock;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    bool held, release;
};

static void *ndc_archive_hold_chain(void *opaque)
{
    struct ndc_archive_lock_holder *holder = opaque;
    zcl_mutex_lock(holder->lock);
    pthread_mutex_lock(&holder->mutex);
    holder->held = true;
    pthread_cond_signal(&holder->changed);
    while (!holder->release) pthread_cond_wait(&holder->changed, &holder->mutex);
    pthread_mutex_unlock(&holder->mutex);
    zcl_mutex_unlock(holder->lock);
    return NULL;
}

static bool ndc_contended_publish(struct boot_cutover_replay *replay,
    struct ndc_publish_case *c, zcl_mutex_t *lock)
{
    struct ndc_archive_lock_holder holder = {.lock = lock};
    if (pthread_mutex_init(&holder.mutex, NULL) != 0) return false;
    if (pthread_cond_init(&holder.changed, NULL) != 0) {
        pthread_mutex_destroy(&holder.mutex);
        return false;
    }
    pthread_t thread;
    bool started = pthread_create(&thread, NULL, ndc_archive_hold_chain, &holder) == 0;
    bool refused = false;
    if (started) {
        pthread_mutex_lock(&holder.mutex);
        while (!holder.held) pthread_cond_wait(&holder.changed, &holder.mutex);
        pthread_mutex_unlock(&holder.mutex);
        refused = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery);
        pthread_mutex_lock(&holder.mutex);
        holder.release = true;
        pthread_cond_signal(&holder.changed);
        pthread_mutex_unlock(&holder.mutex);
        if (pthread_join(thread, NULL) != 0) refused = false;
    }
    pthread_cond_destroy(&holder.changed);
    pthread_mutex_destroy(&holder.mutex);
    return started && refused;
}

static bool ndc_archive_contended_publish(struct boot_cutover_replay *replay,
    struct ndc_publish_case *c, struct main_state *state)
{
    return ndc_contended_publish(replay, c, &state->cs_main);
}

static bool ndc_archive_lock_refusals(struct boot_cutover_replay *replay,
    struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct main_state *states[] = {replay->canonical_state, replay->ctx->main_state};
    for (size_t i = 0; i < 2; i++) {
        bool refused = ndc_archive_contended_publish(replay, c, states[i]);
        struct wallet_cutover_binding binding;
        if (!refused || wallet_readiness_get(replay->ctx->wallet).state != WALLET_READINESS_PENDING ||
            wallet_sqlite_cutover_read(ws, &binding) != WALLET_CUTOVER_PENDING ||
            c->delivery.armed || c->delivery.committed) return false;
    }
    return true;
}

static bool ndc_archive_canonical_drift(struct boot_cutover_replay *replay,
    struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    if (!replay->canonical_state) return false;
    struct block_index *tip = active_chain_tip(&replay->canonical_state->chain_active);
    if (!tip) return false;
    boot_cutover_publish_test_before_final(ndc_archive_mutate_canonical, tip);
    struct wallet_cutover_binding binding;
    bool refused = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery) &&
        wallet_readiness_get(replay->ctx->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        !c->delivery.armed && !c->delivery.committed;
    boot_cutover_publish_test_before_final(NULL, NULL);
    tip->hashFinalSaplingRoot.data[0] ^= 1;
    return refused;
}

static bool ndc_publish_wrong_generation(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct wallet_cutover_binding binding;
    struct coins_kv_read_snapshot_info wrong = c->info; wrong.authority_generation++;
    return !boot_wallet_cutover_publish(replay, &c->guard, c->snapshot, &wrong, &c->plan, &c->delivery) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING;
}

static bool ndc_publish_wallet_assert(struct ndc_replay_fixture *f, struct node_db *db,
    struct wallet_sqlite *ws, struct wallet_cutover_binding *binding)
{
    return wallet_readiness_get(f->wallet).state == WALLET_READINESS_READY &&
        wallet_sqlite_cutover_read(ws, binding) == WALLET_CUTOVER_ABSENT &&
        wallet_sqlite_cutover_observe_completed(ws, binding) == WALLET_CUTOVER_OBS_ABSENT &&
        f->wallet->best_block_height == f->slots[2].nHeight && db_sapling_note_count_unspent(db) == 0 && ndc_published_note(db, f);
}

static bool ndc_publish_assert(struct ndc_replay_fixture *f, struct boot_cutover_replay *replay,
    struct node_db *db, struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct wallet_cutover_binding binding;
    if (replay->binding.history_identity_present) return false;
    if (!ndc_publish_wrong_generation(f, replay, ws, c)) return false;
    if (!ndc_publish_pool(replay, ws, c)) return false;
    if (replay->canonical_state && !ndc_archive_lock_refusals(replay, ws, c)) return false;
    if (replay->canonical_state && !ndc_archive_canonical_drift(replay, ws, c)) return false;
    return boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery) &&
        ndc_publish_delivery_acknowledged(&c->delivery) && ndc_publish_relay_released(c->relay) &&
        ndc_publish_wallet_assert(f, db, ws, &binding);
}

static bool ndc_cutover_publish_real(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct node_db *db, struct wallet_sqlite *ws)
{
    struct ndc_publish_case c = {0};
    bool ok = ndc_publish_coins(f, &c) && ndc_publish_guard(f, db, &c) &&
        ndc_publish_assert(f, replay, db, ws, &c);
    if (c.guard.relay) wpr_pending_proof_end(&c.guard);
    if (c.delivery.armed) ok = db_wallet_utxo_cutover_delivery_flush(&c.delivery) && ok;
    db_wallet_utxo_cutover_delivery_clear(&c.delivery);
    wallet_cutover_v2_plan_free(&c.plan);
    if (c.snapshot) coins_kv_read_snapshot_abort(c.snapshot);
    if (c.relay) { wpr_free(c.relay); free(c.relay); }
    if (c.opened) progress_store_close();
    return ok;
}

static bool ndc_archive_canonical(struct ndc_replay_fixture *f,
    struct main_state *canonical, struct block_index slots[3])
{
    main_state_init(canonical);
    for (int i = 1; i < 3; i++) {
        block_index_init(&slots[i]);
        slots[i].nHeight = f->slots[i].nHeight;
        slots[i].hashBlock = f->hashes[i];
        slots[i].phashBlock = &slots[i].hashBlock;
        slots[i].hashFinalSaplingRoot = f->slots[i].hashFinalSaplingRoot;
        slots[i].pprev = i > 1 ? &slots[i - 1] : NULL;
        if (!active_chain_install_tip_slot(&canonical->chain_active, &slots[i])) return false;
    }
    return true;
}

static bool ndc_archive_init_refusals(struct ndc_replay_fixture *f,
    struct wallet_rpc_context *ctx, struct db_service *svc,
    const struct wallet_cutover_binding *binding, const struct wallet_witness_endpoint *endpoint,
    const uint8_t identity[32], struct main_state *canonical, char *archive)
{
    struct boot_cutover_replay bad;
    char long_path[4096]; memset(long_path, 120, sizeof(long_path)); long_path[sizeof(long_path)-1] = 0;
    bool ok = !boot_cutover_replay_init_archive(&bad, ctx, svc, binding, f->slots[1].nHeight, endpoint, identity, ctx->main_state, archive) &&
        !boot_cutover_replay_init_archive(&bad, ctx, svc, binding, f->slots[1].nHeight, endpoint, identity, canonical, NULL) &&
        !boot_cutover_replay_init_archive(&bad, ctx, svc, binding, f->slots[1].nHeight, endpoint, identity, canonical, "") &&
        !boot_cutover_replay_init_archive(&bad, ctx, svc, binding, f->slots[1].nHeight, endpoint, identity, canonical, long_path);
    archive[0] = 0;
    return ok;
}

static bool ndc_replay_init_refusals(struct ndc_replay_fixture *f,
    struct wallet_rpc_context *ctx, struct db_service *svc,
    const struct wallet_cutover_binding *binding, const struct wallet_witness_endpoint *endpoint,
    const uint8_t identity[32])
{
    uint8_t bad_identity[32];
    memcpy(bad_identity, identity, 32); bad_identity[0] ^= 1;
    struct boot_cutover_replay invalid;
    if (boot_cutover_replay_init(&invalid, ctx, svc, binding, f->slots[1].nHeight, endpoint, bad_identity))
        return false;
    struct wallet_witness_endpoint bad_endpoint = *endpoint;
    bad_endpoint.hash.data[0] ^= 1;
    return !boot_cutover_replay_init(&invalid, ctx, svc, binding, f->slots[1].nHeight,
                                      &bad_endpoint, identity);
}

static bool ndc_cutover_steps(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *r, struct wallet_rpc_context *ctx,
    struct db_service *svc, struct node_db *db, struct wallet_sqlite *ws,
    const struct wallet_cutover_binding *binding, const struct wallet_witness_endpoint *endpoint,
    const uint8_t identity[32], struct main_state *canonical, char *archive, bool publish, bool ok)
{
    if (ok && publish) ok = ndc_archive_init_refusals(f, ctx, svc, binding, endpoint, identity, canonical, archive);
    if (ok) ok = ndc_replay_init_refusals(f, ctx, svc, binding, endpoint, identity);
    int saved_file = f->slots[1].nFile;
    f->slots[1].nFile = -1;
    if (ok) ok = boot_cutover_replay_step(r) == BOOT_CUTOVER_RETRY &&
        r->phase == BOOT_CUTOVER_TRANSPARENT && r->next == f->slots[1].nHeight;
    f->slots[1].nFile = saved_file;
    if (ok) ok = ndc_cutover_complete(r, f, f->fresh_spend ? db : NULL);
    if (ok) ok = publish ? ndc_cutover_publish_real(f, r, db, ws) :
        ndc_cutover_invalidation(r, ctx, svc, binding, endpoint, identity);
    return ok;
}


/* Separate children exercise the ordinary and empty-transparent paths. */
static int ndc_transparent_mode;
static int ndc_coordinator_stop_mode;
unsigned node_db_transparent_test_reads(void);

static void ndc_coordinator_stop_after_read(void *unused)
{
    (void)unused;
    thread_registry_request_shutdown();
}

static bool ndc_coordinator_stop_step(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *r, struct wallet_sqlite *ws)
{
    r->phase = BOOT_CUTOVER_DISCOVER;
    if (ndc_coordinator_stop_mode == 2) {
        struct sapling_replay_result prior = node_db_catchup_sapling_replay_at_reference(
            r->service, r->ctx->node_db, r->ctx->main_state, r->ctx->wallet, f->dir,
            r->floor, r->floor, r->endpoint.height, r->endpoint.hash.data,
            SAPLING_REPLAY_DISCOVER, f->hashes[1].data, r->identity, NULL);
        if (prior.status != SAPLING_REPLAY_COMPLETE || prior.last_complete != r->floor) return false;
        memcpy(r->key_digest, prior.key_digest, sizeof(r->key_digest));
        r->next = r->floor + 1;
    }
    node_db_sapling_replay_test_after_read(ndc_coordinator_stop_after_read, NULL);
    enum boot_cutover_replay_status status = boot_cutover_replay_step(r);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    struct wallet_cutover_binding binding;
    return status == BOOT_CUTOVER_STOPPED && r->phase == BOOT_CUTOVER_DISCOVER &&
        r->next == (ndc_coordinator_stop_mode == 2 ? r->endpoint.height + 1 : r->floor + 1) &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(&binding, &r->binding) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}

struct ndc_mint_case { struct wallet *wallet; bool minted; };
static void ndc_mint_before_publish(void *opaque)
{
    struct ndc_mint_case *m = opaque;
    struct pubkey pk;
    m->minted = wallet_generate_new_key(m->wallet, &pk);
}

static bool ndc_empty_publish_cleanup(struct ndc_publish_case *c, bool ok);

static bool ndc_mint_result(struct ndc_replay_fixture *f, struct node_db *db,
    struct wallet_sqlite *ws, struct ndc_publish_case *c, struct ndc_mint_case *mint, bool refused)
{
    struct wallet_cutover_binding binding;
    return refused && mint->minted && f->wallet->keystore.num_keys > 0 &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        !c->delivery.armed && !c->delivery.committed && ndc_published_note(db, f);
}


static bool ndc_bypass_mint_refusal(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *r, struct node_db *db, struct wallet_sqlite *ws)
{
    struct ndc_publish_case c = {0};
    struct ndc_mint_case mint = {.wallet = f->wallet};
    bool ok = ndc_publish_coins(f, &c) && ndc_publish_guard(f, db, &c);
    if (c.guard.relay) wpr_pending_proof_end(&c.guard);
    if (c.snapshot) { coins_kv_read_snapshot_abort(c.snapshot); c.snapshot = NULL; }
    if (ok) ok = shielded_pool_kv_put(progress_store_db(), r->endpoint.height, 0, 0);
    boot_cutover_publish_test_before_final(ndc_mint_before_publish, &mint);
    bool refused = ok && !boot_wallet_cutover_publish_guarded(r, c.relay, &c.delivery);
    boot_cutover_publish_test_before_final(NULL, NULL);
    ok = ndc_mint_result(f, db, ws, &c, &mint, refused);
    return ndc_empty_publish_cleanup(&c, ok);
}

static bool ndc_bypass_steps(struct ndc_replay_fixture *f, struct boot_cutover_replay *r,
    struct node_db *db, struct wallet_sqlite *ws)
{
    unsigned reads = node_db_transparent_test_reads();
    bool ok = boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_DISCOVER && r->transparent_empty &&
        node_db_transparent_test_reads() == reads &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_WITNESS && db_sapling_note_count_unspent(db) == 1 &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_SPENDS &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_COMPLETE &&
        r->phase == BOOT_CUTOVER_DONE && ndc_published_note(db, f);
    return ok && (ndc_transparent_mode == 1 ? ndc_cutover_publish_real(f, r, db, ws) :
                  ndc_bypass_mint_refusal(f, r, db, ws));
}


static bool ndc_durable_watch_present(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_watch_only WHERE address_hash=zeroblob(20) AND address=char(120)", -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1 &&
        sqlite3_step(stmt) == SQLITE_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && ok;
}

static bool ndc_durable_watch_insert(struct ndc_replay_fixture *f, struct node_db *db)
{
    if (ndc_transparent_mode != 3) return true;
    struct basic_keystore *ks = &f->wallet->keystore;
    if (ks->num_keys || ks->num_watching || ks->num_scripts || f->wallet->num_wallet_tx ||
        f->wallet->num_spent || f->wallet->key_pool_size || f->wallet->has_master_key) return false;
    for (size_t i = 0; i < MAX_KEYSTORE_WATCHING; ++i) if (ks->watching[i].used) return false;
    return sqlite3_exec(db->db,
        "INSERT INTO wallet_watch_only(address_hash,address,created_at) VALUES(zeroblob(20),char(120),0)",
        NULL, NULL, NULL) == SQLITE_OK && ndc_durable_watch_present(db->db);
}

static bool ndc_durable_watch_scan(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *r, struct node_db *db)
{
    unsigned before = node_db_transparent_test_reads();
    return ndc_durable_watch_present(db->db) &&
        boot_cutover_replay_step(r) == BOOT_CUTOVER_PROGRESS &&
        r->phase == BOOT_CUTOVER_DISCOVER && !r->transparent_empty &&
        node_db_transparent_test_reads() > before &&
        f->wallet->keystore.num_watching == 0 && ndc_durable_watch_present(db->db) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}


static bool ndc_cutover_prepare(struct ndc_replay_fixture *f, struct db_service *svc,
    struct node_db *db, struct wallet_sqlite *ws, struct wallet_rpc_context *ctx,
    struct wallet_cutover_binding *binding, struct wallet_witness_endpoint *endpoint,
    uint8_t identity[32], struct boot_cutover_replay *r, struct main_state *canonical,
    char *archive, bool publish, bool watch_ok, bool canonical_ok)
{
    return watch_ok && canonical_ok && (!publish || wallet_sqlite_flush_r(ws, f->wallet).ok) &&
        ndc_durable_watch_insert(f, db) && wallet_sqlite_cutover_prepare(ws, f->wallet, binding) &&
        wallet_scan_identity(f->wallet, identity) &&
        (publish ? boot_cutover_replay_init_archive(r, ctx, svc, binding, f->slots[1].nHeight,
                    endpoint, identity, canonical, archive) :
                   boot_cutover_replay_init(r, ctx, svc, binding, f->slots[1].nHeight, endpoint, identity));
}


static bool ndc_cutover_coordinator(struct ndc_replay_fixture *f,
    struct db_service *svc, struct node_db *db, bool publish)
{
    struct wallet_sqlite ws = {0};
    if (!wallet_sqlite_open_r(&ws, db->db).ok) return false;
    struct wallet_cutover_binding binding = {.old_height = 0, .target_height = f->slots[1].nHeight};
    memcpy(binding.target_hash, f->hashes[1].data, 32);
    binding.artifact_digest[0] = 1;
    f->wallet->scan_retry.pending = true;
    f->wallet->scan_retry.from = f->slots[1].nHeight;
    struct wallet_rpc_context ctx = {.wallet = f->wallet, .wallet_db = &ws,
        .main_state = &f->state, .node_db = db, .datadir = f->dir};
    struct wallet_witness_endpoint endpoint = {.height = f->slots[2].nHeight, .hash = f->hashes[2], .root = f->root};
    uint8_t identity[32];
    struct boot_cutover_replay r = {0};
    struct main_state canonical = {0};
    struct block_index canonical_slots[3];
    bool canonical_ok = !publish || ndc_archive_canonical(f, &canonical, canonical_slots);
    char decoy[512], archive[512];
    snprintf(decoy, sizeof(decoy), "%s/missing", f->dir);
    snprintf(archive, sizeof(archive), "%s", f->dir);
    if (publish) ctx.datadir = decoy;
    struct key_id watch = {0};
    watch.id.data[0] = 77;
    bool watch_ok = ndc_transparent_mode || keystore_add_watch_only_id(&f->wallet->keystore, &watch);
    unsigned reads = node_db_transparent_test_reads();
    bool ok = ndc_cutover_prepare(f, svc, db, &ws, &ctx, &binding, &endpoint, identity,
                                  &r, &canonical, archive, publish, watch_ok, canonical_ok);
    if (ndc_coordinator_stop_mode) ok = ok && ndc_coordinator_stop_step(f, &r, &ws);
    else if (ndc_transparent_mode == 3) ok = ok && ndc_durable_watch_scan(f, &r, db);
    else if (ndc_transparent_mode) ok = ok && ndc_bypass_steps(f, &r, db, &ws);
    else ok = ndc_cutover_steps(f, &r, &ctx, svc, db, &ws, &binding,
                                &endpoint, identity, &canonical, archive, publish, ok);
    if (!ndc_transparent_mode && !ndc_coordinator_stop_mode) ok = ok && node_db_transparent_test_reads() > reads;
    boot_cutover_replay_clear(&r);
    if (publish) main_state_free(&canonical);
    wallet_sqlite_close(&ws);
    return ok;
}

static bool ndc_replay_finish_cases(struct ndc_replay_fixture *f, struct db_service *svc,
    struct node_db *db, event_log_t *log, const uint8_t digest[32])
{
    return ndc_replay_refusal_cases(f, svc, db, log, digest) &&
        ndc_cutover_coordinator(f, svc, db, false);
}

static bool ndc_replay_restart_checks(struct ndc_replay_fixture *f, struct db_service *svc,
    struct node_db *db, event_log_t *log, const uint8_t *before, size_t bn, int bh)
{
    bool ok = ndc_identity_replay_cases(f, svc, db, before, bn, bh) && ndc_replay_reference_cases(f, svc, db);
    struct sapling_replay_result r = {0};
    if (ok) ok = ndc_epk_matrix(f, db, before, bn, bh);
    if (ok) ok = ndc_replay_delivery_failures(f, svc, db, log);
    if (ok) r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_DISCOVER, f->hashes[2].data, NULL);
    if (ok) ok = r.status == SAPLING_REPLAY_COMPLETE && r.notes_found == 1 &&
        ndc_replay_witness_unchanged(db, f->note_txid.data, before, bn, bh);
    if (ok) r = node_db_catchup_sapling_replay(svc, db, &f->state, f->wallet,
        f->dir, 1, 2, SAPLING_REPLAY_SPENDS, f->hashes[2].data, r.key_digest);
    if (ok) ok = ndc_replay_spent_result(r, db);
    if (ok) ok = ndc_epk_matrix(f, db, before, bn, bh);
    if (ok) ok = ndc_replay_finish_cases(f, svc, db, log, r.key_digest);
    return ok;
}
static bool ndc_replay_restart(struct ndc_replay_fixture *f)
{
    event_log_t *log = event_log_open(f->logpath);
    if (!log) return false;
    wallet_projection_set_event_log(log);
    struct node_db db = {0};
    if (!node_db_open(&db, f->dbpath)) return false;
    struct db_service svc;
    db_service_init(&svc);
    bool started = db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    bool ok = started;
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    uint8_t *before = NULL; size_t bn = 0; int bh = -1;
    if (ok) ok = db_sapling_note_load_witness(&db, f->note_txid.data, 1, &before, &bn, &bh);
    if (ok) ok = ndc_replay_restart_checks(f, &svc, &db, log, before, bn, bh);
    free(before);
    app_runtime_set_current(NULL);
    if (started) db_service_stop(&svc);
    node_db_close(&db);
    wallet_projection_set_event_log(NULL);
    event_log_close(log);
    return ok;
}

static bool ndc_cutover_reopen(struct ndc_replay_fixture *f)
{
    event_log_t *log = event_log_open(f->logpath);
    if (!log) return false;
    wallet_projection_set_event_log(log);
    struct node_db db = {0};
    struct db_service svc;
    db_service_init(&svc);
    bool opened = node_db_open(&db, f->dbpath);
    bool started = opened && db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    bool ok = started && ndc_cutover_coordinator(f, &svc, &db, true);
    app_runtime_set_current(NULL);
    if (started) db_service_stop(&svc);
    if (opened) node_db_close(&db);
    wallet_projection_set_event_log(NULL);
    event_log_close(log);
    return ok;
}

static bool ndc_replay_wait_child(pid_t child)
{
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void ndc_replay_stop_after_read(void *unused)
{
    (void)unused;
    thread_registry_request_shutdown();
}

static int ndc_replay_stop_deny_begin(void *ctx, int op, const char *a, const char *b,
                                      const char *c, const char *d)
{
    (void)ctx; (void)b; (void)c; (void)d;
    return op == SQLITE_TRANSACTION && a && strcmp(a, "BEGIN") == 0 ? SQLITE_DENY : SQLITE_OK;
}

static bool ndc_replay_stop_outcome(struct ndc_replay_fixture *f,
    const struct sapling_replay_result *out, int mode)
{
    enum sapling_replay_status expected = mode == 2 ? SAPLING_REPLAY_EVENT_UNAVAILABLE :
        mode == 3 ? SAPLING_REPLAY_DB_ERROR : SAPLING_REPLAY_STOPPED;
    return out->status == expected && out->last_complete == (mode < 2 ? 1 : 0) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}

static bool ndc_replay_stop_run(struct ndc_replay_fixture *f, struct node_db *db,
    struct db_service *svc, event_log_t *log, int mode)
{
    uint8_t identity[32];
    bool ok = wallet_scan_identity(f->wallet, identity);
    int fd = event_log_test_fd(log);
    if (mode == 2) event_log_test_set_fd(log, -1);
    if (mode == 3) ok = ok && sqlite3_set_authorizer(db->db, ndc_replay_stop_deny_begin, NULL) == SQLITE_OK;
    node_db_sapling_replay_test_after_read(ndc_replay_stop_after_read, NULL);
    struct sapling_replay_result out = {0};
    if (ok) out = node_db_catchup_sapling_replay_at_reference(svc, db, &f->state,
        f->wallet, f->dir, 1, mode == 1 ? 1 : 2, 2, f->hashes[2].data,
        SAPLING_REPLAY_DISCOVER, f->hashes[mode == 1 ? 1 : 2].data, identity, NULL);
    node_db_sapling_replay_test_after_read(NULL, NULL);
    if (mode == 2) event_log_test_set_fd(log, fd);
    if (mode == 3) ok = ok && sqlite3_set_authorizer(db->db, NULL, NULL) == SQLITE_OK;
    return ok && ndc_replay_stop_outcome(f, &out, mode);
}

/* Each child owns its worker and shutdown flag. The signal follows a real read. */
static bool ndc_replay_stop_child(struct ndc_replay_fixture *f, int mode)
{
    event_log_t *log = event_log_open(f->logpath);
    if (!log) return false;
    wallet_projection_set_event_log(log);
    struct node_db db = {0};
    struct db_service svc;
    db_service_init(&svc);
    bool opened = node_db_open(&db, f->dbpath);
    bool started = opened && db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    bool ok = started && ndc_replay_stop_run(f, &db, &svc, log, mode);
    app_runtime_set_current(NULL);
    if (started) db_service_stop(&svc);
    if (opened) node_db_close(&db);
    wallet_projection_set_event_log(NULL);
    event_log_close(log);
    return ok;
}

static bool ndc_replay_stop_cases(struct ndc_replay_fixture *f)
{
    uint64_t parent = (uint64_t)getpid();
    for (int mode = 0; mode < 4; ++mode) {
        pid_t child = fork();
        if (!child) {
            if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(2);
            alarm(30);
            _exit(ndc_replay_stop_child(f, mode) ? 0 : 1);
        }
        if (!ndc_replay_wait_child(child)) return false;
    }
    for (int mode = 1; mode <= 2; ++mode) {
        pid_t child = fork();
        if (!child) {
            if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(2);
            alarm(30);
            ndc_coordinator_stop_mode = mode;
            _exit(ndc_cutover_reopen(f) ? 0 : 1);
        }
        if (!ndc_replay_wait_child(child)) return false;
    }
    pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(2);
        alarm(30);
        _exit(ndc_parallel_signal_child(f) ? 0 : 1);
    }
    return ndc_replay_wait_child(child);
}

static int ndc_deny_rollback(void *ctx, int action, const char *a, const char *b,
                             const char *c, const char *d)
{
    (void)ctx; (void)b; (void)c; (void)d;
    return action == SQLITE_TRANSACTION && a && strcmp(a, "ROLLBACK") == 0
        ? SQLITE_DENY : SQLITE_OK;
}

static bool ndc_replay_fatal_exited(pid_t child)
{
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE;
}

static bool ndc_replay_rollback_failstop(const char *path)
{
    pid_t child = fork();
    if (child == 0) {
        struct node_db db = {0};
        if (!node_db_open(&db, path) ||
            sqlite3_exec(db.db, "CREATE TABLE replay_fatal_test(v INTEGER)", NULL, NULL, NULL) != SQLITE_OK ||
            !node_db_begin_immediate(&db) ||
            sqlite3_exec(db.db, "INSERT INTO replay_fatal_test VALUES(1)", NULL, NULL, NULL) != SQLITE_OK ||
            sqlite3_set_authorizer(db.db, ndc_deny_rollback, NULL) != SQLITE_OK) _exit(2);
        node_db_sapling_replay_test_rollback(&db);
        _exit(3);
    }
    if (!ndc_replay_fatal_exited(child)) return false;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "SELECT count(*) FROM replay_fatal_test", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0;
    if (stmt) sqlite3_finalize(stmt);
    if (db) sqlite3_close(db);
    return ok;
}

static bool ndc_replay_run_children(struct ndc_replay_fixture *f, bool ok)
{
    pid_t child = ok ? fork() : -1;
    if (child == 0) { node_db_sapling_replay_test_crash_before_delivery(); _exit(ndc_replay_child(f) ? 0 : 1); }
    int status = 0;
    ok = ok && child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 88;
    child = ok ? fork() : -1;
    if (child == 0) _exit(ndc_replay_child(f) ? 0 : 1);
    ok = ok && ndc_replay_wait_child(child);
    return ok;
}

static bool ndc_replay_followup(struct ndc_replay_fixture *f, bool ok)
{
    if (ok) ok = ndc_replay_restart(f);
    if (ok) ok = ndc_replay_stop_cases(f);
    pid_t restart = ok ? fork() : -1;
    if (restart == 0) _exit(ndc_cutover_reopen(f) ? 0 : 1);
    ok = ok && ndc_replay_wait_child(restart);
    char fatal_path[320]; snprintf(fatal_path, sizeof(fatal_path), "%s/fatal.db", f->dir);
    if (ok) ok = ndc_replay_rollback_failstop(fatal_path);
    return ok;
}

static int ndc_check_sapling_replay(void)
{
    int failures = 0;
    struct ndc_replay_fixture f = {0};
    test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "replay_range");
    char blocks[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
    bool ok = mkdir(blocks, 0755) == 0;
    snprintf(f.dbpath, sizeof(f.dbpath), "%s/node.db", f.dir);
    snprintf(f.logpath, sizeof(f.logpath), "%s/events.log", f.dir);
    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "replay fixture wallet");
    if (f.wallet) {
        wallet_init(f.wallet);
        ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 1);
    }
    main_state_init(&f.state);
    sapling_tree_init(&f.tree);
    uint8_t seed[32] = {1}, d[11], pk[32];
    ok = ok && f.wallet && sapling_keystore_set_seed(&f.wallet->sapling_keys, seed) &&
         sapling_keystore_new_address(&f.wallet->sapling_keys, d, pk) &&
         ndc_replay_write_fixture_block(&f, 1, d, pk) &&
         ndc_replay_write_fixture_block(&f, 2, d, pk);
    ok = ndc_replay_run_children(&f, ok);
    ok = ndc_replay_followup(&f, ok);
    NDC_CHECK("encrypted note, witness, process death and retry preserve state before spend", ok);
    if (f.wallet) { wallet_free(f.wallet); free(f.wallet); }
    main_state_free(&f.state);
    (void)test_rm_rf_recursive(f.dir);
    return failures;
}
#endif /* !_WIN32 */

#ifndef _WIN32
static bool ndc_empty_reprove(struct boot_cutover_replay *replay)
{
    struct wallet_rpc_context *ctx = replay->ctx;
    struct db_service *svc = replay->service;
    struct wallet_cutover_binding binding = replay->binding;
    struct wallet_witness_endpoint endpoint = replay->endpoint;
    int floor = replay->floor;
    bool loaded = replay->sapling_load_ok;
    uint8_t identity[32];
    boot_cutover_replay_clear(replay);
    if (!wallet_scan_identity(ctx->wallet, identity) ||
        !boot_cutover_replay_init(replay, ctx, svc, &binding, floor, &endpoint, identity)) return false;
    replay->sapling_load_ok = loaded;
    return boot_cutover_replay_step(replay) == BOOT_CUTOVER_PROGRESS &&
        replay->phase == BOOT_CUTOVER_DISCOVER &&
        boot_cutover_replay_step(replay) == BOOT_CUTOVER_COMPLETE && replay->shielded_empty;
}

static bool ndc_empty_identity_refusal(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct wallet_sqlite *ws,
    struct ndc_publish_case *c, bool ok)
{
    struct wallet_cutover_binding binding;
    struct key_id extra = {0};
    extra.id.data[0] = 77;
    if (ok) ok = keystore_add_watch_only_id(&f->wallet->keystore, &extra);
    if (ok) ok = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING;
    if (!keystore_remove_watch_only(&f->wallet->keystore, &extra)) ok = false;
    if (ok) ok = ndc_empty_reprove(replay);
    return ok;
}

static bool ndc_empty_seed_refusal(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct node_db *db,
    struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct wallet_cutover_binding binding;
    bool ok = sqlite3_exec(db->db, "INSERT INTO wallet_seed(id,seed,next_child) VALUES(1,X'00',0)",
                           NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        !c->delivery.armed && !c->delivery.committed;
    if (ok) ok = sqlite3_exec(db->db, "DELETE FROM wallet_seed", NULL, NULL, NULL) == SQLITE_OK;
    return ok;
}

static struct ndc_replay_fixture *g_ndc_boot_fixture;
static struct db_service *g_ndc_boot_service;
static void ndc_boot_build_svc(struct app_context *ctx, struct boot_svc_ctx *svc)
{
    (void)ctx;
    memset(svc, 0, sizeof(*svc));
    svc->wallet = g_ndc_boot_fixture->wallet;
    svc->state = &g_ndc_boot_fixture->state;
    svc->db_service = g_ndc_boot_service;
}

struct ndc_auth_timer_race {
    pthread_mutex_t mu;
    pthread_cond_t cond;
    bool blocked;
    bool armed;
    struct wallet *wallet;
};
static void ndc_auth_timer_blocked(void *opaque)
{
    struct ndc_auth_timer_race *race = opaque;
    pthread_mutex_lock(&race->mu);
    race->blocked = true;
    pthread_cond_signal(&race->cond);
    pthread_mutex_unlock(&race->mu);
}
static void ndc_auth_wait_timer(void *opaque)
{
    struct ndc_auth_timer_race *race = opaque;
    race->armed = wallet_lock_arm_timeout(race->wallet, 1).ok;
    if (!race->armed) return;
    pthread_mutex_lock(&race->mu);
    while (!race->blocked) pthread_cond_wait(&race->cond, &race->mu);
    pthread_mutex_unlock(&race->mu);
}
static bool ndc_auth_race_begin(struct ndc_auth_timer_race *race, struct wallet *wallet,
                                struct boot_cutover_replay *replay)
{
    memset(race, 0, sizeof(*race));
    if (pthread_mutex_init(&race->mu, NULL) || pthread_cond_init(&race->cond, NULL)) return false;
    wallet_lock_reset_for_test();
    if (!wallet_lock_unlock(NULL, NULL, "synthetic-startup-auth").ok) return false;
    wallet_lock_note_encrypted_at_rest();
    wallet_lock_timer_test_blocked_hook(ndc_auth_timer_blocked, race);
    race->wallet = wallet;
    replay->auth_deadline_ms = platform_time_monotonic_ms() + 30000;
    boot_cutover_publish_test_before_final(ndc_auth_wait_timer, race);
    return true;
}
static void ndc_auth_race_end(struct ndc_auth_timer_race *race, struct wallet *wallet)
{
    boot_cutover_publish_test_before_final(NULL, NULL);
    wallet_lock_timer_test_blocked_hook(NULL, NULL);
    wallet_lock_lock(wallet);
    pthread_cond_destroy(&race->cond);
    pthread_mutex_destroy(&race->mu);
    wallet_lock_reset_for_test();
}


static bool ndc_auth_expired_refused(struct ndc_replay_fixture *f, struct wallet_sqlite *ws,
                                     struct boot_cutover_env *env, struct app_context *ctx,
                                     struct boot_cutover_replay *replay)
{
    struct wallet_cutover_binding binding;
    int64_t future = replay->auth_deadline_ms;
    bool unlocked = !wallet_lock_is_locked();
    replay->auth_deadline_ms = 1;
    bool expired = unlocked && !boot_test_pending_publish(env, ctx, chain_params_get(), replay) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING;
    replay->auth_deadline_ms = future;
    return expired;
}


static bool ndc_empty_publish_ready(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct wallet_cutover_binding binding;
    (void)c;
    g_ndc_boot_fixture = f; g_ndc_boot_service = replay->service;
    struct boot_cutover_env env = {.wallet = f->wallet, .node = replay->ctx->node_db,
        .db_service = replay->service, .build_svc = ndc_boot_build_svc};
    struct app_context ctx = {.datadir = f->dir};
    struct boot_cutover_env missing = env; missing.node = NULL;
    bool refused = !boot_test_pending_publish(&missing, &ctx, chain_params_get(), replay) &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING;
    struct ndc_auth_timer_race race;
    bool race_started = ndc_auth_race_begin(&race, f->wallet, replay);
    bool expired = race_started && ndc_auth_expired_refused(f, ws, &env, &ctx, replay);
    bool published = race_started && boot_test_pending_publish(&env, &ctx, chain_params_get(), replay);
    if (race_started) ndc_auth_race_end(&race, f->wallet);
    g_ndc_boot_fixture = NULL; g_ndc_boot_service = NULL;
    return refused && expired && race_started && race.armed && race.blocked && published && wallet_readiness_get(f->wallet).state == WALLET_READINESS_READY &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_ABSENT;
}

static bool ndc_empty_publish_cleanup(struct ndc_publish_case *c, bool ok)
{
    if (c->guard.relay) wpr_pending_proof_end(&c->guard);
    if (c->delivery.armed) ok = db_wallet_utxo_cutover_delivery_flush(&c->delivery) && ok;
    db_wallet_utxo_cutover_delivery_clear(&c->delivery);
    wallet_cutover_v2_plan_free(&c->plan);
    if (c->snapshot) coins_kv_read_snapshot_abort(c->snapshot);
    if (c->relay) { wpr_free(c->relay); free(c->relay); }
    if (c->opened) progress_store_close();
    return ok;
}

struct ndc_empty_mutation { struct node_db *db; bool inserted; };
static void ndc_empty_insert_watch(void *opaque)
{
    struct ndc_empty_mutation *m = opaque;
    m->inserted = sqlite3_exec(m->db->db,
        "INSERT INTO wallet_watch_only(address_hash,address,created_at) VALUES(zeroblob(20),char(120),0)",
        NULL, NULL, NULL) == SQLITE_OK;
}
static bool ndc_empty_final_mutation(struct boot_cutover_replay *replay,
    struct wallet_sqlite *ws, struct ndc_publish_case *c)
{
    struct ndc_empty_mutation m = {.db = replay->ctx->node_db};
    struct wallet_cutover_binding binding;
    unsigned before = boot_cutover_publish_test_empty_refusals();
    boot_cutover_publish_test_before_final(ndc_empty_insert_watch, &m);
    bool refused = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery);
    boot_cutover_publish_test_before_final(NULL, NULL);
    bool pending = wallet_readiness_get(replay->ctx->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        !c->delivery.armed && !c->delivery.committed;
    bool removed = sqlite3_exec(m.db->db, "DELETE FROM wallet_watch_only", NULL, NULL, NULL) == SQLITE_OK;
    return m.inserted && refused && pending && removed &&
        boot_cutover_publish_test_empty_refusals() == before + 1;
}


static bool ndc_empty_full_reprove(struct boot_cutover_replay *replay)
{
    struct wallet_rpc_context *ctx = replay->ctx;
    struct db_service *svc = replay->service;
    struct wallet_cutover_binding binding = replay->binding;
    struct wallet_witness_endpoint endpoint = replay->endpoint;
    int floor = replay->floor;
    bool loaded = replay->sapling_load_ok;
    uint8_t identity[32];
    boot_cutover_replay_clear(replay);
    if (!wallet_scan_identity(ctx->wallet, identity) ||
        !boot_cutover_replay_init(replay, ctx, svc, &binding, floor, &endpoint, identity)) return false;
    replay->sapling_load_ok = loaded;
    return boot_cutover_replay_complete_full_empty(replay) && replay->full_empty;
}

static bool ndc_empty_publish(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct node_db *db, struct wallet_sqlite *ws, bool full)
{
    struct ndc_publish_case c = {0};
    bool ok = ndc_publish_coins(f, &c) && ndc_publish_guard(f, db, &c);
    if (c.guard.relay) wpr_pending_proof_end(&c.guard);
    if (c.snapshot) {
        coins_kv_read_snapshot_abort(c.snapshot);
        c.snapshot = NULL;
    }
    if (ok) ok = shielded_pool_kv_put(progress_store_db(), replay->endpoint.height, 0, 0);
    if (full) {
        if (ok) ok = ndc_empty_full_reprove(replay) && ndc_empty_final_mutation(replay, ws, &c) &&
            ndc_empty_full_reprove(replay) && replay->full_empty;
    } else {
        ok = ndc_empty_identity_refusal(f, replay, ws, &c, ok);
        if (ok) ok = ndc_empty_seed_refusal(f, replay, db, ws, &c);
    }
    if (ok) ok = ndc_empty_publish_ready(f, replay, ws, &c);
    return ndc_empty_publish_cleanup(&c, ok);
}

static bool ndc_no_notes_floor_only(const struct boot_cutover_replay *replay)
{
    if (replay->phase != BOOT_CUTOVER_SPENDS || replay->next != replay->floor ||
        replay->floor >= replay->endpoint.height) return false;
    struct boot_cutover_replay probe = *replay;
    probe.next = probe.floor + 1;
    enum boot_cutover_replay_status status = boot_cutover_replay_step(&probe);
    return status == BOOT_CUTOVER_COMPLETE && !probe.spends_empty &&
        probe.phase == BOOT_CUTOVER_DONE;
}

static bool ndc_no_notes_key(struct wallet_sqlite *ws)
{
    struct wallet *tmp = zcl_calloc(1, sizeof(*tmp), "no notes seed");
    if (!tmp) return false;
    wallet_init(tmp);
    uint8_t seed[32] = {2}, d[11], pk[32];
    bool ok = sapling_keystore_set_seed(&tmp->sapling_keys, seed) &&
        sapling_keystore_new_address(&tmp->sapling_keys, d, pk) &&
        wallet_sqlite_write_sapling_seed(ws, seed) &&
        wallet_sqlite_write_sapling_key(ws, 0, &tmp->sapling_keys.keys[0]);
    wallet_free(tmp); free(tmp);
    return ok;
}

struct ndc_notes_mutation {
    struct node_db *db;
    struct wallet *wallet;
    int mode;
    bool changed;
};

static void ndc_notes_mutate(void *opaque)
{
    struct ndc_notes_mutation *m = opaque;
    if (m->mode == 0) {
        m->changed = sqlite3_exec(m->db->db,
            "INSERT INTO wallet_sapling_notes(txid,output_index,value,rcm,ivk,diversifier,pk_d,cm,nullifier) "
            "VALUES(zeroblob(32),0,1,zeroblob(32),zeroblob(32),zeroblob(11),zeroblob(32),zeroblob(32),zeroblob(32))",
            NULL, NULL, NULL) == SQLITE_OK;
    } else if (m->mode == 1) {
        zcl_mutex_lock(&m->wallet->cs);
        if (m->wallet->sapling_notes_cap && m->wallet->sapling_notes && !m->wallet->sapling_notes[0].used) {
            m->wallet->sapling_notes[0].used = true; m->changed = true;
        }
        zcl_mutex_unlock(&m->wallet->cs);
    } else if (m->mode == 2) {
        zcl_mutex_lock(&m->wallet->sapling_keys.cs);
        if (m->wallet->sapling_keys.num_keys > 0 && m->wallet->sapling_keys.keys[0].used) {
            m->wallet->sapling_keys.keys[0].ivk[0] ^= 1; m->changed = true;
        }
        zcl_mutex_unlock(&m->wallet->sapling_keys.cs);
    } else {
        zcl_mutex_lock(&m->wallet->cs);
        ++m->wallet->readiness.epoch; m->changed = true;
        zcl_mutex_unlock(&m->wallet->cs);
    }
}

static bool ndc_notes_restore(struct ndc_notes_mutation *m, int mode)
{
    bool restored = true;
    if (mode == 0 && m->changed)
        restored = sqlite3_exec(m->db->db, "DELETE FROM wallet_sapling_notes", NULL, NULL, NULL) == SQLITE_OK;
    else if (mode == 1 && m->changed) m->wallet->sapling_notes[0].used = false;
    else if (mode == 2 && m->changed) {
        zcl_mutex_lock(&m->wallet->sapling_keys.cs);
        m->wallet->sapling_keys.keys[0].ivk[0] ^= 1;
        zcl_mutex_unlock(&m->wallet->sapling_keys.cs);
    }
    else if (mode == 3 && m->changed) --m->wallet->readiness.epoch;
    return restored;
}

static bool ndc_notes_refusal(struct boot_cutover_replay *replay,
    struct wallet_sqlite *ws, struct ndc_publish_case *c, int mode)
{
    struct ndc_notes_mutation m = {.db = replay->ctx->node_db, .wallet = replay->ctx->wallet, .mode = mode};
    if (mode == 1 && !m.wallet->sapling_notes_cap) {
        m.wallet->sapling_notes = calloc(1, sizeof(*m.wallet->sapling_notes));
        if (!m.wallet->sapling_notes) return false;
        m.wallet->sapling_notes_cap = 1;
    }
    boot_cutover_publish_test_before_final(ndc_notes_mutate, &m);
    bool refused = !boot_wallet_cutover_publish_guarded(replay, c->relay, &c->delivery);
    boot_cutover_publish_test_before_final(NULL, NULL);
    struct wallet_cutover_binding binding;
    bool pending = wallet_readiness_get(m.wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        !c->delivery.armed && !c->delivery.committed;
    bool restored = ndc_notes_restore(&m, mode);
    return m.changed && refused && pending && restored;
}

static bool ndc_no_notes_publish(struct ndc_replay_fixture *f,
    struct boot_cutover_replay *replay, struct node_db *db, struct wallet_sqlite *ws)
{
    struct ndc_publish_case c = {0};
    bool ok = ndc_publish_coins(f, &c) && ndc_publish_guard(f, db, &c);
    if (c.guard.relay) wpr_pending_proof_end(&c.guard);
    if (c.snapshot) { coins_kv_read_snapshot_abort(c.snapshot); c.snapshot = NULL; }
    if (ok) ok = shielded_pool_kv_put(progress_store_db(), replay->endpoint.height, 0, 0);
    for (int mode = 0; ok && mode < 4; ++mode) ok = ndc_notes_refusal(replay, ws, &c, mode);
    if (ok) ok = ndc_contended_publish(replay, &c, &replay->ctx->wallet->cs);
    if (ok) ok = ndc_empty_publish_ready(f, replay, ws, &c);
    return ndc_empty_publish_cleanup(&c, ok);
}

static bool ndc_populated_empty_steps(struct boot_cutover_replay *replay, struct node_db *db)
{
    return boot_cutover_replay_step(replay) == BOOT_CUTOVER_PROGRESS &&
        replay->phase == BOOT_CUTOVER_WITNESS && db_sapling_note_count_all(db) == 0 &&
        boot_cutover_replay_step(replay) == BOOT_CUTOVER_PROGRESS &&
        replay->phase == BOOT_CUTOVER_SPENDS && replay->next == replay->floor &&
        ndc_no_notes_floor_only(replay) &&
        boot_cutover_replay_step(replay) == BOOT_CUTOVER_COMPLETE &&
        replay->spends_empty && !replay->shielded_empty && replay->phase == BOOT_CUTOVER_DONE;
}

static bool ndc_unpopulated_empty_steps(struct boot_cutover_replay *replay)
{
    return boot_cutover_replay_step(replay) == BOOT_CUTOVER_COMPLETE &&
        replay->shielded_empty && replay->phase == BOOT_CUTOVER_DONE;
}

static bool ndc_empty_replay(struct ndc_replay_fixture *f, struct node_db *db,
                             struct db_service *svc, bool full, bool populated)
{
    struct wallet_sqlite ws = {0};
    if (!wallet_sqlite_open_r(&ws, db->db).ok) return false;
    if (populated && !ndc_no_notes_key(&ws)) { wallet_sqlite_close(&ws); return false; }
    bool loaded = wallet_sqlite_read_sapling_keys(&ws, f->wallet);
    struct wallet_cutover_binding binding = {.old_height = 0, .target_height = f->slots[1].nHeight};
    memcpy(binding.target_hash, f->hashes[1].data, 32);
    binding.artifact_digest[0] = 1;
    f->wallet->scan_retry.pending = true;
    f->wallet->scan_retry.from = f->slots[1].nHeight;
    struct wallet_rpc_context ctx = {.wallet = f->wallet, .wallet_db = &ws,
        .main_state = &f->state, .node_db = db, .datadir = f->dir};
    struct wallet_witness_endpoint endpoint = {.height = f->slots[2].nHeight,
        .hash = f->hashes[2], .root = f->root};
    struct boot_cutover_replay replay = {0};
    uint8_t identity[32];
    bool ok = loaded && wallet_sqlite_cutover_prepare(&ws, f->wallet, &binding) &&
        wallet_scan_identity(f->wallet, identity) &&
        boot_cutover_replay_init(&replay, &ctx, svc, &binding, f->slots[1].nHeight,
                                 &endpoint, identity);
    replay.sapling_load_ok = loaded;
    if (ok) ok = boot_cutover_replay_step(&replay) == BOOT_CUTOVER_PROGRESS &&
        replay.phase == BOOT_CUTOVER_DISCOVER;
    if (ok && populated) ok = ndc_populated_empty_steps(&replay, db);
    else if (ok) ok = ndc_unpopulated_empty_steps(&replay);
    if (ok) ok = populated ? ndc_no_notes_publish(f, &replay, db, &ws) :
        ndc_empty_publish(f, &replay, db, &ws, full);
    boot_cutover_replay_clear(&replay);
    wallet_sqlite_close(&ws);
    return ok;
}

static bool ndc_empty_fixture_blocks(struct ndc_replay_fixture *f, bool ok)
{
    uint8_t seed[32] = {1}, d[11], pk[32];
    return ok && sapling_keystore_set_seed(&f->wallet->sapling_keys, seed) &&
        sapling_keystore_new_address(&f->wallet->sapling_keys, d, pk) &&
        ndc_replay_write_fixture_block(f, 1, d, pk) &&
        ndc_replay_write_fixture_block(f, 2, d, pk);
}

static bool ndc_empty_fixture_service(struct ndc_replay_fixture *f, bool ok, bool full, bool populated)
{
    struct node_db db = {0};
    struct db_service svc;
    db_service_init(&svc);
    bool opened = ok && wallet_readiness_initialize(f->wallet, WALLET_READINESS_PENDING, true, 1) &&
        node_db_open(&db, f->dbpath);
    bool started = opened && db_service_attach(&svc, &db) && db_service_start_test_worker(&svc);
    struct app_runtime_context runtime = {.db_service = &svc};
    app_runtime_set_current(&runtime);
    char path[512]; snprintf(path, sizeof(path), "%s/no-notes-events.log", f->dir);
    event_log_t *log = populated ? event_log_open(path) : NULL;
    if (log) wallet_projection_set_event_log(log);
    ok = started && (!populated || log) && ndc_empty_replay(f, &db, &svc, full, populated);
    if (log) { wallet_projection_set_event_log(NULL); event_log_close(log); }
    app_runtime_set_current(NULL);
    if (started) db_service_stop(&svc);
    if (opened) node_db_close(&db);
    return ok;
}

static bool ndc_empty_fixture_child(const char *base, bool full, bool populated)
{
    chain_params_select(CHAIN_TESTNET);
    if (!SetDataDir(base)) return false;
    struct ndc_replay_fixture f = {.height_offset = NDC_SAP_OFF - 1};
    GetDataDir(true, f.dir, sizeof(f.dir));
    char blocks[320];
    snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
    bool ok = f.dir[0] && (mkdir(blocks, 0700) == 0 || errno == EEXIST);
    snprintf(f.dbpath, sizeof(f.dbpath), "%s/node.db", f.dir);
    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "empty replay wallet");
    if (!f.wallet) return false;
    wallet_init(f.wallet);
    main_state_init(&f.state);
    sapling_tree_init(&f.tree);
    ok = ndc_empty_fixture_blocks(&f, ok);
    wallet_free(f.wallet);
    free(f.wallet);
    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "empty replay wallet");
    if (!f.wallet) { main_state_free(&f.state); return false; }
    wallet_init(f.wallet);
    ok = ndc_empty_fixture_service(&f, ok, full, populated);
    main_state_free(&f.state);
    wallet_free(f.wallet);
    free(f.wallet);
    return ok;
}

static int ndc_check_empty_cutover(void)
{
    int failures = 0;
    char base[256];
    test_make_tmpdir(base, sizeof(base), "node_db_catchup", "empty_cutover");
    pid_t child = fork();
    if (child == 0) { alarm(60); _exit(ndc_empty_fixture_child(base, false, false) ? 0 : 1); }
    NDC_CHECK("empty shielded replay publishes only while the proof remains valid",
              ndc_replay_wait_child(child));
    (void)test_rm_rf_recursive(base);
    test_make_tmpdir(base, sizeof(base), "node_db_catchup", "full_empty_cutover");
    child = fork();
    if (child == 0) { alarm(60); _exit(ndc_empty_fixture_child(base, true, false) ? 0 : 1); }
    NDC_CHECK("full empty proof publishes only after final revalidation", ndc_replay_wait_child(child));
    (void)test_rm_rf_recursive(base);
    test_make_tmpdir(base, sizeof(base), "node_db_catchup", "populated_no_notes");
    child = fork();
    if (child == 0) { alarm(60); _exit(ndc_empty_fixture_child(base, false, true) ? 0 : 1); }
    NDC_CHECK("populated Sapling replay discovers, witnesses and skips empty spends", ndc_replay_wait_child(child));
    (void)test_rm_rf_recursive(base);
    return failures;
}

static bool ndc_fresh_spend_child(const char *base)
{
    chain_params_select(CHAIN_TESTNET);
    if (!SetDataDir(base)) return false;
    struct ndc_replay_fixture f = {.height_offset = NDC_SAP_OFF - 1, .fresh_spend = true};
    GetDataDir(true, f.dir, sizeof(f.dir));
    char blocks[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
    bool ok = f.dir[0] && (mkdir(blocks, 0700) == 0 || errno == EEXIST);
    snprintf(f.dbpath, sizeof(f.dbpath), "%s/node.db", f.dir);
    snprintf(f.logpath, sizeof(f.logpath), "%s/events.log", f.dir);
    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "fresh spend wallet");
    if (!f.wallet) return false;
    wallet_init(f.wallet);
    main_state_init(&f.state);
    sapling_tree_init(&f.tree);
    uint8_t seed[32] = {1}, d[11], pk[32];
    ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 1) &&
        sapling_keystore_set_seed(&f.wallet->sapling_keys, seed) &&
        sapling_keystore_new_address(&f.wallet->sapling_keys, d, pk) &&
        ndc_replay_write_fixture_block(&f, 1, d, pk) &&
        ndc_replay_write_fixture_block(&f, 2, d, pk) && ndc_cutover_reopen(&f);
    main_state_free(&f.state);
    wallet_free(f.wallet); free(f.wallet);
    return ok;
}

static int ndc_check_fresh_spend_publication(void)
{
    int failures = 0;
    char base[256];
    test_make_tmpdir(base, sizeof(base), "node_db_catchup", "fresh_spend");
    pid_t child = fork();
    if (child == 0) _exit(ndc_fresh_spend_child(base) ? 0 : 1);
    NDC_CHECK("activated-chain replay discovers, witnesses and attributes a fresh spend before publication",
        ndc_replay_wait_child(child));
    (void)test_rm_rf_recursive(base);
    return failures;
}
static int ndc_check_transparent_bypass_cutover(void)
{
    int failures = 0;
    for (int mode = 1; mode <= 3; ++mode) {
        char base[256];
        test_make_tmpdir(base, sizeof(base), "node_db_catchup", "transparent_bypass");
        pid_t parent = getpid();
        pid_t child = fork();
        if (child == 0) {
            if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(1);
            alarm(60);
            ndc_transparent_mode = mode;
            _exit(ndc_fresh_spend_child(base) ? 0 : 1);
        }
        NDC_CHECK("transparent bypass discovers real note and enforces final key proof",
                  ndc_replay_wait_child(child));
        (void)test_rm_rf_recursive(base);
    }
    return failures;
}

#endif

static bool ndc_replay_event_rollback(struct node_db *db, event_log_t *log,
                                      struct db_sapling_note *n)
{
    struct sapling_replay_delivery d = {0};
    bool ok = node_db_begin_immediate(db) &&
        db_sapling_note_merge_replayed(db, n, &d) == SAPLING_REPLAY_MERGE_INSERTED &&
        event_log_size(log) == 0 && node_db_rollback(db) && event_log_size(log) == 0 && d.committed == 0;
    db_sapling_replay_delivery_clear(&d);
    return ok;
}

static bool ndc_replay_event_commit(struct node_db *db, event_log_t *log,
                                    struct db_sapling_note *n, uint64_t *committed)
{
    struct sapling_replay_delivery d = {0};
    bool ok = node_db_begin_immediate(db) &&
        db_sapling_note_merge_replayed(db, n, &d) == SAPLING_REPLAY_MERGE_INSERTED &&
        event_log_size(log) == 0 && node_db_commit(db) &&
        db_sapling_replay_delivery_flush(&d);
    db_sapling_replay_delivery_clear(&d);
    *committed = event_log_size(log);
    if (ok) ok = *committed > 0 && node_db_begin_immediate(db) &&
        db_sapling_note_merge_replayed(db, n, &d) == SAPLING_REPLAY_MERGE_EXISTING &&
        node_db_commit(db) && db_sapling_replay_delivery_flush(&d) &&
        event_log_size(log) > *committed;
    db_sapling_replay_delivery_clear(&d);
    *committed = event_log_size(log);
    return ok;
}

static bool ndc_replay_event_untracked(struct node_db *db, event_log_t *log,
                                       struct db_sapling_note *n, uint64_t committed)
{
    struct sapling_replay_delivery d = {0};
    bool ok = sqlite3_exec(db->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        db_sapling_note_merge_replayed(db, n, &d) == SAPLING_REPLAY_MERGE_ERROR &&
        sqlite3_exec(db->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK &&
        event_log_size(log) == committed;
    db_sapling_replay_delivery_clear(&d);
    return ok;
}

static bool ndc_replay_event_oom(struct node_db *db, event_log_t *log,
                                 struct db_sapling_note *n, uint64_t committed)
{
    struct sapling_replay_delivery d = {0};
    n->txid[0] ^= 0x80; n->nullifier[0] ^= 0x80;
    bool began = node_db_begin_immediate(db);
    zcl_alloc_fault_fail_nth("after_commit record copy", 1);
    enum sapling_replay_merge_result failed = began ? db_sapling_note_merge_replayed(db, n, &d) : SAPLING_REPLAY_MERGE_INSERTED;
    zcl_alloc_fault_clear();
    bool rolled = began && node_db_rollback(db);
    bool ok = failed == SAPLING_REPLAY_MERGE_ERROR && rolled &&
           db_sapling_note_count_unspent(db) == 1 && event_log_size(log) == committed && d.committed == 0;
    db_sapling_replay_delivery_clear(&d);
    return ok;
}

static void ndc_replay_count_hook(void *record, void *ctx)
{
    (void)record;
    ++*(int *)ctx;
}

static bool ndc_replay_autorollback_discards_hooks(struct node_db *db)
{
    int count = 0, record = 1;
    if (!node_db_begin_immediate(db) ||
        !ar_after_commit_enqueue(ndc_replay_count_hook, &count, &record, sizeof(record))) return false;
    db->sync_in_batch = true;
    bool ok = sqlite3_exec(db->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK &&
        !node_db_sapling_replay_test_flush_batch(db).ok && ar_after_commit_depth() == 0 &&
        ar_after_commit_pending() == 0 && node_db_begin_immediate(db) && node_db_commit(db);
    return ok && count == 0;
}

static int ndc_check_replay_projection_commit(void)
{
    int failures = 0;
    char dir[256], dbpath[320], logpath[320];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "replay_event");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(logpath, sizeof(logpath), "%s/events.log", dir);
    struct node_db db = {0};
    event_log_t *log = event_log_open(logpath);
    bool ok = log && node_db_open(&db, dbpath);
    wallet_projection_set_event_log(log);
    struct db_sapling_note n = {0};
    memset(n.txid, 1, 32); memset(n.rcm, 2, 32); memset(n.ivk, 3, 32);
    memset(n.diversifier, 4, 11); memset(n.pk_d, 5, 32);
    memset(n.cm, 6, 32); memset(n.nullifier, 7, 32);
    n.value = 12; n.block_height = 15;
    if (ok) ok = ndc_replay_event_rollback(&db, log, &n);
    NDC_CHECK("replay rollback emits no note projection", ok);
    uint64_t committed = 0;
    if (ok) ok = ndc_replay_event_commit(&db, log, &n, &committed);
    NDC_CHECK("replay commit and retry emit convergent events", ok);
    if (ok) ok = ndc_replay_event_untracked(&db, log, &n, committed);
    NDC_CHECK("untracked transaction refuses replay", ok);
    if (ok) ok = ndc_replay_event_oom(&db, log, &n, committed);
    NDC_CHECK("event enqueue failure rolls back note and emits nothing", ok);
    if (ok) ok = ndc_replay_autorollback_discards_hooks(&db);
    NDC_CHECK("auto-rollback discards stale hooks", ok);
    wallet_projection_set_event_log(NULL);
    if (db.open) node_db_close(&db);
    event_log_close(log);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

#ifndef _WIN32
struct ndc_transparent_fixture {
    char dir[256];
    struct main_state state;
    struct wallet *wallet;
    struct block_index slots[4];
    struct uint256 hashes[4], funding, spend;
    struct key_id watch;
    off_t tamper_offset;
    int file;
};

static bool ndc_transparent_write(struct ndc_transparent_fixture *f, int height)
{
    struct block b; block_init(&b);
    b.header.nVersion = 4; b.header.nTime = 1700000000u + (unsigned)height;
    b.header.nBits = 0x2000ffffu; b.header.hashPrevBlock = f->hashes[height - 1];
    b.num_vtx = 1; b.vtx = zcl_calloc(1, sizeof(*b.vtx), "transparent fixture tx");
    if (!b.vtx) return false;
    struct transaction *tx = b.vtx; transaction_init(tx);
    bool ok = transaction_alloc(tx, 1, 1);
    if (ok && height == 1) {
        struct tx_destination dest = {.type = DEST_KEY_ID, .id.key = f->watch};
        script_for_destination(&tx->vout[0].script_pub_key, &dest);
        tx->vout[0].value = 12345;
    } else if (ok) { tx->vin[0].prevout.hash = f->funding; tx->vin[0].prevout.n = 0; }
    if (ok) { transaction_compute_hash(tx); b.header.hashMerkleRoot = tx->hash; }
    if (ok && height == 1) f->funding = tx->hash;
    if (ok && height == 2) f->spend = tx->hash;
    struct byte_stream bytes; stream_init(&bytes, 4096);
    if (ok) ok = block_serialize(&b, &bytes);
    struct disk_block_pos pos; disk_block_pos_init(&pos);
    const unsigned char magic[4] = {0x24, 0xe9, 0x27, 0x64};
    if (ok) ok = write_block_to_disk(&b, &pos, f->dir, magic);
    if (ok) {
        block_get_hash(&b, &f->hashes[height]);
        struct block_index *p = &f->slots[height];
        block_index_init(p); p->nHeight = height; p->nFile = pos.nFile;
        p->nDataPos = pos.nPos; p->nStatus = BLOCK_HAVE_DATA; p->phashBlock = &f->hashes[height];
        ok = active_chain_install_tip_slot(&f->state.chain_active, p);
        if (height == 2) { f->file = pos.nFile; f->tamper_offset = (off_t)pos.nPos + (off_t)bytes.size - 1; }
    }
    stream_free(&bytes); block_free(&b);
    return ok;
}

static bool ndc_transparent_tamper(struct ndc_transparent_fixture *f,
                                   const uint8_t identity[32])
{
    char path[320]; snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", f->dir, f->file);
    int fd = open(path, O_RDWR); unsigned char original = 0, changed;
    if (fd < 0) return false;
    bool ok = pread(fd, &original, 1, f->tamper_offset) == 1;
    changed = original ^ 1u;
    if (ok) ok = pwrite(fd, &changed, 1, f->tamper_offset) == 1;
    struct transparent_replay_result r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity);
    if (ok) ok = r.status == TRANSPARENT_REPLAY_INCOMPLETE && r.last_complete == 1;
    if (pwrite(fd, &original, 1, f->tamper_offset) != 1) ok = false;
    close(fd); return ok;
}

static bool ndc_transparent_refusals(struct ndc_transparent_fixture *f,
                                     uint8_t identity[32])
{
    uint8_t wrong[32]; memcpy(wrong, f->hashes[2].data, 32); wrong[0] ^= 1;
    struct transparent_replay_result r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 2, 2, wrong, identity);
    if (r.status != TRANSPARENT_REPLAY_CHAIN_CHANGED) return false;
    memcpy(wrong, f->hashes[2].data, 32); f->hashes[2].data[0] ^= 1;
    r = node_db_catchup_wallet_transparent(&f->state, f->wallet, f->dir, 1, 2, 2, wrong, identity);
    f->hashes[2].data[0] ^= 1;
    if (r.status != TRANSPARENT_REPLAY_CHAIN_CHANGED) return false;
    memcpy(wrong, identity, 32); wrong[0] ^= 1;
    r = node_db_catchup_wallet_transparent(&f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, wrong);
    if (r.status != TRANSPARENT_REPLAY_KEYS_CHANGED) return false;
    struct key_id extra = {0}; extra.id.data[0] = 77;
    if (!keystore_add_watch_only_id(&f->wallet->keystore, &extra)) return false;
    r = node_db_catchup_wallet_transparent(&f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity);
    if (r.status != TRANSPARENT_REPLAY_KEYS_CHANGED || !wallet_scan_identity(f->wallet, identity)) return false;
    int file = f->slots[1].nFile; f->slots[1].nFile = -1;
    r = node_db_catchup_wallet_transparent(&f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity);
    f->slots[1].nFile = file;
    return r.status == TRANSPARENT_REPLAY_INCOMPLETE && ndc_transparent_tamper(f, identity);
}

static bool ndc_transparent_identity_one(struct ndc_transparent_fixture *f, int which)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    size_t before = f->wallet->num_wallet_tx;
    bool spent = wallet_is_outpoint_spent(f->wallet, &f->funding, 0);
    struct ndc_identity_probe p = {.wallet = f->wallet, .which = which};
    node_db_transparent_replay_test_after_read(ndc_identity_mutate_once, &p);
    struct transparent_replay_result r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data, identity);
    node_db_transparent_replay_test_after_read(NULL, NULL);
    if (p.fired) ndc_identity_flip(f->wallet, which);
    return p.fired && r.status == TRANSPARENT_REPLAY_KEYS_CHANGED && r.last_complete == 0 &&
        f->wallet->num_wallet_tx == before &&
        wallet_is_outpoint_spent(f->wallet, &f->funding, 0) == spent &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
}
static bool ndc_transparent_capture_once(struct ndc_transparent_fixture *f)
{
    uint8_t identity[32];
    if (!wallet_scan_identity(f->wallet, identity)) return false;
    zcl_alloc_fault_fail_nth("wallet scan snapshot", 2);
    struct transparent_replay_result r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity);
    bool once = zcl_alloc_fault_armed_label() && r.status == TRANSPARENT_REPLAY_COMPLETE;
    zcl_alloc_fault_clear();
    size_t before = f->wallet->num_wallet_tx;
    zcl_alloc_fault_fail_next("wallet scan snapshot");
    r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data, identity);
    zcl_alloc_fault_clear();
    return once && r.status == TRANSPARENT_REPLAY_KEYS_CHANGED && f->wallet->num_wallet_tx == before;
}
static bool ndc_transparent_identity_cases(struct ndc_transparent_fixture *f)
{
    struct ndc_identity_saved saved;
    ndc_identity_seed(f->wallet, &saved);
    struct sapling_key_entry saved_sapling = f->wallet->sapling_keys.keys[0];
    size_t count = f->wallet->sapling_keys.num_keys;
    f->wallet->sapling_keys.num_keys = 1;
    f->wallet->sapling_keys.keys[0].used = true;
    bool ok = ndc_transparent_capture_once(f);
    for (int which = 0; ok && which <= 30; ++which)
        ok = ndc_transparent_identity_one(f, which);
    f->wallet->sapling_keys.keys[0] = saved_sapling;
    f->wallet->sapling_keys.num_keys = count;
    ndc_identity_unseed(f->wallet, &saved);
    return ok;
}

static bool ndc_transparent_extension(struct ndc_transparent_fixture *f,
                                      const uint8_t identity[32])
{
    if (!ndc_transparent_write(f, 3)) return false;
    struct transparent_replay_result r = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity);
    return r.status == TRANSPARENT_REPLAY_COMPLETE && r.last_complete == 2 &&
        r.reference_height == 2 && f->wallet->num_wallet_tx == 2 &&
        f->wallet->map_wallet[0].confirms == 2 && f->wallet->map_wallet[1].confirms == 1 &&
        wallet_is_outpoint_spent(f->wallet, &f->funding, 0) && f->wallet->sapling_keys.num_keys == 0;
}

static bool ndc_transparent_filter_sparse(struct wallet *w)
{
    struct uint256 hash = {{0}}, other = {{0}};
    hash.data[0] = 91; other.data[0] = 92;
    w->map_wallet[MAX_WALLET_TX - 1].used = true;
    w->map_wallet[MAX_WALLET_TX - 1].tx.hash = hash;
    w->map_wallet[MAX_WALLET_TX - 2].used = true;
    w->map_wallet[MAX_WALLET_TX - 2].tx.hash = hash;
    struct transparent_replay_filter *f = transparent_replay_filter_new(w);
    bool ok = f && w->num_wallet_tx == 0 && (transparent_replay_filter_test_maybe(f, &hash) == TRANSPARENT_FILTER_POSSIBLE);
    transparent_replay_filter_test_saturate(f);
    ok = ok && (transparent_replay_filter_test_maybe(f, &other) == TRANSPARENT_FILTER_POSSIBLE);
    transparent_replay_filter_free(f);
    w->map_wallet[MAX_WALLET_TX - 1].used = false;
    w->map_wallet[MAX_WALLET_TX - 2].used = false;
    return ok;
}

static bool ndc_transparent_filter_negative(struct ndc_transparent_fixture *f,
                                            const uint8_t identity[32])
{
    struct transparent_replay_filter *filter = transparent_replay_filter_new(f->wallet);
    if (!filter) return false;
    bool negative = (transparent_replay_filter_test_maybe(filter, &f->funding) == TRANSPARENT_FILTER_ABSENT) &&
        (transparent_replay_filter_test_maybe(filter, &f->spend) == TRANSPARENT_FILTER_ABSENT);
    struct transparent_replay_result indexed = node_db_catchup_wallet_transparent_indexed(
        &f->state, f->wallet, f->dir, 2, 2, 2, f->hashes[2].data, identity, filter);
    bool unchanged = f->wallet->num_wallet_tx == 0 && f->wallet->num_spent == 0;
    struct transparent_replay_result legacy = node_db_catchup_wallet_transparent(
        &f->state, f->wallet, f->dir, 2, 2, 2, f->hashes[2].data, identity);
    bool ok = negative && unchanged && indexed.status == TRANSPARENT_REPLAY_COMPLETE &&
        indexed.status == legacy.status && indexed.last_complete == legacy.last_complete &&
        f->wallet->num_wallet_tx == 0 && f->wallet->num_spent == 0;
    transparent_replay_filter_free(filter);
    return ok;
}

static bool ndc_transparent_filter_batches(struct ndc_transparent_fixture *f,
                                           const uint8_t identity[32])
{
    zcl_alloc_fault_fail_nth("transparent replay filter", 1);
    struct transparent_replay_filter *oom = transparent_replay_filter_new(f->wallet);
    zcl_alloc_fault_clear();
    if (oom) { transparent_replay_filter_free(oom); return false; }
    struct transparent_replay_filter *filter = transparent_replay_filter_new(f->wallet);
    if (!filter) return false;
    struct transparent_replay_result first = node_db_catchup_wallet_transparent_indexed(
        &f->state, f->wallet, f->dir, 1, 1, 2, f->hashes[2].data, identity, filter);
    struct transparent_replay_result second = node_db_catchup_wallet_transparent_indexed(
        &f->state, f->wallet, f->dir, 2, 2, 2, f->hashes[2].data, identity, filter);
    transparent_replay_filter_test_saturate(filter);
    struct transparent_replay_result collision = node_db_catchup_wallet_transparent_indexed(
        &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity, filter);
    struct transparent_replay_result retry = node_db_catchup_wallet_transparent_indexed(
        &f->state, f->wallet, f->dir, 1, 2, 2, f->hashes[2].data, identity, NULL);
    bool ok = first.status == TRANSPARENT_REPLAY_COMPLETE && second.status == TRANSPARENT_REPLAY_COMPLETE &&
        collision.status == TRANSPARENT_REPLAY_COMPLETE && retry.status == TRANSPARENT_REPLAY_COMPLETE && f->wallet->num_wallet_tx == 2 &&
        wallet_is_outpoint_spent(f->wallet, &f->funding, 0);
    transparent_replay_filter_free(filter);
    return ok;
}

static int ndc_check_transparent_replay(void)
{
    int failures = 0;
    struct ndc_transparent_fixture f = {0};
    test_make_tmpdir(f.dir, sizeof(f.dir), "node_db_catchup", "transparent_range");
    char blocks[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f.dir);
    bool ok = mkdir(blocks, 0755) == 0;
    f.wallet = zcl_calloc(1, sizeof(*f.wallet), "transparent fixture wallet");
    if (f.wallet) wallet_init(f.wallet);
    main_state_init(&f.state); f.watch.id.data[0] = 9;
    ok = ok && f.wallet && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 1) &&
        keystore_add_watch_only_id(&f.wallet->keystore, &f.watch) &&
        ndc_transparent_write(&f, 1) && ndc_transparent_write(&f, 2);
    uint8_t identity[32];
    if (ok) ok = ndc_transparent_filter_sparse(f.wallet) && wallet_scan_identity(f.wallet, identity) && ndc_transparent_filter_negative(&f, identity) && ndc_transparent_filter_batches(&f, identity) && ndc_transparent_refusals(&f, identity);
    if (ok) ok = ndc_transparent_extension(&f, identity);
    if (ok) ok = ndc_transparent_identity_cases(&f);
    NDC_CHECK("transparent range rejects wrong chain, keys, missing and tampered blocks, then retries", ok);
    if (f.wallet) { wallet_free(f.wallet); free(f.wallet); }
    main_state_free(&f.state); (void)test_rm_rf_recursive(f.dir);
    return failures;
}
#endif

static bool ndc_reemit_seed(struct node_db *db)
{
    const char *sql = "BEGIN IMMEDIATE;"
        "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,height,is_coinbase,spent_txid,spent_vin) "
        "VALUES(CAST(zeroblob(31)||x'01' AS BLOB),0,42,zeroblob(20),x'51',10,0,NULL,NULL),"
        "(CAST(zeroblob(31)||x'02' AS BLOB),1,17,zeroblob(20),x'51',11,1,zeroblob(32),0); COMMIT";
    return sqlite3_exec(db->db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int ndc_reemit_deny_read(void *arg, int op, const char *table,
    const char *column, const char *db, const char *trigger)
{
    (void)arg; (void)column; (void)db; (void)trigger;
    return op == SQLITE_READ && table && strcmp(table, "wallet_utxos") == 0 ? SQLITE_DENY : SQLITE_OK;
}

static bool ndc_reemit_faults(struct node_db *db, event_log_t *log)
{
    if (sqlite3_set_authorizer(db->db, ndc_reemit_deny_read, NULL) != SQLITE_OK) return false;
    bool denied = !db_wallet_utxo_reemit_all(db);
    sqlite3_set_authorizer(db->db, NULL, NULL);
    int fd = event_log_test_fd(log);
    event_log_test_set_force_per_append(1);
    event_log_test_set_fd(log, -1);
    bool append_failed = !db_wallet_utxo_reemit_all(db);
    event_log_test_set_fd(log, fd);
    event_log_test_set_force_per_append(-1);
    return denied && append_failed && db_wallet_utxo_reemit_all(db);
}


static bool ndc_reemit_checks(struct node_db *db, event_log_t *log, const char *view_path)
{
    wallet_projection_t *view = wallet_projection_open(view_path, log);
    if (!view) return false;
    wallet_projection_catch_up(view);
    bool ok = wallet_projection_utxo_count(view) == 0 && ndc_reemit_faults(db, log) && db_wallet_utxo_reemit_all(db) &&
        db_wallet_utxo_reemit_all(db);
    wallet_projection_catch_up(view);
    ok = ok && wallet_projection_utxo_count(view) == 2 && wallet_projection_total_value_zat(view) == 59;
    ok = ok && sqlite3_exec(db->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        !db_wallet_utxo_reemit_all(db) && sqlite3_exec(db->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    ok = ok && sqlite3_exec(db->db, "UPDATE wallet_utxos SET address_hash=1 WHERE vout=1", NULL, NULL, NULL) == SQLITE_OK &&
        !db_wallet_utxo_reemit_all(db) &&
        sqlite3_exec(db->db, "UPDATE wallet_utxos SET address_hash=zeroblob(20) WHERE vout=1", NULL, NULL, NULL) == SQLITE_OK &&
        db_wallet_utxo_reemit_all(db);
    wallet_projection_catch_up(view);
    ok = ok && wallet_projection_utxo_count(view) == 2;
    wallet_projection_close(view);
    return ok;
}

static int ndc_check_utxo_reemit_restart(void)
{
    char dir[256], dbpath[320], eventpath[320], viewpath[320];
    test_make_tmpdir(dir, sizeof(dir), "wallet_utxo_reemit", "restart");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(eventpath, sizeof(eventpath), "%s/event.dat", dir);
    snprintf(viewpath, sizeof(viewpath), "%s/view.db", dir);
    struct node_db db = {0};
    event_log_t *old = wallet_projection_event_log(), *log = NULL;
    wallet_projection_set_event_log(NULL);
    bool ok = node_db_open(&db, dbpath);
    log = event_log_open(eventpath);
    wallet_projection_set_event_log(log);
    ok = ok && log && db_wallet_utxo_reemit_all(&db);
    wallet_projection_set_event_log(NULL);
    if (log) event_log_close(log);
    log = NULL;
    ok = ok && ndc_reemit_seed(&db);
    if (db.open) node_db_close(&db);
    ok = ok && node_db_open(&db, dbpath) && !db_wallet_utxo_reemit_all(&db);
    log = event_log_open(eventpath);
    wallet_projection_set_event_log(log);
    ok = ok && log && ndc_reemit_checks(&db, log, viewpath);
    wallet_projection_set_event_log(old);
    if (log) event_log_close(log);
    if (db.open) node_db_close(&db);
    test_rm_rf(dir);
    printf("wallet UTXO historical re-emission survives restart: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}


struct ndc_pace_run {
    struct node_db *db; const struct active_chain *chain; struct wallet *wallet; const char *dir; int result;
    bool background, deferred;
};
struct ndc_pace_fixture {
    char dir[256], refdir[256];
    struct node_db db, ref;
    struct wallet *wallet, *ref_wallet;
    bool opened;
};
static void *ndc_pace_walk(void *arg)
{
    struct ndc_pace_run *run = arg;
    run->result = run->background
        ? node_db_catchup_service_run_origin(run->db, true, &run->deferred, run->chain, run->wallet, run->dir)
        : node_db_catchup_service_run(run->db, run->chain, run->wallet, run->dir);
    return NULL;
}
static struct wallet *ndc_pace_wallet(void)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "pace wallet");
    if (w) { wallet_init(w); w->keystore.keys[0].used = true; w->keystore.num_keys = 1; }
    return w;
}
static bool ndc_pace_open(struct ndc_fix_ctx *fx, struct ndc_pace_fixture *p)
{
    char path[512], refpath[512];
    test_make_tmpdir(p->dir, sizeof(p->dir), "node_db_catchup", "pace");
    test_make_tmpdir(p->refdir, sizeof(p->refdir), "node_db_catchup", "pace_ref");
    snprintf(path, sizeof(path), "%s/node.db", p->dir);
    snprintf(refpath, sizeof(refpath), "%s/node.db", p->refdir);
    p->wallet = ndc_pace_wallet(); p->ref_wallet = ndc_pace_wallet();
    p->opened = p->wallet && p->ref_wallet && fx->built &&
        node_db_open(&p->db, path) && node_db_open(&p->ref, refpath);
    node_pace_set_datadir(NULL); node_db_catchup_lock_guard_test_reset();
    return p->opened;
}
static int ndc_pace_entry(struct ndc_fix_ctx *fx, struct ndc_pace_fixture *p)
{
    int failures = 0;
    node_pace_set(NODE_PACE_PAUSE);
    int before = p->opened ? node_db_sync_get_tip_height(&p->db) : -1;
    int paused = p->opened ? node_db_catchup_service_run(&p->db, &fx->ac, p->wallet, fx->dirF) : -1;
    NDC_CHECK("paused entry leaves projection unchanged", p->opened && paused == 0 &&
              node_db_sync_get_tip_height(&p->db) == before && !node_db_catchup_service_active());
    return failures;
}
static int ndc_pace_midwalk(struct ndc_fix_ctx *fx, struct ndc_pace_fixture *p, int *prefix)
{
    int failures = 0;
    node_pace_set(NODE_PACE_NORMAL);
    node_db_catchup_lock_guard_test_set_batch_size(2);
    node_db_catchup_lock_guard_test_set_height_delay_ms(150);
    struct ndc_pace_run run = {.db = &p->db, .chain = &fx->ac, .wallet = p->wallet, .dir = fx->dirF, .result = -1};
    pthread_t thread; bool started = p->opened && pthread_create(&thread, NULL, ndc_pace_walk, &run) == 0;
    for (int i = 0; started && i < 1000 && node_db_catchup_lock_guard_test_batch_commits() < 1; i++) platform_sleep_ms(2);
    bool reached = node_db_catchup_lock_guard_test_batch_commits() >= 1;
    node_pace_set(NODE_PACE_PAUSE);
    if (started) pthread_join(thread, NULL);
    *prefix = p->opened ? node_db_sync_get_tip_height(&p->db) : -1;
    NDC_CHECK("mid-pass pause commits only walked prefix", started && reached && run.result > 0 &&
              run.result < NDC_FIX_N && *prefix == run.result &&
              !node_db_catchup_service_active() && node_db_catchup_lock_guard_test_abort_streak() == 0);
    return failures;
}
static int ndc_pace_resume(struct ndc_fix_ctx *fx, struct ndc_pace_fixture *p, int prefix)
{
    int failures = 0;
    node_pace_set(NODE_PACE_NORMAL); node_db_catchup_lock_guard_test_set_height_delay_ms(0);
    int resumed = p->opened ? node_db_catchup_service_run(&p->db, &fx->ac, p->wallet, fx->dirF) : -1;
    int reference = p->opened ? node_db_catchup_service_run(&p->ref, &fx->ac, p->ref_wallet, fx->dirF) : -1;
    uint8_t a[32], b[32];
    bool receipts = p->opened && db_view_integrity_get(&p->db, NDC_FIX_N, a) &&
        db_view_integrity_get(&p->ref, NDC_FIX_N, b);
    NDC_CHECK("resume matches uninterrupted projection and receipt", p->opened &&
              resumed == NDC_FIX_N - prefix && reference == NDC_FIX_N &&
              ndc_restart_projection_equal(p->db.db, p->ref.db) && receipts && !memcmp(a, b, 32));
    return failures;
}
static void ndc_pace_close(struct ndc_pace_fixture *p)
{
    node_db_catchup_lock_guard_test_reset(); node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    if (p->db.open) node_db_close(&p->db);
    if (p->ref.open) node_db_close(&p->ref);
    if (p->wallet) { wallet_free(p->wallet); free(p->wallet); }
    if (p->ref_wallet) { wallet_free(p->ref_wallet); free(p->ref_wallet); }
    test_cleanup_tmpdir(p->dir); test_cleanup_tmpdir(p->refdir);
}
static int ndc_check_pace_pause(struct ndc_fix_ctx *fx)
{
    int failures = 0, prefix = -1; struct ndc_pace_fixture p = {0};
    (void)ndc_pace_open(fx, &p);
    failures += ndc_pace_entry(fx, &p);
    failures += ndc_pace_midwalk(fx, &p, &prefix);
    failures += ndc_pace_resume(fx, &p, prefix);
    ndc_pace_close(&p); return failures;
}
static void ndc_pace_set_missing(struct ndc_fix_ctx *fx, uint32_t *statuses, bool restore)
{
    for (int i = 1; i <= NDC_FIX_N; i++) {
        if (restore) fx->slots[i].nStatus = statuses[i];
        else { statuses[i] = fx->slots[i].nStatus; fx->slots[i].nStatus &= ~BLOCK_HAVE_DATA; }
    }
}
static int ndc_check_pace_sparse(struct ndc_fix_ctx *fx)
{
    int failures = 0; char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "pace_sparse");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db db = {0}; bool opened = fx->built && node_db_open(&db, path);
    int before = opened ? node_db_sync_get_tip_height(&db) : -1;
    uint32_t statuses[NDC_FIX_N + 1]; ndc_pace_set_missing(fx, statuses, false);
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_NORMAL);
    node_db_catchup_lock_guard_test_reset(); node_db_catchup_lock_guard_test_set_height_delay_ms(200);
    struct ndc_pace_run run = {.db = &db, .chain = &fx->ac, .dir = fx->dirF, .result = -1};
    pthread_t thread; bool started = opened && pthread_create(&thread, NULL, ndc_pace_walk, &run) == 0;
    for (int i = 0; started && i < 1000 && !node_db_catchup_service_active(); i++) platform_sleep_ms(2);
    bool active = node_db_catchup_service_active(); node_pace_set(NODE_PACE_PAUSE);
    if (started) pthread_join(thread, NULL);
    NDC_CHECK("paused sparse walk leaves cursor and outcome unchanged", started && active && run.result == 0 &&
              node_db_sync_get_tip_height(&db) == before && !node_db_catchup_service_active() &&
              node_db_catchup_lock_guard_test_abort_streak() == 0);
    ndc_pace_set_missing(fx, statuses, true); node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    node_db_catchup_lock_guard_test_reset(); if (db.open) node_db_close(&db);
    test_cleanup_tmpdir(dir); return failures;
}

#ifndef _WIN32
/* Disk-backed Sapling outputs exercise the same pause boundary as the walk. */
struct ndc_pause_sapling {
    char dir[256];
    struct active_chain chain;
    struct block_index slots[NDC_FIX_N + 1];
    struct uint256 hashes[NDC_FIX_N + 1], cm, roots[NDC_FIX_N + 1];
};
static bool ndc_pause_sapling_build(struct ndc_pause_sapling *f)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "node_db_catchup", "pace_sapling");
    char blocks[512]; snprintf(blocks, sizeof(blocks), "%s/blocks", f->dir);
    if (mkdir(blocks, 0755) != 0) return false;
    active_chain_init(&f->chain);
    struct incremental_merkle_tree tree; sapling_tree_init(&tree);
    f->hashes[0].data[0] = 1;
    f->cm.data[0] = 0x31; f->cm.data[1] = 0x77;
    const unsigned char magic[4] = {0x24, 0xe9, 0x27, 0x64};
    for (int h = 1; h <= NDC_FIX_N; h++) {
        struct block b; block_init(&b);
        b.header.nVersion = 4; b.header.nTime = 1700000123u + (unsigned)h;
        b.header.nBits = 0x2000ffffu; b.header.hashPrevBlock = f->hashes[h - 1];
        b.vtx = calloc(1, sizeof(*b.vtx)); // raw-alloc-ok:test-fixture
        if (!b.vtx) return false;
        b.num_vtx = 1; transaction_init(b.vtx);
        bool ok = transaction_alloc(b.vtx, 1, 1);
        b.vtx->version = SAPLING_TX_VERSION; b.vtx->overwintered = true;
        b.vtx->version_group_id = SAPLING_VERSION_GROUP_ID;
        b.vtx->v_shielded_output = calloc(1, sizeof(*b.vtx->v_shielded_output)); // raw-alloc-ok:test-fixture
        ok = ok && b.vtx->v_shielded_output;
        if (ok) {
            b.vtx->num_shielded_output = 1;
            b.vtx->v_shielded_output[0].cm = f->cm;
            b.vtx->v_shielded_output[0].cm.data[0] += (uint8_t)(h - 1);
            incremental_tree_append(&tree, &b.vtx->v_shielded_output[0].cm);
            incremental_tree_root(&tree, &f->roots[h]);
            b.header.hashFinalSaplingRoot = f->roots[h];
            transaction_compute_hash(b.vtx); b.header.hashMerkleRoot = b.vtx->hash;
        }
        struct disk_block_pos pos; disk_block_pos_init(&pos);
        ok = ok && write_block_to_disk(&b, &pos, f->dir, magic);
        if (ok) {
            block_get_hash(&b, &f->hashes[h]);
            struct block_index *slot = &f->slots[h]; block_index_init(slot);
            slot->nHeight = h; slot->nStatus = BLOCK_HAVE_DATA;
            slot->nFile = pos.nFile; slot->nDataPos = pos.nPos;
            slot->hashBlock = f->hashes[h]; slot->phashBlock = &slot->hashBlock;
            slot->hashFinalSaplingRoot = f->roots[h];
            slot->pprev = h > 1 ? &f->slots[h - 1] : NULL;
            ok = active_chain_install_tip_slot(&f->chain, slot);
        }
        block_free(&b);
        if (!ok) return false;
    }
    return true;
}

static bool ndc_pause_row_match(sqlite3_stmt *x, sqlite3_stmt *y, int next)
{
    return next <= NDC_FIX_N && sqlite3_column_int(x, 0) == next &&
           ndc_restart_row_equal(x, y);
}

static bool ndc_pause_rows_equal(sqlite3 *a, sqlite3 *b, bool hole)
{
    const char *sql = "SELECT height,hash,prev_hash,status FROM blocks ORDER BY height,hash";
    sqlite3_stmt *x = NULL, *y = NULL; bool ok = false; int next = 1;
    if (sqlite3_prepare_v2(a, sql, -1, &x, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(b, sql, -1, &y, NULL) != SQLITE_OK) goto done;
    for (;;) {
        int rx = sqlite3_step(x), ry = sqlite3_step(y);
        if (rx == SQLITE_DONE && ry == SQLITE_DONE) { ok = next == NDC_FIX_N + 1; break; }
        if (hole && next == 4) next++;
        if (rx != SQLITE_ROW || ry != SQLITE_ROW || !ndc_pause_row_match(x, y, next)) break;
        next++;
    }
done:
    if (x && sqlite3_finalize(x) != SQLITE_OK) ok = false;
    if (y && sqlite3_finalize(y) != SQLITE_OK) ok = false;
    return ok;
}


static bool ndc_pause_receipts_equal(struct node_db *a, struct node_db *b, bool hole)
{
    for (int h = 1; h <= NDC_FIX_N; h++) {
        uint8_t x[32], y[32];
        bool ax = db_view_integrity_get(a, h, x), by = db_view_integrity_get(b, h, y);
        if (ax != !(hole && h == 4) || by != ax || (ax && memcmp(x, y, 32))) return false;
    }
    return true;
}

static bool ndc_pause_sapling_equal(struct node_db *a, struct node_db *b,
                                    const struct ndc_pause_sapling *f, bool hole)
{
    uint8_t *aw = NULL, *bw = NULL; size_t an = 0, bn = 0;
    int ah = -1, bh = -1; struct uint256 ar, br;
    bool ok = ndc_tip_witness(a, 0x71, &ah, &ar, &aw, &an) &&
        ndc_tip_witness(b, 0x71, &bh, &br, &bw, &bn);
    int want = hole ? 3 : NDC_FIX_N;
    ok = ok && ah == want && bh == want && an > 0 && an == bn &&
        !memcmp(aw, bw, an) && uint256_eq(&ar, &br) &&
        uint256_eq(&ar, &f->roots[want]) &&
        node_db_sync_get_tip_height(a) == NDC_FIX_N &&
        node_db_sync_get_tip_height(b) == NDC_FIX_N &&
        ndc_pause_rows_equal(a->db, b->db, hole);
    ok = ok && ndc_pause_receipts_equal(a, b, hole);
    free(aw); free(bw); return ok;
}

static bool ndc_sapling_partial_result(const struct ndc_pace_run *run, int prefix, bool background)
{
    return (!background || run->deferred) && run->result > 0 && prefix > 0 &&
           prefix < NDC_FIX_N && !node_db_catchup_service_active();
}

static bool ndc_pause_sapling_walk(struct ndc_pace_fixture *p,
                                    struct ndc_pause_sapling *f, bool seeded, bool background)
{
    node_pace_set(NODE_PACE_NORMAL); node_db_catchup_lock_guard_test_set_batch_size(2);
    node_db_catchup_lock_guard_test_set_height_delay_ms(150);
    if (background) node_db_catchup_lock_guard_test_hold_walk(true);
    struct ndc_pace_run run = {.db = &p->db, .chain = &f->chain, .dir = f->dir, .result = -1, .background = background};
    pthread_t thread; bool started = seeded && pthread_create(&thread, NULL, ndc_pace_walk, &run) == 0;
    for (int i = 0; started && i < 1000 && node_db_catchup_lock_guard_test_batch_commits() < 1; i++) platform_sleep_ms(2);
    bool reached = node_db_catchup_lock_guard_test_batch_commits() >= 1;
    node_pace_set(background ? NODE_PACE_GENTLE : NODE_PACE_PAUSE);
    if (background) node_db_catchup_lock_guard_test_hold_walk(false);
    if (started) pthread_join(thread, NULL);
    int prefix = seeded ? node_db_sync_get_tip_height(&p->db) : -1;
    return started && reached && ndc_sapling_partial_result(&run, prefix, background);
}

static int ndc_check_pace_sapling(bool hole, bool background)
{
    int failures = 0; struct ndc_pause_sapling f = {0};
    struct ndc_pace_fixture p = {0}; struct ndc_fix_ctx fake = {0};
    bool built = ndc_pause_sapling_build(&f); fake.built = built;
    bool opened = ndc_pace_open(&fake, &p);
    bool seeded = opened && ndc_tip_note(&p.db, 0x71, &f.cm, 1) &&
                  ndc_tip_note(&p.ref, 0x71, &f.cm, 1);
    if (hole) f.slots[4].nStatus &= ~BLOCK_HAVE_DATA;
    bool partial = ndc_pause_sapling_walk(&p, &f, seeded, background);
    node_pace_set(NODE_PACE_NORMAL); node_db_catchup_lock_guard_test_set_height_delay_ms(0);
    bool deferred = false;
    int resumed = partial ? node_db_catchup_service_run_origin(&p.db, background, &deferred, &f.chain, NULL, f.dir) : -1;
    int reference = seeded ? node_db_catchup_service_run(&p.ref, &f.chain, NULL, f.dir) : -1;
    NDC_CHECK("Sapling pause stops at a committed partial prefix", partial);
    NDC_CHECK("Sapling resume matches uninterrupted rows, receipts and witness",
              partial && !deferred && resumed > 0 && reference > 0 && ndc_pause_sapling_equal(&p.db, &p.ref, &f, hole));
    ndc_pace_close(&p); active_chain_free(&f.chain); (void)test_rm_rf_recursive(f.dir);
    return failures;
}

static int ndc_check_pace_sapling_bounded(bool hole, bool background)
{
    int failures = 0, status = 0;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        int result = ndc_check_pace_sapling(hole, background);
        fflush(NULL);
        _exit(result == 0 ? 0 : 1);
    }
    bool finished = false;
    int64_t deadline = platform_time_monotonic_ms() + 30000;
    while (child > 0 && platform_time_monotonic_ms() < deadline) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) { finished = true; break; }
        if (got < 0 && errno != EINTR) break;
        platform_sleep_ms(10);
    }
    if (child > 0 && !finished) { kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    NDC_CHECK("Sapling pause/resume completes within 30 seconds",
              child > 0 && finished && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return failures;
}
#endif


#ifndef _WIN32
/* The rollback authorizer changes pace at the retry boundary without adding a
 * production hook. The recursive pass must keep its background origin. */
static int ndc_background_rollback(void *arg, int action, const char *one,
                                   const char *two, const char *db, const char *source)
{
    (void)two; (void)db; (void)source;
    bool *changed = arg;
    if (action == SQLITE_TRANSACTION && one && strcmp(one, "ROLLBACK") == 0) {
        *changed = true;
        node_pace_set(NODE_PACE_GENTLE);
    }
    return SQLITE_OK;
}

static int ndc_check_background_retry(struct ndc_fix_ctx *fx)
{
    int failures = 0; struct node_db db = {0}; char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "background_retry");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool opened = fx->built && node_db_open(&db, path), changed = false, deferred = false;
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_NORMAL);
    node_db_catchup_lock_guard_test_reset();
    node_db_catchup_lock_guard_test_force_snapshot_failures(1);
    bool armed = opened && sqlite3_set_authorizer(db.db, ndc_background_rollback, &changed) == SQLITE_OK;
    int result = armed ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                                            &fx->ac, NULL, fx->dirF) : -1;
    if (opened) sqlite3_set_authorizer(db.db, NULL, NULL);
    NDC_CHECK("background origin survives BUSY_SNAPSHOT restart and defers",
              armed && changed && deferred && result == 0 &&
              node_db_catchup_lock_guard_test_snapshot_restarts() == 1 &&
              node_db_sync_get_tip_height(&db) < 1 && !node_db_catchup_service_active());
    node_pace_set(NODE_PACE_NORMAL); deferred = true;
    result = opened ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                                         &fx->ac, NULL, fx->dirF) : -1;
    NDC_CHECK("background retry resumes complete after pace normalizes",
              result == NDC_FIX_N && !deferred && node_db_sync_get_tip_height(&db) == NDC_FIX_N);
    node_db_catchup_lock_guard_test_reset(); node_pace_set(NODE_PACE_NORMAL);
    node_pace_test_end_resume_grace(); if (opened) node_db_close(&db);
    test_cleanup_tmpdir(dir); return failures;
}

static int ndc_background_deny_index(void *arg, int action, const char *one,
                                     const char *two, const char *db, const char *source)
{
    (void)one; (void)two; (void)db; (void)source;
    if (action != SQLITE_CREATE_INDEX) return SQLITE_OK;
    *(bool *)arg = true;
    return SQLITE_DENY;
}

static bool ndc_background_restore_failure(struct node_db *db, struct ndc_fix_ctx *fx)
{
    bool denied = false, deferred = true;
    bool armed = sqlite3_set_authorizer(db->db, ndc_background_deny_index, &denied) == SQLITE_OK;
    int result = armed ? node_db_catchup_service_run_origin(db, true, &deferred,
                                      &fx->ac, NULL, fx->dirF) : 0;
    if (armed) sqlite3_set_authorizer(db->db, NULL, NULL);
    return armed && denied && result == -1 && !deferred;
}

static bool ndc_background_foreign_yield(struct node_db *db, struct ndc_fix_ctx *fx)
{
    bool deferred = false;
    int result = node_db_catchup_service_run_origin(db, true, &deferred, &fx->ac, NULL, fx->dirF);
    return result == 0 && !deferred && !sqlite3_get_autocommit(db->db) &&
           node_db_synchronous_level(db) == 0;
}

static int ndc_check_background_owed(struct ndc_fix_ctx *fx)
{
    int failures = 0; struct node_db db = {0}; char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "background_owed");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool opened = fx->built && node_db_open(&db, path), deferred = false;
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_NORMAL);
    node_db_catchup_lock_guard_test_reset(); node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    node_db_catchup_test_set_after_turbo_hook(ndc_race_foreign_begin);
    bool held = opened && ndc_background_foreign_yield(&db, fx);
    int result = 0;
    NDC_CHECK("foreign writer preserves owed restore and is not thermal deferral", held);
    node_pace_set(NODE_PACE_GENTLE); deferred = true;
    result = held ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                                       &fx->ac, NULL, fx->dirF) : -1;
    NDC_CHECK("foreign transaction remains open while restore is owed",
              held && result == 0 && !deferred && !sqlite3_get_autocommit(db.db));
    bool released = held && sqlite3_exec(db.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    node_pace_set(NODE_PACE_NORMAL);
    NDC_CHECK("normal owed restore error fails and does not report deferral",
              released && ndc_background_restore_failure(&db, fx));
    result = released ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                                           &fx->ac, NULL, fx->dirF) : -1;
    NDC_CHECK("normal retry restores turbo state before walking",
              released && result == NDC_FIX_N && !deferred &&
              node_db_synchronous_level(&db) == 1 &&
              ndc_secondary_index_count(&db) == NDC_SECONDARY_INDEXES);
    node_db_catchup_test_set_after_turbo_hook(NULL); node_db_catchup_lock_guard_test_reset();
    node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    if (opened) node_db_close(&db);
    test_cleanup_tmpdir(dir); return failures;
}


static int ndc_check_background_close_failure(struct ndc_fix_ctx *fx)
{
    int failures = 0; struct node_db db = {0}; char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "background_close");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool opened = fx->built && node_db_open(&db, path), denied = false, deferred = false;
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_NORMAL);
    node_db_catchup_lock_guard_test_reset(); node_db_catchup_lock_guard_test_set_bulk_threshold(2);
    bool armed = opened && sqlite3_set_authorizer(db.db, ndc_background_deny_index, &denied) == SQLITE_OK;
    int result = armed ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                      &fx->ac, NULL, fx->dirF) : 0;
    if (armed) sqlite3_set_authorizer(db.db, NULL, NULL);
    NDC_CHECK("failed turbo scope close is an error and not deferred",
              armed && denied && result == -1 && !deferred);
    node_pace_set(NODE_PACE_GENTLE); deferred = false;
    result = opened ? node_db_catchup_service_run_origin(&db, true, &deferred,
                                      &fx->ac, NULL, fx->dirF) : -1;
    NDC_CHECK("gentle retry restores failed scope before deferral",
              result == 0 && deferred && node_db_synchronous_level(&db) == 1 &&
              ndc_secondary_index_count(&db) == NDC_SECONDARY_INDEXES);
    node_db_catchup_lock_guard_test_reset(); node_pace_set(NODE_PACE_NORMAL);
    node_pace_test_end_resume_grace(); if (opened) node_db_close(&db);
    test_cleanup_tmpdir(dir); return failures;
}


static bool ndc_oldkey_genesis(struct ndc_replay_fixture *f)
{
    struct block b; block_init(&b); b.header.nVersion = 4;
    b.vtx = zcl_calloc(1, sizeof(*b.vtx), "old key genesis tx");
    if (!b.vtx) return false;
    b.num_vtx = 1; transaction_init(b.vtx);
    bool ok = transaction_alloc(b.vtx, 1, 1);
    if (ok) { transaction_compute_hash(b.vtx); b.header.hashMerkleRoot = b.vtx->hash; }
    struct disk_block_pos pos; disk_block_pos_init(&pos);
    const unsigned char magic[4] = {0x24, 0xe9, 0x27, 0x64};
    ok = ok && write_block_to_disk(&b, &pos, f->dir, magic);
    if (ok) {
        block_get_hash(&b, &f->hashes[0]);
        struct block_index *slot = &f->slots[0]; block_index_init(slot);
        slot->nHeight = 0; slot->nStatus = BLOCK_HAVE_DATA;
        slot->nFile = pos.nFile; slot->nDataPos = pos.nPos;
        slot->hashBlock = f->hashes[0]; slot->phashBlock = &slot->hashBlock;
        ok = active_chain_install_tip_slot(&f->state.chain_active, slot);
    }
    block_free(&b); return ok;
}

static bool ndc_oldkey_found(const struct wallet *w, const struct uint256 *txid)
{
    for (size_t i = 0; i < w->num_sapling_notes; i++)
        if (w->sapling_notes[i].used && uint256_eq(&w->sapling_notes[i].txid, txid)) return true;
    return false;
}

static bool ndc_oldkey_rpc_mode(struct ndc_replay_fixture *f, struct wallet *w,
                                struct wallet_sqlite *ws, bool no_chain, bool *scan_save_error)
{
    char key[512] = {0}; const struct chain_params *cp = chain_params_get();
    bool encoded = sapling_encode_extended_spending_key(&f->wallet->sapling_keys.keys[0].xsk,
                    cp->bech32HRPs[BECH32_SAPLING_EXTENDED_SPEND_KEY], key, sizeof(key));
    struct json_value params, value, result;
    json_init(&params); json_set_array(&params); json_init(&value); json_init(&result);
    json_set_str(&value, key); json_push_back(&params, &value);
    wallet_rpc_context_set_base(w, no_chain ? NULL : &f->state, f->dir, ws, NULL, NULL);
    bool imported = encoded && rpc_z_importkey(&params, false, &result);
    const char *message = json_get_str(&result);
    if (scan_save_error) *scan_save_error = message && strstr(message, "Key imported, but scan state could not be saved") != NULL;
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    json_free(&params); json_free(&value); json_free(&result);
    memory_cleanse(key, sizeof(key)); return imported;
}
static bool ndc_oldkey_rpc(struct ndc_replay_fixture *f, struct wallet *w, struct wallet_sqlite *ws)
{
    return ndc_oldkey_rpc_mode(f, w, ws, false, NULL);
}

struct ndc_oldkey_case {
    struct ndc_replay_fixture f; struct wallet *imported;
    struct node_db db; struct wallet_sqlite ws;
};
static bool ndc_oldkey_setup(struct ndc_oldkey_case *c)
{
    struct ndc_replay_fixture *f = &c->f;
    c->imported = zcl_calloc(1, sizeof(*c->imported), "old key imported wallet");
    test_make_tmpdir(f->dir, sizeof(f->dir), "node_db_catchup", "oldkey");
    char blocks[320], dbpath[320]; snprintf(blocks, sizeof(blocks), "%s/blocks", f->dir);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", f->dir);
    bool up = c->imported && mkdir(blocks, 0700) == 0 && node_db_open(&c->db, dbpath) &&
              wallet_sqlite_open(&c->ws, c->db.db);
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "old key source wallet");
    if (f->wallet) wallet_init(f->wallet);
    if (c->imported) wallet_init(c->imported);
    main_state_init(&f->state); sapling_tree_init(&f->tree);
    uint8_t seed[32] = {1}, d[11], pk[32];
    return up && f->wallet && sapling_keystore_set_seed(&f->wallet->sapling_keys, seed) &&
         sapling_keystore_new_address(&f->wallet->sapling_keys, d, pk) && ndc_oldkey_genesis(f) &&
         ndc_replay_write_fixture_block(f, 1, d, pk) && ndc_replay_write_fixture_block(f, 2, d, pk) &&
         wallet_readiness_initialize(c->imported, WALLET_READINESS_READY, false, 0);
}
static bool ndc_oldkey_coverage(struct ndc_oldkey_case *c, const struct wallet_rescan_report *r)
{
    return r->coverage_ok && r->blocks_scanned == 3 && r->blocks_in_range == 3 &&
           wallet_scanned_through_height(c->imported) == 2;
}
static int ndc_oldkey_verify(struct ndc_oldkey_case *c, bool up)
{
    int failures = 0; struct ndc_replay_fixture *f = &c->f;
    NDC_CHECK("historical encrypted note absent before old key import",
              up && c->imported->sapling_keys.num_keys == 0 && !ndc_oldkey_found(c->imported, &f->note_txid));
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_GENTLE);
    bool deferred = false; int before = up ? node_db_sync_get_tip_height(&c->db) : -1;
    int result = up ? node_db_catchup_service_run_origin(&c->db, true, &deferred,
                              &f->state.chain_active, c->imported, f->dir) : -1;
    NDC_CHECK("background history is deferred before import",
              up && result == 0 && deferred && before < 2 && node_db_sync_get_tip_height(&c->db) == before);
    bool imported_ok = up && ndc_oldkey_rpc(f, c->imported, &c->ws);
    NDC_CHECK("default old-key import rescans and discovers the historical encrypted note",
              imported_ok && c->imported->sapling_keys.num_keys == 1 && ndc_oldkey_found(c->imported, &f->note_txid));
    struct wallet_rescan_report report = {0};
    if (imported_ok) (void)wallet_rescan_report(c->imported, &f->state.chain_active, 0, -1, f->dir, &report);
    NDC_CHECK("historical rescan reads the complete range and reaches the tip",
              imported_ok && ndc_oldkey_coverage(c, &report));
    return failures;
}
static int ndc_check_oldkey_import(struct ndc_fix_ctx *unused)
{
    (void)unused; struct ndc_oldkey_case c = {0};
    bool up = ndc_oldkey_setup(&c); int failures = ndc_oldkey_verify(&c, up);
    node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    if (c.ws.open) wallet_sqlite_close(&c.ws);
    if (c.db.open) node_db_close(&c.db);
    main_state_free(&c.f.state);
    if (c.imported) { wallet_free(c.imported); free(c.imported); }
    if (c.f.wallet) { wallet_free(c.f.wallet); free(c.f.wallet); }
    (void)test_rm_rf_recursive(c.f.dir); return failures;
}


static bool ndc_oldkey_reload(struct ndc_oldkey_case *c);
static bool ndc_oldkey_marker(struct ndc_oldkey_case *c, bool pending);
static bool ndc_oldkey_public_scan(struct ndc_oldkey_case *c, const char *status);
static bool ndc_oldkey_recovered(struct ndc_oldkey_case *c, bool imported)
{
    struct wallet_rescan_report report = {0};
    if (imported) (void)wallet_rescan_report(c->imported, &c->f.state.chain_active, 0, -1, c->f.dir, &report);
    wallet_rpc_context_set_base(c->imported, &c->f.state, c->f.dir, &c->ws, NULL, NULL);
    struct zcl_result flushed = wallet_flush_from_context(wallet_ctx());
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    return imported && ndc_oldkey_coverage(c, &report) &&
           ndc_oldkey_found(c->imported, &c->f.note_txid) && flushed.ok &&
           ndc_oldkey_reload(c) && ndc_oldkey_marker(c, false) &&
           ndc_oldkey_public_scan(c, "complete");
}
static bool ndc_oldkey_reload(struct ndc_oldkey_case *c)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "old key reload wallet");
    if (!w) return false;
    wallet_init(w);
    char path[320]; snprintf(path, sizeof(path), "%s/node.db", c->f.dir);
    wallet_sqlite_close(&c->ws); node_db_close(&c->db);
    bool ok = node_db_open(&c->db, path) && wallet_sqlite_open(&c->ws, c->db.db) &&
              wallet_sqlite_read_sapling_keys(&c->ws, w) &&
              sapling_keystore_find_by_ivk(&w->sapling_keys, c->f.wallet->sapling_keys.keys[0].ivk) != NULL;
    wallet_free(w); free(w); return ok;
}
static bool ndc_oldkey_honest(int scanned)
{
    return scanned < 2;
}
static bool ndc_oldkey_public_scan(struct ndc_oldkey_case *c, const char *status)
{
    struct json_value out; json_init(&out); json_set_object(&out);
    wallet_rpc_context_set_base(c->imported, &c->f.state, c->f.dir, &c->ws, NULL, NULL);
    wallet_readiness_append_scan(&out);
    const struct json_value *scan = json_get(&out, "scan");
    const struct json_value *v = scan ? json_get(scan, "status") : NULL;
    const char *s = v ? json_get_str(v) : NULL;
    bool ok = s && strcmp(s, status) == 0;
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    json_free(&out); return ok;
}
static bool ndc_oldkey_marker(struct ndc_oldkey_case *c, bool pending)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "old key scan reload");
    if (!w) return false;
    wallet_init(w);
    enum wallet_scan_state_status state = wallet_sqlite_read_scan_state_checked(&c->ws, w);
    bool ok = state == WALLET_SCAN_STATE_OK && w->scan_retry.pending == pending;
    if (pending) ok = ok && w->scan_retry.from == 0;
    wallet_free(w); free(w); return ok;
}

static bool ndc_oldkey_pending_ok(struct ndc_oldkey_case *c)
{
    return c->imported->scan_retry.pending && ndc_oldkey_marker(c, true) &&
           ndc_oldkey_public_scan(c, "incomplete");
}
static bool ndc_oldkey_retained(bool up, bool rpc, bool held, bool durable)
{
    return up && !rpc && held && durable;
}
static int ndc_oldkey_missing_verify(struct ndc_oldkey_case *cp, bool up)
{
    int failures = 0;
    uint32_t saved = cp->f.slots[1].nStatus; cp->f.slots[1].nStatus &= ~BLOCK_HAVE_DATA;
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_GENTLE);
    bool deferred = false;
    int walk = up ? node_db_catchup_service_run_origin(&cp->db, true, &deferred,
                         &cp->f.state.chain_active, cp->imported, cp->f.dir) : -1;
    bool imported = up && ndc_oldkey_rpc(&cp->f, cp->imported, &cp->ws);
    bool held = up && cp->imported->sapling_keys.num_keys == 1;
    bool durable = held && ndc_oldkey_reload(cp);
    int scanned = up ? wallet_scanned_through_height(cp->imported) : -1;
    enum wallet_readiness_state ready = up ? wallet_readiness_get(cp->imported).state : WALLET_READINESS_UNKNOWN;
    printf("old-key missing body: rpc=%d held=%d durable=%d deferred=%d scanned=%d readiness=%d marker=%d\n",
           imported, held, durable, deferred, scanned, (int)ready, up && cp->imported->scan_retry.pending);
    NDC_CHECK("incomplete import retains a durable key", ndc_oldkey_retained(up, imported, held, durable));
    NDC_CHECK("missing historical note remains absent after incomplete default import rescan",
              walk == 0 && deferred && !ndc_oldkey_found(cp->imported, &cp->f.note_txid));
    NDC_CHECK("incomplete historical scan does not claim the tip", up && ndc_oldkey_honest(scanned));
    NDC_CHECK("incomplete scan is durable and public",
              up && ndc_oldkey_pending_ok(cp));
    cp->f.slots[1].nStatus = saved;
    NDC_CHECK("full rescan after body returns discovers the historical note",
              up && ndc_oldkey_recovered(cp, true));
    return failures;
}
static int ndc_check_oldkey_missing(struct ndc_fix_ctx *unused)
{
    (void)unused; struct ndc_oldkey_case c = {0};
    bool up = ndc_oldkey_setup(&c); int failures = ndc_oldkey_missing_verify(&c, up);
    node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    if (c.ws.open) wallet_sqlite_close(&c.ws);
    if (c.db.open) node_db_close(&c.db);
    main_state_free(&c.f.state);
    if (c.imported) { wallet_free(c.imported); free(c.imported); }
    if (c.f.wallet) { wallet_free(c.f.wallet); free(c.f.wallet); }
    (void)test_rm_rf_recursive(c.f.dir); return failures;
}

struct ndc_oldkey_overlap {
    struct ndc_oldkey_case *c; _Atomic bool entered, release;
    struct wallet_rescan_report report;
};
static void ndc_oldkey_before_clear(void *arg)
{
    struct ndc_oldkey_overlap *o = arg;
    atomic_store(&o->entered, true);
    while (!atomic_load(&o->release)) platform_sleep_ms(2);
}
static void *ndc_oldkey_old_scan(void *arg)
{
    struct ndc_oldkey_overlap *o = arg;
    (void)wallet_rescan_report(o->c->imported, &o->c->f.state.chain_active,
                               0, -1, o->c->f.dir, &o->report);
    return NULL;
}
static bool ndc_oldkey_other_key(struct wallet *w)
{
    uint8_t seed[32] = {9}, d[11], pk[32];
    return sapling_keystore_set_seed(&w->sapling_keys, seed) &&
           sapling_keystore_new_address(&w->sapling_keys, d, pk);
}
static bool ndc_oldkey_overlap_preserved(struct ndc_oldkey_overlap *o)
{
    struct ndc_oldkey_case *c = o->c;
    return o->report.coverage_ok && o->report.shielded_txs_unscanned == 0 &&
        !ndc_oldkey_found(c->imported, &c->f.note_txid) && c->imported->scan_retry.pending &&
        ndc_oldkey_marker(c, true) && wallet_scanned_through_height(c->imported) < 2 &&
        ndc_oldkey_public_scan(c, "incomplete");
}
static bool ndc_oldkey_wait_entered(struct ndc_oldkey_overlap *o, bool started)
{
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    while (started && !atomic_load(&o->entered) && platform_time_monotonic_ms() < deadline) platform_sleep_ms(2);
    return atomic_load(&o->entered);
}
static int ndc_oldkey_overlap_verify(struct ndc_oldkey_case *c, bool up)
{
    int failures = 0; struct ndc_oldkey_overlap o = {.c = c};
    bool seeded = up && ndc_oldkey_other_key(c->imported) &&
                  !ndc_oldkey_found(c->imported, &c->f.note_txid);
    wallet_rescan_test_before_clear(ndc_oldkey_before_clear, &o);
    pthread_t thread; bool started = seeded && pthread_create(&thread, NULL, ndc_oldkey_old_scan, &o) == 0;
    bool entered = ndc_oldkey_wait_entered(&o, started);
    bool rpc = entered && ndc_oldkey_rpc_mode(&c->f, c->imported, &c->ws, true, NULL);
    bool held = entered && sapling_keystore_find_by_ivk(&c->imported->sapling_keys,
                                c->f.wallet->sapling_keys.keys[0].ivk) != NULL;
    bool pending = held && c->imported->scan_retry.pending && ndc_oldkey_marker(c, true);
    atomic_store(&o.release, true);
    if (started) pthread_join(thread, NULL);
    wallet_rescan_test_before_clear(NULL, NULL);
    NDC_CHECK("older scan pauses before clear and default import leaves a pending key",
              entered && !rpc && held && pending);
    NDC_CHECK("older scan cannot clear pending history after import",
              entered && ndc_oldkey_overlap_preserved(&o));
    NDC_CHECK("later full scan finds the historical note and clears the marker",
              held && ndc_oldkey_recovered(c, true));
    return failures;
}
static int ndc_check_oldkey_overlap(struct ndc_fix_ctx *unused)
{
    (void)unused; struct ndc_oldkey_case c = {0};
    bool up = ndc_oldkey_setup(&c); int failures = ndc_oldkey_overlap_verify(&c, up);
    if (c.ws.open) wallet_sqlite_close(&c.ws);
    if (c.db.open) node_db_close(&c.db);
    main_state_free(&c.f.state);
    if (c.imported) { wallet_free(c.imported); free(c.imported); }
    if (c.f.wallet) { wallet_free(c.f.wallet); free(c.f.wallet); }
    (void)test_rm_rf_recursive(c.f.dir); return failures;
}


struct ndc_oldkey_flush_fault { struct node_db *db; bool installed, fired; };
static void ndc_oldkey_fault_sql(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc; (void)argv;
    struct ndc_oldkey_flush_fault *f = sqlite3_user_data(ctx);
    f->fired = true; sqlite3_result_error(ctx, "injected", -1);
}
static void ndc_oldkey_fail_marker_delete(void *arg)
{
    struct ndc_oldkey_flush_fault *f = arg;
    const char *sql = "CREATE TRIGGER ndc_scan_delete_fail BEFORE DELETE ON node_state "
        "WHEN OLD.key=\x27wallet_scan_incomplete\x27 BEGIN SELECT ndc_scan_fault(); END";
    f->installed = sqlite3_create_function(f->db->db, "ndc_scan_fault", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS,
                          f, ndc_oldkey_fault_sql, NULL, NULL) == SQLITE_OK &&
                   sqlite3_exec(f->db->db, sql, NULL, NULL, NULL) == SQLITE_OK;
}
static bool ndc_oldkey_fault_observed(struct ndc_oldkey_flush_fault *f, bool rpc, bool scan_error)
{
    return f->installed && f->fired && scan_error && !rpc;
}
static int ndc_oldkey_flush_verify(struct ndc_oldkey_case *c, bool up)
{
    int failures = 0; struct ndc_oldkey_flush_fault fault = {.db = &c->db};
    wallet_rescan_test_before_clear(ndc_oldkey_fail_marker_delete, &fault);
    bool scan_error = false;
    bool rpc = up && ndc_oldkey_rpc_mode(&c->f, c->imported, &c->ws, false, &scan_error);
    wallet_rescan_test_before_clear(NULL, NULL);
    bool held = up && c->imported->sapling_keys.num_keys == 1;
    bool pending = held && c->imported->scan_retry.pending;
    bool cleared = fault.installed && sqlite3_exec(c->db.db, "DROP TRIGGER ndc_scan_delete_fail", NULL, NULL, NULL) == SQLITE_OK;
    bool durable = held && cleared && ndc_oldkey_reload(c);
    NDC_CHECK("postscan flush failure returns error with key and pending state intact",
              up && ndc_oldkey_fault_observed(&fault, rpc, scan_error) && held && pending && durable && ndc_oldkey_marker(c, true));
    NDC_CHECK("later full scan and flush clear the durable marker",
              durable && ndc_oldkey_recovered(c, true));
    return failures;
}
static int ndc_check_oldkey_flush_failure(struct ndc_fix_ctx *unused)
{
    (void)unused; struct ndc_oldkey_case c = {0};
    bool up = ndc_oldkey_setup(&c); int failures = ndc_oldkey_flush_verify(&c, up);
    if (c.ws.open) wallet_sqlite_close(&c.ws);
    if (c.db.open) node_db_close(&c.db);
    main_state_free(&c.f.state);
    if (c.imported) { wallet_free(c.imported); free(c.imported); }
    if (c.f.wallet) { wallet_free(c.f.wallet); free(c.f.wallet); }
    (void)test_rm_rf_recursive(c.f.dir); return failures;
}


static int ndc_background_case_bounded(struct ndc_fix_ctx *fx, int (*fn)(struct ndc_fix_ctx *))
{
    int failures = 0, status = 0; fflush(NULL); pid_t child = fork();
    if (child == 0) { int result = fn(fx); fflush(NULL); _exit(result == 0 ? 0 : 1); }
    bool finished = false; int64_t deadline = platform_time_monotonic_ms() + 30000;
    while (child > 0 && platform_time_monotonic_ms() < deadline) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) { finished = true; break; }
        if (got < 0 && errno != EINTR) break;
        platform_sleep_ms(10);
    }
    if (child > 0 && !finished) { kill(child, SIGKILL); (void)waitpid(child, &status, 0); }
    NDC_CHECK("background error case completes within 30 seconds",
              child > 0 && finished && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return failures;
}
#endif

int test_node_db_catchup_service(void)
{
    int failures = 0;
    printf("\n=== node_db_catchup_service tests ===\n");
#ifndef _WIN32
    failures += ndc_check_sapling_replay();
    failures += ndc_check_empty_cutover();
    failures += ndc_check_fresh_spend_publication();
    failures += ndc_check_transparent_bypass_cutover();
    failures += ndc_check_transparent_replay();
#endif
    failures += ndc_check_replay_projection_commit();
    failures += ndc_check_utxo_reemit_restart();

    char dir[256];
    char blocks[512];
    struct ndc_map_probe probe;
    failures += ndc_check_missing_and_empty_block_files(
        dir, sizeof(dir), blocks, sizeof(blocks), &probe);
    failures += ndc_check_valid_block_file_maps(dir, blocks, &probe);
    failures += ndc_check_tail_fold_and_sparse_prefix();
    failures += ndc_check_hashless_sync_block_lean();
    failures += ndc_check_competing_fork_parent();
    failures += ndc_check_shielded_values(7, "positive");
    failures += ndc_check_shielded_values(-11, "negative");
    failures += ndc_check_torn_hashless_walk();
    failures += ndc_check_sapling_tree_not_extended_by_old_heights();
    failures += ndc_check_start_at_seed();
    failures += ndc_check_tip_witnesses();

    /* ── Commit cadence / BUSY_SNAPSHOT restart / abort-streak park ────
     * Five real on-disk blocks + active-chain slots drive three fresh
     * node.db instances against one shared fixture datadir. */
    struct ndc_fix_ctx fx = {0};
    failures += ndc_prepare_five_block_fixture(&fx);
    failures += ndc_check_service_conflict_rollback(&fx);
    failures += ndc_check_pace_pause(&fx);
    failures += ndc_check_pace_sparse(&fx);
#ifndef _WIN32
    failures += ndc_background_case_bounded(&fx, ndc_check_background_retry);
    failures += ndc_background_case_bounded(&fx, ndc_check_oldkey_import);
    failures += ndc_background_case_bounded(&fx, ndc_check_oldkey_missing);
    failures += ndc_background_case_bounded(&fx, ndc_check_oldkey_overlap);
    failures += ndc_background_case_bounded(&fx, ndc_check_oldkey_flush_failure);
    failures += ndc_background_case_bounded(&fx, ndc_check_background_owed);
    failures += ndc_background_case_bounded(&fx, ndc_check_background_close_failure);
    failures += ndc_check_pace_sapling_bounded(false, true);
    failures += ndc_check_pace_sapling_bounded(true, true);
#endif
    #ifndef _WIN32
    failures += ndc_check_pace_sapling_bounded(false, false);
    failures += ndc_check_pace_sapling_bounded(true, false);
#endif
    failures += ndc_check_batch_cap_two(&fx);
    failures += ndc_check_default_cap_one_commit(&fx);
    failures += ndc_check_busy_snapshot_restart(&fx);
    failures += ndc_check_transient_reopen_busy(&fx);
    failures += ndc_check_reopen_busy_never_clears(&fx);
    failures += ndc_check_idle_walk_never_sleeps(&fx);
    failures += ndc_check_walk_yields_to_writers(&fx);
    failures += ndc_check_bulk_walk_tip_jobs(&fx);
    failures += ndc_check_tip_queue_refusal();
    failures += ndc_check_hole_stretch_releases_lock(&fx);
    failures += ndc_check_holes_after_rows_release_lock(&fx);
    failures += ndc_check_waiting_writer_cycles_batch(&fx);
    failures += ndc_check_yield_sleep_not_hold_time(&fx);
    failures += ndc_check_timed_commit_survives_abort(&fx);
    failures += ndc_check_tip_read_failure(&fx);
    failures += ndc_check_serving_tip_keeps_indexes(&fx);
    failures += ndc_check_foreign_txn_yields(&fx);
    failures += ndc_check_yield_after_turbo_defers_restore(&fx);
    failures += ndc_check_durable_reopen(&fx);
    failures += ndc_check_maintenance_defers_while_active(&fx);
    failures += ndc_check_abort_storm_parks_worker();
    failures += ndc_append_sixth_block(&fx);
    failures += ndc_check_parked_then_half_open(&fx);
    failures += ndc_check_resumed_matches_continuous(&fx);
    ndc_release_five_block_fixture(&fx);

    test_cleanup_tmpdir(dir);
    printf("node_db_catchup_service: %d failures\n", failures);
    return failures;
}
