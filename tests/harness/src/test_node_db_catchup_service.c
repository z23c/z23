/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "services/node_db_catchup_service.h"
#include "services/node_db_catchup_lock_guard.h"
#include "services/db_maintenance.h"
#include "models/database.h"
#include "models/block.h"
#include "models/explorer_index.h"
#include "controllers/sync_controller.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/connect_block.h"
#include "chain/chain.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
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

int test_node_db_catchup_service(void)
{
    int failures = 0;
    printf("\n=== node_db_catchup_service tests ===\n");

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

    /* ── Commit cadence / BUSY_SNAPSHOT restart / abort-streak park ────
     * Five real on-disk blocks + active-chain slots drive three fresh
     * node.db instances against one shared fixture datadir. */
    struct ndc_fix_ctx fx = {0};
    failures += ndc_prepare_five_block_fixture(&fx);
    failures += ndc_check_service_conflict_rollback(&fx);
    failures += ndc_check_batch_cap_two(&fx);
    failures += ndc_check_default_cap_one_commit(&fx);
    failures += ndc_check_busy_snapshot_restart(&fx);
    failures += ndc_check_transient_reopen_busy(&fx);
    failures += ndc_check_reopen_busy_never_clears(&fx);
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
