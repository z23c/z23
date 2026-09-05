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

int test_node_db_catchup_service(void)
{
    int failures = 0;
    printf("\n=== node_db_catchup_service tests ===\n");

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "node_db_catchup", "mmap");
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    mkdir(blocks, 0755);

    size_t sz = 99;
    int err = 0;
    void *mapping = NULL;
    const uint8_t *data = NULL;
    bool opened = node_db_catchup_test_block_mapping_open(
        dir, 7, &mapping, &data, &sz, &err);
    NDC_CHECK("missing block file is quiet ENOENT",
              !opened && mapping == NULL && data == NULL &&
              sz == 0 && err == ENOENT);

    char path[512];
    snprintf(path, sizeof(path), "%s/blk00008.dat", blocks);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
    sz = 99;
    err = 0;
    opened = node_db_catchup_test_block_mapping_open(
        dir, 8, &mapping, &data, &sz, &err);
    NDC_CHECK("empty block file is quiet EINVAL",
              !opened && mapping == NULL && data == NULL &&
              sz == 0 && err == EINVAL);

    snprintf(path, sizeof(path), "%s/blk00009.dat", blocks);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    const uint8_t bytes[] = {0xde, 0xad, 0xbe, 0xef};
    bool wrote = fd >= 0 &&
        write(fd, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes);
    if (fd >= 0) close(fd);
    sz = 0;
    err = 0;
    opened = node_db_catchup_test_block_mapping_open(
        dir, 9, &mapping, &data, &sz, &err);
    bool mapped = wrote && opened && mapping != NULL && data != NULL &&
                  sz == sizeof(bytes) && err == 0 &&
                  memcmp(data, bytes, sizeof(bytes)) == 0;
    node_db_catchup_test_block_mapping_close(mapping);
    NDC_CHECK("valid block file maps", mapped);

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
    /* Two-or-more missing TOP slots (chain_tip=3, projection_tip=1: heights
     * 2 AND 3 both missing active-chain indices). A fresh catchup pass would
     * start at height 2, find it missing, and publish target=1 — the same
     * projection_tip it already has, no progress — so the watcher must
     * suppress the restart just as it does for a single missing slot. This
     * is the exact defect this predicate was generalized to cover. */
    NDC_CHECK("sparse watcher waits when two-or-more top slots are missing",
              node_db_catchup_sparse_tip_slot_pending(true, 1, 3, false));
    /* Missing slot strictly interior (below projection_tip + 1) while the
     * next-needed slot IS present: a fresh catchup pass starting at
     * projection_tip + 1 makes real progress (the interior hole is a lean
     * hole handled inline by the run, not a reason to wait), so the watcher
     * must allow the restart. */
    NDC_CHECK("sparse watcher allows restart when the next slot is present "
              "despite an interior hole",
              !node_db_catchup_sparse_tip_slot_pending(true, 1, 5, true));

    /* A torn index (cp -a of a running node) can hand the catchup walk a
     * block_index carrying BLOCK_HAVE_DATA yet a NULL phashBlock. That must
     * fail-closed with a named log — never a SIGSEGV in sync_block_lean. */
    {
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
    }

    /* Drive the full walk against a torn projection: a real decodable block
     * on disk reached through an active-chain slot whose phashBlock is NULL,
     * with a missing lower slot (h=0). The run must complete with a named
     * lean-hole outcome, never crash, and never advance the projection tip
     * onto the unidentifiable slot. */
    {
        char dir2[256];
        test_make_tmpdir(dir2, sizeof(dir2), "node_db_catchup", "torn_walk");
        char blocks2[512];
        snprintf(blocks2, sizeof(blocks2), "%s/blocks", dir2);
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
        bool wrote = b.vtx && write_block_to_disk(&b, &pos, dir2, msg_start);
        struct uint256 block_hash;
        block_get_hash(&b, &block_hash);
        block_free(&b);

        struct block_index torn;
        memset(&torn, 0, sizeof(torn));
        torn.nHeight = 1;
        torn.nStatus = BLOCK_HAVE_DATA;
        torn.nFile = pos.nFile;
        torn.nDataPos = pos.nPos;
        torn.phashBlock = NULL;

        struct active_chain ac;
        active_chain_init(&ac);
        bool installed = active_chain_install_tip_slot(&ac, &torn);

        struct node_db ndb;
        char ndb_path[512];
        snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir2);
        bool opened = node_db_open(&ndb, ndb_path);

        /* A pre-run sentinel: if the walk SIGSEGVs on the hash-less slot,
         * the process dies here and the group fails with a signal. Reaching
         * the assertions with result reassigned proves the walk returned a
         * named outcome (a catchup abort returns -1 via LOG_ERR) instead. */
        int result = -99;
        if (wrote && installed && opened)
            result = node_db_catchup_service_run(&ndb, &ac, NULL, dir2);

        int tip = opened ? node_db_sync_get_tip_height(&ndb) : -1;
        NDC_CHECK("catchup survives a torn hash-less slot without crashing",
                  wrote && installed && opened && result != -99);
        NDC_CHECK("catchup refuses to advance the projection onto a torn slot",
                  tip < 1);

        /* Repair only the torn identity and run the same on-disk block through
         * the real catchup transaction. This reaches advance_wallet_witnesses
         * with sync_in_batch=false while the catchup's plain BEGIN is open —
         * the exact post-bundle path that previously misclassified its own
         * transaction as foreign and aborted on the first block. */
        torn.phashBlock = &block_hash;
        int repaired_result = opened
            ? node_db_catchup_service_run(&ndb, &ac, NULL, dir2) : -1;
        int repaired_tip = opened ? node_db_sync_get_tip_height(&ndb) : -1;
        int64_t tree_height = -1;
        bool tree_persisted = opened &&
            node_db_state_get_int(&ndb, "sapling_tree_rebuild_height",
                                  &tree_height);
        NDC_CHECK("catchup advances through its caller-owned plain transaction",
                  repaired_result == 1 && repaired_tip == 1);
        NDC_CHECK("catchup commits the Sapling tree/height pair atomically",
                  tree_persisted && tree_height == 1);

        if (opened) node_db_close(&ndb);
        active_chain_free(&ac);
        test_cleanup_tmpdir(dir2);
    }

    /* ── Commit cadence / BUSY_SNAPSHOT restart / abort-streak park ────
     * Five real on-disk blocks + active-chain slots drive three fresh
     * node.db instances against one shared fixture datadir. */
    {
        enum { FIX_N = 5 };
        char dirF[256], dirA[256], dirB[256], dirC[256], dirD[256];
        char dirR[256], dirS[256];
        test_make_tmpdir(dirF, sizeof(dirF), "node_db_catchup", "fix");
        test_make_tmpdir(dirA, sizeof(dirA), "node_db_catchup", "batchA");
        test_make_tmpdir(dirB, sizeof(dirB), "node_db_catchup", "batchB");
        test_make_tmpdir(dirC, sizeof(dirC), "node_db_catchup", "snapC");
        test_make_tmpdir(dirD, sizeof(dirD), "node_db_catchup", "continuousD");
        test_make_tmpdir(dirR, sizeof(dirR), "node_db_catchup", "reopenR");
        test_make_tmpdir(dirS, sizeof(dirS), "node_db_catchup", "reopenS");
        char blocksF[512];
        snprintf(blocksF, sizeof(blocksF), "%s/blocks", dirF);
        mkdir(blocksF, 0755);

        struct disk_block_pos pos[FIX_N + 1];
        struct uint256 hashes[FIX_N + 1];
        unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
        bool built = true;
        for (int h = 1; h <= FIX_N && built; h++) {
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
            built = b.vtx &&
                (disk_block_pos_init(&pos[h]),
                 write_block_to_disk(&b, &pos[h], dirF, msg_start)) &&
                (block_get_hash(&b, &hashes[h]), true);
            block_free(&b);
        }

        struct block_index slots[FIX_N + 1];
        struct active_chain ac;
        active_chain_init(&ac);
        for (int h = 1; h <= FIX_N && built; h++) {
            memset(&slots[h], 0, sizeof(slots[h]));
            slots[h].nHeight = h;
            slots[h].nStatus = BLOCK_HAVE_DATA;
            slots[h].nFile = pos[h].nFile;
            slots[h].nDataPos = pos[h].nPos;
            slots[h].phashBlock = &hashes[h];
            built = active_chain_install_tip_slot(&ac, &slots[h]);
        }
        NDC_CHECK("five-block fixture builds and installs", built);

        char pathA[512], pathB[512], pathC[512], pathD[512];
        char pathR[512], pathS[512];
        snprintf(pathA, sizeof(pathA), "%s/node.db", dirA);
        snprintf(pathB, sizeof(pathB), "%s/node.db", dirB);
        snprintf(pathC, sizeof(pathC), "%s/node.db", dirC);
        snprintf(pathD, sizeof(pathD), "%s/node.db", dirD);
        snprintf(pathR, sizeof(pathR), "%s/node.db", dirR);
        snprintf(pathS, sizeof(pathS), "%s/node.db", dirS);

        /* (c1) Batch cap 2 over 5 blocks: commits at indexed=2 and 4 plus
         * the final commit — multiple transactions, never one unbounded
         * batch. */
        struct node_db ndbA;
        bool openA = built && node_db_open(&ndbA, pathA);
        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_lock_guard_test_set_batch_size(2);
        int resA = openA ? node_db_catchup_service_run(&ndbA, &ac, NULL, dirF) : -1;
        int tipA = openA ? node_db_sync_get_tip_height(&ndbA) : -1;
        int maxA = openA ? db_block_max_height(&ndbA) : -1;
        int commitsA = node_db_catchup_lock_guard_test_batch_commits();
        NDC_CHECK("batch cap 2 indexes all five blocks",
                  resA == FIX_N && tipA == FIX_N && maxA == FIX_N);
        NDC_CHECK("batch cap 2 commits mid-walk at 2 and 4",
                  commitsA == 2);

        /* (c2) Default cap (2000): one final commit only — and the final
         * state is identical to the multi-transaction run. */
        struct node_db ndbB;
        bool openB = built && node_db_open(&ndbB, pathB);
        node_db_catchup_lock_guard_test_reset();
        int resB = openB ? node_db_catchup_service_run(&ndbB, &ac, NULL, dirF) : -1;
        int tipB = openB ? node_db_sync_get_tip_height(&ndbB) : -1;
        int maxB = openB ? db_block_max_height(&ndbB) : -1;
        int commitsB = node_db_catchup_lock_guard_test_batch_commits();
        int64_t treeA = -1, treeB = -1;
        bool treeA_ok = openA &&
            node_db_state_get_int(&ndbA, "sapling_tree_rebuild_height", &treeA);
        bool treeB_ok = openB &&
            node_db_state_get_int(&ndbB, "sapling_tree_rebuild_height", &treeB);
        NDC_CHECK("default cap needs no mid-walk commit",
                  resB == FIX_N && commitsB == 0);
        NDC_CHECK("commit granularity never changes the final state",
                  tipB == tipA && maxB == maxA &&
                  treeA_ok && treeB_ok && treeA == treeB);

        /* (b) Injected SQLITE_BUSY_SNAPSHOT write failure: the pass rolls
         * back and restarts the whole walk once (bounded), then completes
         * with the identical final state. */
        struct node_db ndbC;
        bool openC = built && node_db_open(&ndbC, pathC);
        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_lock_guard_test_force_snapshot_failures(1);
        int restarts_before = node_db_catchup_lock_guard_test_snapshot_restarts();
        int resC = openC ? node_db_catchup_service_run(&ndbC, &ac, NULL, dirF) : -1;
        int tipC = openC ? node_db_sync_get_tip_height(&ndbC) : -1;
        int restarts_after = node_db_catchup_lock_guard_test_snapshot_restarts();
        NDC_CHECK("BUSY_SNAPSHOT triggers exactly one whole-walk restart",
                  restarts_after == restarts_before + 1);
        NDC_CHECK("the restarted walk completes with identical state",
                  resC == FIX_N && tipC == tipA);

        /* (r1) ONE transient SQLITE_BUSY on the post-batch-commit
         * BEGIN IMMEDIATE. This is the class a wait cures: the batch
         * already committed durably and the walk holds no snapshot, so
         * the reopen retries in place and the pass completes with the
         * identical state. Aborting here instead is what stopped catchup
         * on the node1 devfleet node — with catchup stopped the boot
         * watchdog withholds its ping, systemd kills the node, and the
         * next boot repeats the whole thing at a random height. */
        struct node_db ndbR;
        bool openR = built && node_db_open(&ndbR, pathR);
        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_test_reset_reopen();
        node_db_catchup_lock_guard_test_set_batch_size(2);
        node_db_catchup_test_force_reopen_busy(1);
        int resR = openR ? node_db_catchup_service_run(&ndbR, &ac, NULL, dirF) : -1;
        int tipR = openR ? node_db_sync_get_tip_height(&ndbR) : -1;
        int maxR = openR ? db_block_max_height(&ndbR) : -1;
        int attemptsR = node_db_catchup_test_reopen_attempts();
        NDC_CHECK("a transient busy reopen never aborts the walk",
                  resR == FIX_N && tipR == FIX_N && maxR == FIX_N);
        /* Two mid-walk commits (blocks 2 and 4) means two reopens; the
         * injected busy costs exactly one extra BEGIN. */
        NDC_CHECK("the retry costs exactly one extra BEGIN attempt",
                  attemptsR == 3);

        /* (r2) A busy that never clears. The walk spends exactly
         * NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS BEGINs on it, names every
         * retry, then keeps the unchanged fail-closed abort — the budget
         * buys patience, it does not remove the wall. */
        struct node_db ndbS;
        bool openS = built && node_db_open(&ndbS, pathS);
        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_test_reset_reopen();
        node_db_catchup_lock_guard_test_set_batch_size(2);
        node_db_catchup_test_force_reopen_busy(
            NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS);
        char logS[16384];
        g_cap_ndb = &ndbS;
        g_cap_chain = &ac;
        g_cap_datadir = dirF;
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
        node_db_catchup_test_reset_reopen();
        if (openS) node_db_close(&ndbS);

        /* (r3) The other half of the same policy: db_maintenance is the
         * writer whose lock hold produced the busy above, so it yields
         * its tick while a walk is running and runs on the next call once
         * the walk is over. The yield is bounded — a multi-hour catchup
         * must not silence housekeeping for its whole duration. */
        node_db_catchup_test_set_active(true);
        bool deferred = openB && !db_maintenance_run_now(&ndbB, "wal").ok;
        node_db_catchup_test_set_active(false);
        bool ran_after = openB && db_maintenance_run_now(&ndbB, "wal").ok;
        NDC_CHECK("db_maintenance defers its tick while catchup is active",
                  deferred);
        NDC_CHECK("db_maintenance runs on the next tick once catchup ends",
                  ran_after);

        node_db_catchup_test_set_active(true);
        bool budget_held = openB;
        for (int i = 0; i < DB_MAINT_MAX_CATCHUP_DEFERRALS && budget_held; i++)
            budget_held = !db_maintenance_run_now(&ndbB, "wal").ok;
        bool ran_at_bound = openB && db_maintenance_run_now(&ndbB, "wal").ok;
        node_db_catchup_test_set_active(false);
        NDC_CHECK("the courtesy holds for the whole deferral budget",
                  budget_held);
        NDC_CHECK("housekeeping is never deferred forever", ran_at_bound);

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

        /* Real work pending (a 6th block) must stay undone while parked. */
        {
            struct disk_block_pos pos6;
            struct uint256 hash6;
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
            bool sixth = b6.vtx &&
                (disk_block_pos_init(&pos6),
                 write_block_to_disk(&b6, &pos6, dirF, msg_start));
            block_get_hash(&b6, &hash6);
            block_free(&b6);
            struct block_index slot6;
            memset(&slot6, 0, sizeof(slot6));
            slot6.nHeight = FIX_N + 1;
            slot6.nStatus = BLOCK_HAVE_DATA;
            slot6.nFile = pos6.nFile;
            slot6.nDataPos = pos6.nPos;
            slot6.phashBlock = &hash6;
            sixth = sixth && active_chain_install_tip_slot(&ac, &slot6);
            NDC_CHECK("sixth block extends the pending work", sixth);

            int res_parked = sixth && openA
                ? node_db_catchup_service_run(&ndbA, &ac, NULL, dirF) : -1;
            int tip_parked = openA ? node_db_sync_get_tip_height(&ndbA) : -1;
            NDC_CHECK("the parked worker does NOT re-run the failing pass",
                      res_parked == 0 && tip_parked == FIX_N);

            blocker_clear(NODE_DB_CATCHUP_ABORT_STREAK_BLOCKER_ID);
            NDC_CHECK("operator clear half-opens the worker",
                      !node_db_catchup_lock_guard_parked() &&
                      node_db_catchup_lock_guard_test_abort_streak() == 0);
            int res_halfopen = sixth && openA
                ? node_db_catchup_service_run(&ndbA, &ac, NULL, dirF) : -1;
            int tip_halfopen = openA ? node_db_sync_get_tip_height(&ndbA) : -1;
            NDC_CHECK("the half-open pass resumes indexing",
                      res_halfopen == 1 && tip_halfopen == FIX_N + 1);

            /* Differential restart proof: a resumed 1..5 then 6 walk must
             * produce exactly the same height-6 chained receipt as a fresh
             * continuous 1..6 walk. If the production start-1 read is
             * deleted, changed to start, or replaced by a zero seed, these
             * receipts diverge while all per-row writes still look green. */
            node_db_catchup_lock_guard_test_reset();
            struct node_db ndbD;
            bool openD = sixth && node_db_open(&ndbD, pathD);
            int res_continuous = openD
                ? node_db_catchup_service_run(&ndbD, &ac, NULL, dirF) : -1;
            uint8_t resumed_receipt[32] = {0};
            uint8_t continuous_receipt[32] = {0};
            bool resumed_read = openA && db_view_integrity_get(
                &ndbA, FIX_N + 1, resumed_receipt);
            bool continuous_read = openD && db_view_integrity_get(
                &ndbD, FIX_N + 1, continuous_receipt);
            NDC_CHECK("resumed catchup receipt matches continuous chain",
                      res_continuous == FIX_N + 1 && resumed_read &&
                      continuous_read &&
                      memcmp(resumed_receipt, continuous_receipt, 32) == 0);
            if (openD) node_db_close(&ndbD);
        }

        node_db_catchup_lock_guard_test_reset();
        node_db_catchup_test_reset_reopen();
        blocker_reset_for_testing();
        if (openA) node_db_close(&ndbA);
        if (openB) node_db_close(&ndbB);
        if (openC) node_db_close(&ndbC);
        if (openR) node_db_close(&ndbR);
        active_chain_free(&ac);
        test_cleanup_tmpdir(dirF);
        test_cleanup_tmpdir(dirA);
        test_cleanup_tmpdir(dirB);
        test_cleanup_tmpdir(dirC);
        test_cleanup_tmpdir(dirD);
        test_cleanup_tmpdir(dirR);
        test_cleanup_tmpdir(dirS);
    }

    test_cleanup_tmpdir(dir);
    printf("node_db_catchup_service: %d failures\n", failures);
    return failures;
}
