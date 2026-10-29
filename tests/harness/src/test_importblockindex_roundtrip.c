/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_importblockindex_roundtrip — execution coverage for
 * snapshot_import_block_index() (engine/controllers/src/
 * snapshot_controller_import.c), which engine/entry/main.c's
 * `--importblockindex <src-datadir> [<target-node.db>]` dispatches to. That
 * flag is the first step of the two-step cold-sync recipe.
 *
 * The function has two production call shapes with different header_only:
 *   - the --importblockindex CLI: header_only=true (positions force-zeroed,
 *     bodies fetched lazily via P2P).
 *   - the parallel snapshot-bundle loader (import_block_index_thread):
 *     header_only=false; positions are copied VERBATIM from the source
 *     LevelDB record, so nDataPos preservation is load-bearing (a low file-0
 *     offset such as 1711 must pass through untouched).
 *
 * Both shapes run against the SAME synthetic legacy blocks/index LevelDB
 * (built with the real disk_block_index_serialize() wire format).
 *
 * Scenario C covers per-row import-time trust: every row must hash-bind to its
 * own LevelDB key and pass the PoW target check, or it is quarantined
 * (skipped, counted, typed blocker) while the batch continues. Because the
 * hash-bind needs a REAL header hash, the fixture "mines" each row (bumps
 * nTime until CheckProofOfWork passes at the mainnet powLimit, ~8192 expected
 * SHA256d tries).
 *
 * make t ONLY=importblockindex_roundtrip
 */

#include "test/test_core.h"

#include "chain/chain.h"           /* BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO / BLOCK_VALID_* */
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "controllers/snapshot_controller.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "models/block.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "storage/block_index_db.h"
#include "storage/dbwrapper.h"
#include "test/importblockindex_fixture.h"
#include "util/blocker.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define IBR_N_BLOCKS 32

#define IBR_CHECK(name, expr) do {                              \
    printf("importblockindex_roundtrip: %s... ", (name));       \
    if ((expr)) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

static int ibr_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* The mainnet powLimit as compact nBits — the value the GetNextWorkRequired()
 * genesis case uses (core/chainparams/src/pow.c:45). It is the easiest target
 * CheckProofOfWork accepts, so mining fixture rows is cheap. */
static uint32_t ibr_pow_limit_bits(void)
{
    const struct chain_params *cp = chain_params_get();
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

/* Bump dbi->nTime until the row's real (post-mutation) header hash satisfies
 * the PoW target at `bits`, writing the winning hash to *out_hash. Compares
 * against the decoded target directly instead of calling CheckProofOfWork()
 * per attempt, which logs on every failure. Bounded so a structural break
 * fails loudly instead of hanging. */
static bool ibr_mine_pow(struct disk_block_index *dbi, uint32_t bits,
                         struct uint256 *out_hash)
{
    bool neg = false, overflow = false;
    struct arith_uint256 target;
    arith_uint256_set_compact(&target, bits, &neg, &overflow);
    if (neg || overflow || arith_uint256_is_zero(&target))
        return false;

    dbi->nBits = bits;
    for (uint32_t tries = 0; tries < 2000000u; tries++) {
        dbi->nTime = 1231006505u + tries;
        disk_block_index_get_hash(dbi, out_hash);
        struct arith_uint256 hash_arith;
        uint256_to_arith(&hash_arith, out_hash);
        if (arith_uint256_compare(&hash_arith, &target) <= 0)
            return true;
    }
    return false;
}

/* Serialize `dbi` with the real wire format and write it under LevelDB key
 * 'b' || key_hash[32] — the row-write shape scenarios A-D share; the key may
 * differ from dbi's own hash (hash-bind-mismatch case). */
static bool ibr_write_row(struct db_wrapper *dbw,
                          const struct disk_block_index *dbi,
                          const uint8_t key_hash[32])
{
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = disk_block_index_serialize(dbi, &s) && !s.error;
    if (ok) {
        char key[33];
        key[0] = 'b';
        memcpy(key + 1, key_hash, 32);
        ok = db_write(dbw, key, sizeof(key), (const char *)s.data, s.size,
                      false);
    }
    stream_free(&s);
    return ok;
}

struct ibr_block_fixture {
    uint8_t  hash[32];
    uint8_t  prev_hash[32];
    uint8_t  merkle_root[32];
    uint32_t time;
    uint32_t bits;
    unsigned int status;   /* nStatus as written to the source record */
    int32_t  nfile;
    uint32_t ndatapos;
    uint32_t nundopos;
    int64_t  sapling_value;
};

/* Synthesize a tiny legacy `<src_dir>/blocks/index` LevelDB with N
 * CDiskBlockIndex-shaped 'b'-prefixed records in the real
 * disk_block_index_serialize() wire format, chained hashPrev height-to-height.
 * Block h=1 carries a low file-0 offset (nFile=0, nDataPos=1711) that must
 * pass through unchanged. Every row's `hash` is the real
 * disk_block_index_get_hash() of its header, mined (see ibr_mine_pow) so it
 * also satisfies CheckProofOfWork at the mainnet powLimit. Expected values are
 * recorded into fx[]. Returns false on any failure. */
static bool ibr_build_fixture(const char *src_dir,
                              struct ibr_block_fixture *fx, int n)
{
    char idx_dir[512];
    snprintf(idx_dir, sizeof(idx_dir), "%s/blocks/index", src_dir);

    struct db_wrapper dbw;
    if (!db_wrapper_open(&dbw, idx_dir, 4 << 20, false, true)) {
        fprintf(stderr, "ibr_build_fixture: db_wrapper_open failed: %s\n",
                idx_dir);
        return false;
    }

    uint32_t pow_bits = ibr_pow_limit_bits();
    uint8_t prev[32];
    memset(prev, 0, sizeof(prev));
    bool ok = true;

    for (int h = 0; h < n && ok; h++) {
        struct ibr_block_fixture *b = &fx[h];
        memset(b, 0, sizeof(*b));

        memcpy(b->prev_hash, prev, 32);

        b->merkle_root[0] = 0xBB;
        b->merkle_root[1] = (uint8_t)(h & 0xff);
        b->merkle_root[31] = 0x02;

        /* VALID_TRANSACTIONS | HAVE_DATA | HAVE_UNDO. */
        b->status = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        /* Heights 0-15 -> file 0, 16-31 -> file 1. */
        b->nfile = (h < 16) ? 0 : 1;
        /* h=1: file 0, a SMALL offset (1711). */
        b->ndatapos = (h == 1) ? 1711u : (2000u + (uint32_t)h * 100u);
        b->nundopos = b->ndatapos + 500u;
        b->sapling_value = (int64_t)h * 1000;

        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = h;
        memcpy(dbi.hashPrev.data, b->prev_hash, 32);
        dbi.nStatus = b->status;
        dbi.nTx = 1;
        dbi.nFile = b->nfile;
        dbi.nDataPos = b->ndatapos;
        dbi.nUndoPos = b->nundopos;
        dbi.nVersion = 4;
        memcpy(dbi.hashMerkleRoot.data, b->merkle_root, 32);
        dbi.nSolutionSize = 0;
        dbi.has_sprout_value = false;
        dbi.nSaplingValue = b->sapling_value;

        struct uint256 mined_hash;
        if (!ibr_mine_pow(&dbi, pow_bits, &mined_hash)) {
            fprintf(stderr, "ibr_build_fixture: mine failed h=%d\n", h);
            ok = false;
            break;
        }
        memcpy(b->hash, mined_hash.data, 32);
        b->time = dbi.nTime;
        b->bits = dbi.nBits;

        if (!ibr_write_row(&dbw, &dbi, b->hash)) {
            fprintf(stderr, "ibr_build_fixture: write failed h=%d\n", h);
            ok = false;
            break;
        }

        memcpy(prev, b->hash, 32);
    }

    db_wrapper_close(&dbw);
    return ok;
}

bool test_importblockindex_fixture_build_minimal(const char *src_dir)
{
    struct ibr_block_fixture fx;
    return src_dir && ibr_build_fixture(src_dir, &fx, 1);
}

/* Shutdown abort: the bulk LevelDB walk polls the thread-registry shutdown
 * flag at the top of every 4096-row cadence (first row included), so a
 * shutdown requested before (or during) the import breaks out, rolls the
 * open bulk transaction back, and returns not-ok — the zcl_snap_idx thread
 * no longer holds a shutdown join hostage for the full walk. */
static int ibr_test_shutdown_abort(void)
{
    int failures = 0;

    ibr_mkdir_p("./test-tmp");
    char base[300];
    test_fmt_tmpdir(base, sizeof(base), "importblockindex_roundtrip", "abort");
    ibr_mkdir_p(base);

    char src_dir[340];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy-src-abort", base);
    ibr_mkdir_p(src_dir);

    bool built = test_importblockindex_fixture_build_minimal(src_dir);
    IBR_CHECK("abort scenario: minimal fixture builds", built);
    if (built) {
        char db_path[380];
        snprintf(db_path, sizeof(db_path), "%s/node_abort.db", base);

        thread_registry_reset_for_test();
        thread_registry_request_shutdown();
        int count = -1;
        bool ok = snapshot_import_block_index(src_dir, db_path,
                                              /*header_only=*/true, &count);
        thread_registry_reset_for_test();
        IBR_CHECK("abort scenario: import aborts under shutdown", !ok);
        IBR_CHECK("abort scenario: no rows imported", count == 0);

        struct node_db ndb;
        bool opened = node_db_open(&ndb, db_path);
        IBR_CHECK("abort scenario: target node.db opens", opened);
        if (opened) {
            IBR_CHECK("abort scenario: blocks table left empty",
                      db_block_count(&ndb) == 0);
            node_db_close(&ndb);
        }

        /* Control: flag clear, the SAME import succeeds — the abort above
         * is the registry flag, not a broken fixture. */
        count = -1;
        ok = snapshot_import_block_index(src_dir, db_path,
                                         /*header_only=*/true, &count);
        IBR_CHECK("abort control: import succeeds once the flag clears",
                  ok && count == 1);
    }
    return failures;
}

/* Assert every fixture row (hash/prev_hash/merkle_root/time/bits) landed in
 * the target blocks table unchanged; header_only never touches those fields. */
static void ibr_check_header_fields(int *failure_count, struct node_db *ndb,
                                    const struct ibr_block_fixture *fx, int n)
{
    bool all_match = true;
    for (int h = 0; h < n; h++) {
        struct db_block row;
        if (!db_block_find_by_height(ndb, h, &row)) {
            fprintf(stderr, "  >> missing row at height %d\n", h);
            all_match = false;
            continue;
        }
        if (memcmp(row.hash, fx[h].hash, 32) != 0 ||
            memcmp(row.prev_hash, fx[h].prev_hash, 32) != 0 ||
            memcmp(row.merkle_root, fx[h].merkle_root, 32) != 0 ||
            row.time != fx[h].time || row.bits != fx[h].bits) {
            fprintf(stderr, "  >> header field mismatch at height %d\n", h);
            all_match = false;
        }
    }
    printf("importblockindex_roundtrip: header fields "
           "(hash/prev_hash/merkle_root/time/bits) match the source for every "
           "height... ");
    if (all_match)
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failure_count)++;
    }
}

/* ==================================================================
 * Scenario A row checks: header_only=true force-zeroes the positions and
 * clears HAVE_DATA/HAVE_UNDO while keeping the other status bits. */
static int ibr_check_scenario_a_rows(struct node_db *ndb,
                                     const struct ibr_block_fixture *fx)
{
    int failures = 0;
    bool positions_zeroed = true, status_masked = true;
    for (int h = 0; h < IBR_N_BLOCKS; h++) {
        struct db_block row;
        if (!db_block_find_by_height(ndb, h, &row)) { positions_zeroed = false; continue; }
        if (row.file_num != 0 || row.data_pos != 0 || row.undo_pos != 0)
            positions_zeroed = false;
        unsigned int expect_status =
            fx[h].status & ~(unsigned int)(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        if ((unsigned int)row.status != expect_status)
            status_masked = false;
    }
    IBR_CHECK("scenario A: file_num/data_pos/undo_pos force-zeroed for "
              "EVERY height (not leaked/garbled from the source, even "
              "though the fixture carries nFile=1 and large nDataPos "
              "values for h>=16)", positions_zeroed);
    IBR_CHECK("scenario A: status has HAVE_DATA/HAVE_UNDO cleared, other "
              "bits (BLOCK_VALID_TRANSACTIONS) preserved", status_masked);
    return failures;
}

/* Fast-boot cursors: both state keys must read back as the max height. */
static int ibr_check_tip_cursors(struct node_db *ndb, const char *name)
{
    int failures = 0;
    int64_t pprev_h = -2, shielded_h = -2;
    bool cursors_ok = node_db_state_get_int(ndb, "pprev_repaired_height", &pprev_h) &&
                      node_db_state_get_int(ndb, "shielded_backfill_height", &shielded_h);
    IBR_CHECK(name, cursors_ok && pprev_h == IBR_N_BLOCKS - 1 &&
              shielded_h == IBR_N_BLOCKS - 1);
    return failures;
}

/* ==================================================================
 * Scenario A — header_only=true: the --importblockindex CLI dispatch
 * shape (importblockindex_cli_mode, engine/entry/main_cli_modes.c).
 * Positions must be force-zeroed, HAVE_DATA/HAVE_UNDO cleared.
 * ================================================================== */
static int ibr_scenario_a(const char *base, const char *src_dir,
                          const struct ibr_block_fixture *fx)
{
    int failures = 0;
    {
        char db_path[380];
        snprintf(db_path, sizeof(db_path), "%s/node_a.db", base);

        int count = -1;
        bool ok = snapshot_import_block_index(src_dir, db_path,
                                              /*header_only=*/true, &count);
        IBR_CHECK("scenario A (header-only, CLI dispatch shape): import "
                  "returns ok", ok);
        IBR_CHECK("scenario A: imported row count == N", count == IBR_N_BLOCKS);

        struct node_db ndb;
        IBR_CHECK("scenario A: target node.db opens", node_db_open(&ndb, db_path));

        ibr_check_header_fields(&failures, &ndb, fx, IBR_N_BLOCKS);
        failures += ibr_check_scenario_a_rows(&ndb, fx);
        failures += ibr_check_tip_cursors(&ndb,
            "scenario A: fast-boot cursors (pprev_repaired_height, "
            "shielded_backfill_height) stamped to max height (N-1)");

        int count_before = db_block_count(&ndb);
        node_db_close(&ndb);

        /* Idempotency: re-import into the SAME target. The import's
         * `DELETE FROM blocks` reset makes a dropped reset show as 2N rows. */
        int count2 = -1;
        bool ok2 = snapshot_import_block_index(src_dir, db_path,
                                               /*header_only=*/true, &count2);
        IBR_CHECK("scenario A: re-running import is idempotent (ok)", ok2);
        IBR_CHECK("scenario A: re-running import reports the same count", count2 == IBR_N_BLOCKS);

        struct node_db ndb2;
        IBR_CHECK("scenario A: target node.db reopens after re-import",
                  node_db_open(&ndb2, db_path));
        int count_after = db_block_count(&ndb2);
        IBR_CHECK("scenario A: row count unchanged after re-import (== N, "
                  "not 2N)", count_before == IBR_N_BLOCKS && count_after == IBR_N_BLOCKS);
        node_db_close(&ndb2);
    }
    return failures;
}

/* ==================================================================
 * Scenario B row checks: header_only=false copies positions and status
 * verbatim, including the file-0 low-offset entry at h=1. */
static int ibr_check_scenario_b_rows(struct node_db *ndb,
                                     const struct ibr_block_fixture *fx)
{
    int failures = 0;
    bool positions_exact = true, status_exact = true;
    for (int h = 0; h < IBR_N_BLOCKS; h++) {
        struct db_block row;
        if (!db_block_find_by_height(ndb, h, &row)) { positions_exact = false; continue; }
        if (row.file_num != fx[h].nfile ||
            (uint32_t)row.data_pos != fx[h].ndatapos ||
            (uint32_t)row.undo_pos != fx[h].nundopos)
            positions_exact = false;
        if ((unsigned int)row.status != fx[h].status)
            status_exact = false;
    }
    IBR_CHECK("scenario B: file_num/data_pos/undo_pos copied VERBATIM "
              "for every height (no translation)", positions_exact);
    IBR_CHECK("scenario B: status copied verbatim (unmasked)", status_exact);

    /* The file-0 low-offset entry (h=1, nFile=0, nDataPos=1711) must land
     * as EXACTLY 1711. */
    struct db_block row1;
    bool h1_ok = db_block_find_by_height(ndb, 1, &row1);
    IBR_CHECK("scenario B: file-0 low-offset entry (h=1) nDataPos is "
              "PRESERVED EXACTLY at 1711 (the historical bug translated "
              "this to 3414 instead of passing it through)",
              h1_ok && row1.file_num == 0 && row1.data_pos == 1711);
    return failures;
}

/* ==================================================================
 * Scenario B — header_only=false: the snapshot-bundle loader shape.
 * Positions must be copied VERBATIM.
 * ================================================================== */
static int ibr_scenario_b(const char *base, const char *src_dir,
                          const struct ibr_block_fixture *fx)
{
    int failures = 0;
    {
        char db_path[380];
        snprintf(db_path, sizeof(db_path), "%s/node_b.db", base);

        int count = -1;
        bool ok = snapshot_import_block_index(src_dir, db_path,
                                              /*header_only=*/false, &count);
        IBR_CHECK("scenario B (full positions, snapshot-bundle-loader shape): "
                  "import returns ok", ok);
        IBR_CHECK("scenario B: imported row count == N", count == IBR_N_BLOCKS);

        struct node_db ndb;
        IBR_CHECK("scenario B: target node.db opens", node_db_open(&ndb, db_path));

        ibr_check_header_fields(&failures, &ndb, fx, IBR_N_BLOCKS);
        failures += ibr_check_scenario_b_rows(&ndb, fx);
        failures += ibr_check_tip_cursors(&ndb,
            "scenario B: fast-boot cursors stamped to max height (N-1)");

        int count_before = db_block_count(&ndb);
        node_db_close(&ndb);

        int count2 = -1;
        bool ok2 = snapshot_import_block_index(src_dir, db_path,
                                               /*header_only=*/false, &count2);
        IBR_CHECK("scenario B: re-running import is idempotent (ok)", ok2);
        IBR_CHECK("scenario B: re-running import reports the same count", count2 == IBR_N_BLOCKS);

        struct node_db ndb2;
        IBR_CHECK("scenario B: target node.db reopens after re-import",
                  node_db_open(&ndb2, db_path));
        int count_after = db_block_count(&ndb2);
        IBR_CHECK("scenario B: row count unchanged after re-import (== N, "
                  "not 2N)", count_before == IBR_N_BLOCKS && count_after == IBR_N_BLOCKS);
        node_db_close(&ndb2);
    }
    return failures;
}

/* Writes the scenario C corrupt-row source: h=0 good, h=1 bad hash-bind,
 * h=2 bad PoW-target, h=3 good. *built_out is true only if every row landed. */
static int ibr_c_write_fixture(const char *src_dir_c, bool *built_out)
{
    int failures = 0;
    char idx_dir_c[512];
    snprintf(idx_dir_c, sizeof(idx_dir_c), "%s/blocks/index", src_dir_c);

    struct db_wrapper dbw;
    bool dbw_ok = db_wrapper_open(&dbw, idx_dir_c, 4 << 20, false, true);
    IBR_CHECK("scenario C fixture: open corrupt-row source LevelDB", dbw_ok);

    uint32_t pow_bits = ibr_pow_limit_bits();
    bool built = dbw_ok;

    /* h=0: good row (mined PoW, correct hash-bind). */
    struct disk_block_index dbi0;
    struct uint256 hash0;
    if (built) {
        disk_block_index_init(&dbi0);
        dbi0.nHeight = 0;
        dbi0.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                      BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi0.nTx = 1;
        dbi0.nFile = 0; dbi0.nDataPos = 100; dbi0.nUndoPos = 200;
        dbi0.nVersion = 4;
        dbi0.hashMerkleRoot.data[0] = 0x21;
        dbi0.nSolutionSize = 0;
        built = ibr_mine_pow(&dbi0, pow_bits, &hash0) &&
               ibr_write_row(&dbw, &dbi0, hash0.data);
    }
    IBR_CHECK("scenario C fixture: write h=0 (good)", built);

    /* h=1: bad hash-bind — keyed by something other than the real hash. */
    struct disk_block_index dbi1;
    struct uint256 hash1_real;
    uint8_t claimed_hash1[32];
    if (built) {
        disk_block_index_init(&dbi1);
        dbi1.nHeight = 1;
        memcpy(dbi1.hashPrev.data, hash0.data, 32);
        dbi1.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                      BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi1.nTx = 1;
        dbi1.nFile = 0; dbi1.nDataPos = 300; dbi1.nUndoPos = 400;
        dbi1.nVersion = 4;
        dbi1.hashMerkleRoot.data[0] = 0x22;
        dbi1.nSolutionSize = 0;
        built = ibr_mine_pow(&dbi1, pow_bits, &hash1_real);
        if (built) {
            memcpy(claimed_hash1, hash1_real.data, 32);
            claimed_hash1[0] ^= 0xFF;  /* claim a WRONG key on purpose */
            built = ibr_write_row(&dbw, &dbi1, claimed_hash1);
        }
    }
    IBR_CHECK("scenario C fixture: write h=1 (bad hash-bind)", built);

    /* h=2: bad PoW-target — hash-bind correct, nBits demands target=65536
     * (vs. powLimit ~2^243), so it fails by construction. */
    struct disk_block_index dbi2;
    struct uint256 hash2;
    if (built) {
        disk_block_index_init(&dbi2);
        dbi2.nHeight = 2;
        memcpy(dbi2.hashPrev.data, claimed_hash1, 32);
        dbi2.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                      BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi2.nTx = 1;
        dbi2.nFile = 0; dbi2.nDataPos = 500; dbi2.nUndoPos = 600;
        dbi2.nVersion = 4;
        dbi2.hashMerkleRoot.data[0] = 0x23;
        dbi2.nTime = 1231006505u;
        dbi2.nBits = 0x03010000u;  /* compact target = 65536 */
        dbi2.nSolutionSize = 0;
        disk_block_index_get_hash(&dbi2, &hash2);
        built = ibr_write_row(&dbw, &dbi2, hash2.data);
    }
    IBR_CHECK("scenario C fixture: write h=2 (bad PoW-target)", built);

    /* h=3: good row again — the batch continued past two bad rows. */
    struct disk_block_index dbi3;
    struct uint256 hash3;
    if (built) {
        disk_block_index_init(&dbi3);
        dbi3.nHeight = 3;
        memcpy(dbi3.hashPrev.data, hash2.data, 32);
        dbi3.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                      BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi3.nTx = 1;
        dbi3.nFile = 0; dbi3.nDataPos = 700; dbi3.nUndoPos = 800;
        dbi3.nVersion = 4;
        dbi3.hashMerkleRoot.data[0] = 0x24;
        dbi3.nSolutionSize = 0;
        built = ibr_mine_pow(&dbi3, pow_bits, &hash3) &&
               ibr_write_row(&dbw, &dbi3, hash3.data);
    }
    IBR_CHECK("scenario C fixture: write h=3 (good, after two bad rows)",
              built);

    db_wrapper_close(&dbw);
    *built_out = built;
    return failures;
}

/* Imports the scenario C corrupt source and checks the quarantine outcome. */
static int ibr_c_check_import(const char *base, const char *src_dir_c)
{
    int failures = 0;
    char db_path_c[380];
    snprintf(db_path_c, sizeof(db_path_c), "%s/node_c.db", base);

    uint64_t q_before = snapshot_import_block_index_quarantine_total();
    int count_c = -1;
    bool ok_c = snapshot_import_block_index(src_dir_c, db_path_c,
                                             /*header_only=*/true,
                                             &count_c);
    uint64_t q_after = snapshot_import_block_index_quarantine_total();

    IBR_CHECK("scenario C: import returns ok DESPITE two bad rows "
              "(quarantine, not abort)", ok_c);
    IBR_CHECK("scenario C: only the 2 good rows (h=0,3) imported",
              count_c == 2);
    IBR_CHECK("scenario C: quarantine counter advanced by exactly 2",
              q_after - q_before == 2);

    struct node_db ndb_c;
    bool opened_c = node_db_open(&ndb_c, db_path_c);
    IBR_CHECK("scenario C: target node.db opens", opened_c);
    if (opened_c) {
        struct db_block row;
        IBR_CHECK("scenario C: h=0 landed",
                  db_block_find_by_height(&ndb_c, 0, &row));
        IBR_CHECK("scenario C: h=1 (bad hash-bind) did NOT land",
                  !db_block_find_by_height(&ndb_c, 1, &row));
        IBR_CHECK("scenario C: h=2 (bad PoW-target) did NOT land",
                  !db_block_find_by_height(&ndb_c, 2, &row));
        IBR_CHECK("scenario C: h=3 landed (import continued past "
                  "both bad rows)",
                  db_block_find_by_height(&ndb_c, 3, &row));
        IBR_CHECK("scenario C: exactly 2 rows total in target",
                  db_block_count(&ndb_c) == 2);
        node_db_close(&ndb_c);
    }

    IBR_CHECK("scenario C: typed blocker "
              "'importblockindex_row_quarantine' set",
              blocker_exists("importblockindex_row_quarantine"));
    IBR_CHECK("scenario C: blocker class is TRANSIENT (recoverable "
              "— row skipped, import continues)",
              blocker_class_for("importblockindex_row_quarantine") ==
              (int)BLOCKER_TRANSIENT);
    return failures;
}

/* ==================================================================
 * Scenario C — per-row trust: hash-bind + PoW-target check at import
 * time (default ROM checkpoint, so both bad rows fail the UNCONDITIONAL
 * checks). h=0 good, h=1 bad hash-bind, h=2 bad PoW-target, h=3 good:
 * the batch continues past two consecutive bad rows. */
static int ibr_scenario_c(const char *base)
{
    int failures = 0;
    {
        char src_dir_c[340];
        snprintf(src_dir_c, sizeof(src_dir_c), "%s/legacy-src-corrupt", base);
        ibr_mkdir_p(src_dir_c);

        bool built = false;
        failures += ibr_c_write_fixture(src_dir_c, &built);
        if (built)
            failures += ibr_c_check_import(base, src_dir_c);
    }
    return failures;
}

/* Writes the scenario D bad-solution source: h=1 has a correct hash-bind and
 * mined PoW but a garbage Equihash solution. *built_out reports success. */
static int ibr_d_write_fixture(const char *src_dir_d, bool *built_out)
{
    int failures = 0;
    char idx_dir_d[512];
    snprintf(idx_dir_d, sizeof(idx_dir_d), "%s/blocks/index", src_dir_d);

    struct db_wrapper dbw;
    bool dbw_ok = db_wrapper_open(&dbw, idx_dir_d, 4 << 20, false, true);
    IBR_CHECK("scenario D fixture: open bad-solution source LevelDB",
              dbw_ok);

    bool built = dbw_ok;
    if (built) {
        uint32_t pow_bits = ibr_pow_limit_bits();
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = 1;  /* > overridden checkpoint height=0 */
        dbi.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                     BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi.nTx = 1;
        dbi.nFile = 0; dbi.nDataPos = 100; dbi.nUndoPos = 200;
        dbi.nVersion = 4;
        dbi.hashMerkleRoot.data[0] = 0x31;
        dbi.nSolutionSize = MAX_SOLUTION_SIZE;  /* 1344 — the real (200,9)
                                                   size, garbage content */
        memset(dbi.nSolution, 0x42, dbi.nSolutionSize);

        struct uint256 hash;
        built = ibr_mine_pow(&dbi, pow_bits, &hash) &&
                ibr_write_row(&dbw, &dbi, hash.data);
    }
    IBR_CHECK("scenario D fixture: write h=1 (garbage Equihash solution, "
              "correct hash-bind + PoW target)", built);

    db_wrapper_close(&dbw);
    *built_out = built;
    return failures;
}

/* Imports the scenario D source and checks the above-checkpoint quarantine. */
static int ibr_d_check_import(const char *base, const char *src_dir_d)
{
    int failures = 0;
    char db_path_d[380];
    snprintf(db_path_d, sizeof(db_path_d), "%s/node_d.db", base);

    uint64_t q_before = snapshot_import_block_index_quarantine_total();
    int count_d = -1;
    bool ok_d = snapshot_import_block_index(src_dir_d, db_path_d,
                                             /*header_only=*/true,
                                             &count_d);
    uint64_t q_after = snapshot_import_block_index_quarantine_total();

    IBR_CHECK("scenario D: import returns ok (quarantine, not abort)",
              ok_d);
    IBR_CHECK("scenario D: the bad-solution row did NOT import",
              count_d == 0);
    IBR_CHECK("scenario D: quarantine counter advanced by exactly 1 "
              "(the above-checkpoint full Equihash check fired)",
              q_after - q_before == 1);
    return failures;
}

/* ==================================================================
 * Scenario D — the stride/above-checkpoint full-Equihash gate
 * (import_row_verify's expensive path) fires. The ROM checkpoint is
 * overridden to height=0 so height=1 is "above checkpoint"; the row has a
 * correct hash-bind and mined PoW but a garbage 1344-byte solution that
 * only the full check catches.
 * ================================================================== */
static int ibr_scenario_d(const char *base)
{
    int failures = 0;
    struct rom_state_checkpoint low_cp;
    memset(&low_cp, 0, sizeof(low_cp));
    low_cp.height = 0;
    checkpoints_set_rom_state_override_for_test(&low_cp);

    char src_dir_d[340];
    snprintf(src_dir_d, sizeof(src_dir_d), "%s/legacy-src-badsol", base);
    ibr_mkdir_p(src_dir_d);

    bool built = false;
    failures += ibr_d_write_fixture(src_dir_d, &built);
    if (built)
        failures += ibr_d_check_import(base, src_dir_d);

    checkpoints_reset_rom_state_override_for_test();
    return failures;
}

/* ==================================================================
 * Scenario E — throughput profile. Measures the marginal per-row cost
 * import_row_verify adds: one disk_block_index_get_hash() plus one
 * CheckProofOfWork(). The full check_equihash_solution() is excluded (it
 * runs only on the stride/above-checkpoint rows). 1,000,000 iterations on
 * a pre-mined header, extrapolated x3.1 to the real row count, asserted
 * against a generous ceiling. */
static int ibr_scenario_e(void)
{
    int failures = 0;
    {
        uint32_t pow_bits = ibr_pow_limit_bits();
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = 12345;
        dbi.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                     BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi.nTx = 1;
        dbi.nVersion = 4;
        dbi.hashMerkleRoot.data[0] = 0x55;
        dbi.nSolutionSize = 0;

        struct uint256 mined_hash;
        bool mined = ibr_mine_pow(&dbi, pow_bits, &mined_hash);
        IBR_CHECK("scenario E: mine a representative header for the "
                  "throughput probe", mined);

        if (mined) {
            const struct chain_params *cp = chain_params_get();
            const int64_t n = 1000000;
            int64_t t0 = platform_time_monotonic_us();
            for (int64_t i = 0; i < n; i++) {
                struct uint256 h;
                disk_block_index_get_hash(&dbi, &h);
                (void)CheckProofOfWork(h, dbi.nBits, &cp->consensus);
            }
            int64_t t1 = platform_time_monotonic_us();
            double us_per_row = (double)(t1 - t0) / (double)n;
            /* The real --importblockindex fixture is ~3.1M rows (see
             * CLAUDE.md "Tenacity & recovery"); the unverified baseline
             * is ~60-74s, so the "~2x" budget leaves ~60-74s of added-cost
             * headroom for the WHOLE import, i.e. up to ~19-24us/row on
             * average. Assert two full orders of magnitude below that
             * (<= 5us/row) so a real regression trips this long before it
             * would ever threaten the throughput doctrine. */
            double extrapolated_3_1m_secs = us_per_row * 3100000.0 / 1e6;
            printf("importblockindex_roundtrip: scenario E throughput: "
                   "%.3f us/row (hash-bind recompute + PoW-target check), "
                   "%.2fs extrapolated added cost for 3.1M rows\n",
                   us_per_row, extrapolated_3_1m_secs);
            IBR_CHECK("scenario E: per-row hash-bind+PoW-target overhead "
                      "stays well within the ~2x-baseline import-"
                      "throughput budget (<= 5us/row)",
                      us_per_row <= 5.0);
        }
    }
    return failures;
}

/* ==================================================================
 * Scenario F — a stale same-height fork must not evict the selected
 * chain parent through SQLite's partial unique-height index. The source
 * has main 0->1->2->3 plus a stale sibling at h=2; the unique highest
 * tip h=3 selects the main h=2 by hashPrev, independent of LevelDB key
 * order. */
static int ibr_scenario_f(const char *base)
{
    int failures = 0;
    {
        char src_dir_f[340];
        snprintf(src_dir_f, sizeof(src_dir_f), "%s/legacy-src-fork", base);
        ibr_mkdir_p(src_dir_f);
        struct ibr_block_fixture main_fx[4];
        bool built = ibr_build_fixture(src_dir_f, main_fx, 4);

        struct uint256 fork_hash;
        uint256_set_null(&fork_hash);
        char idx_dir_f[512];
        snprintf(idx_dir_f, sizeof(idx_dir_f), "%s/blocks/index", src_dir_f);
        struct db_wrapper dbw;
        bool dbw_ok = built &&
            db_wrapper_open(&dbw, idx_dir_f, 4 << 20, false, false);
        if (dbw_ok) {
            struct disk_block_index fork;
            disk_block_index_init(&fork);
            fork.nHeight = 2;
            memcpy(fork.hashPrev.data, main_fx[1].hash, 32);
            fork.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                          BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            fork.nTx = 1;
            fork.nFile = 0;
            fork.nDataPos = 9000;
            fork.nUndoPos = 9500;
            fork.nVersion = 4;
            fork.hashMerkleRoot.data[0] = 0xF2;
            built = ibr_mine_pow(&fork, ibr_pow_limit_bits(), &fork_hash) &&
                    ibr_write_row(&dbw, &fork, fork_hash.data);
            db_wrapper_close(&dbw);
        } else {
            built = false;
        }
        IBR_CHECK("scenario F fixture: selected chain plus stale h=2 sibling",
                  built);

        if (built) {
            char db_path_f[380];
            snprintf(db_path_f, sizeof(db_path_f), "%s/node_f.db", base);
            int count_f = -1;
            bool ok_f = snapshot_import_block_index(
                src_dir_f, db_path_f, /*header_only=*/true, &count_f);
            IBR_CHECK("scenario F: selected-chain import succeeds", ok_f);
            IBR_CHECK("scenario F: only four selected headers are reported",
                      count_f == 4);

            struct node_db ndb_f;
            bool opened_f = node_db_open(&ndb_f, db_path_f);
            IBR_CHECK("scenario F: target node.db opens", opened_f);
            if (opened_f) {
                struct db_block row;
                bool main_h2 = db_block_find_by_height(&ndb_f, 2, &row) &&
                    memcmp(row.hash, main_fx[2].hash, 32) == 0;
                bool stale_absent =
                    !db_block_find_by_hash(&ndb_f, fork_hash.data, &row);
                IBR_CHECK("scenario F: h=2 is the parent selected by h=3",
                          main_h2);
                IBR_CHECK("scenario F: stale same-height sibling is absent",
                          stale_absent && db_block_count(&ndb_f) == 4);
                node_db_close(&ndb_f);
            }
        }
    }
    return failures;
}

int test_importblockindex_roundtrip(void)
{
    int failures = 0;

    ibr_mkdir_p("./test-tmp");
    char base[300];
    test_fmt_tmpdir(base, sizeof(base), "importblockindex_roundtrip", "main");
    ibr_mkdir_p(base);

    char src_dir[340];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy-src", base);
    ibr_mkdir_p(src_dir);

    struct ibr_block_fixture fx[IBR_N_BLOCKS];
    bool fixture_ok = ibr_build_fixture(src_dir, fx, IBR_N_BLOCKS);
    IBR_CHECK("fixture: synthesize N=32 legacy blocks/index LevelDB records "
              "(incl. file-0 low-offset shape nDataPos=1711 at h=1)",
              fixture_ok);
    if (!fixture_ok)
        return failures + 1;

    failures += ibr_scenario_a(base, src_dir, fx);
    failures += ibr_scenario_b(base, src_dir, fx);
    failures += ibr_scenario_c(base);
    failures += ibr_scenario_d(base);
    failures += ibr_scenario_e();
    failures += ibr_scenario_f(base);

    failures += ibr_test_shutdown_abort();

    return failures;
}
