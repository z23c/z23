/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_recovery_no_worse — the "RECOVERY NEVER MAKES IT WORSE" invariant.
 *
 * This builds no recovery machinery. It drives the REAL production entry
 * points for two recovery actions and asserts the safety contract that makes
 * falling back to a deeper recovery layer safe in the first place:
 *
 *   (1) NEVER delete state the action cannot locally rebuild — a reindex on a
 *       bodyless datadir REFUSES; it does not wipe.
 *   (2) NEVER spend an unbounded number of destructive attempts — a sentinel
 *       exhausts into a NAMED terminal marker, not a retry loop.
 *   (3) After the action plus a simulated reboot, the datadir CONVERGES: the
 *       preserved state is still there and the terminal marker never silently
 *       re-arms.
 *
 * Two actions are covered here because their contracts are otherwise unproven:
 *
 *   SECTION B — reindex-chainstate coins-state clear. Main proves the
 *       destructive helper boot_index_clear_coins_state() WIPES correctly
 *       (test_coins_anchor_reconcile.c). This proves the GUARD: composed with
 *       boot_index_reindex_replay_executable() in the exact order engine/composition/src/
 *       boot.c uses them, a bodyless (cold-import) datadir refuses, so the
 *       wipe never runs and the un-rebuildable coins state survives — across a
 *       reopen.
 *
 *   SECTION D — the auto_refold boot sentinel. Its auto_reindex sibling is
 *       proven end-to-end by test_boot_reindex_terminates.c; storage/
 *       boot_auto_refold.h had no budget/terminal coverage at all. Attempts
 *       must climb at CONSUME time (not arm time), exhaust into a durable
 *       terminal marker, and never re-arm across further reboots — while a
 *       genuinely-recovered episode still starts fresh.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "coins/utxo_commitment.h"
#include "core/arith_uint256.h"
#include "domain/consensus/coinbase.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "mining/miner.h"
#include "models/database.h"
#include "services/seed_integrity_gate.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "storage/boot_auto_refold.h"
#include "storage/txdb.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NW_CHECK(name, expr) do {                                    \
    printf("  recovery_no_worse: %s... ", (name));                   \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

/* COUNT(*) over `sql` on an open node_db, or -1 on any error. */
static int nw_count(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* Real regtest coinbase and PoW, matching boot_matrix's public builder path. */
static bool nw_build_one(struct block *blk, const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "nw_replay_coinbase");
    if (!blk->vtx) return false;
    blk->num_vtx = 1;
    transaction_init(&blk->vtx[0]);
    if (!transaction_alloc(&blk->vtx[0], 1, 1)) return false;
    struct script script;
    script_init(&script);
    script.data[0] = 0x76; script.data[1] = 0xa9; script.data[2] = 0x14;
    memset(script.data + 3, 0x42, 20);
    script.data[23] = 0x88; script.data[24] = 0xac; script.size = 25;
    struct domain_consensus_coinbase_inputs inputs = {
        .n_height = 1, .subsidy = get_block_subsidy(1, &cp->consensus),
        .miner_script = &script, .params = &cp->consensus,
    };
    struct zcl_result result = domain_consensus_coinbase_build(&inputs, &blk->vtx[0]);
    if (!result.ok) return false;
    blk->header.hashMerkleRoot = compute_merkle_root(&blk->vtx[0].hash, 1);
    blk->header.hashPrevBlock = cp->consensus.hashGenesisBlock;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700000001u;
    struct arith_uint256 limit;
    uint256_to_arith(&limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&limit, false);
    return mine_block_pow(blk, 1, cp, 0);
}

struct nw_replay {
    char root[256], dir[512], file[640];
    struct main_state ms;
    struct node_db ndb;
    struct coins_view_sqlite view;
    struct coins_view_cache cache;
    struct block one;
    struct block_index *genesis;
    struct uint256 hash;
    struct disk_block_pos pos;
    bool view_open;
};

static bool nw_replay_open(struct nw_replay *f)
{
    main_state_init(&f->ms);
    block_init(&f->one);
    test_make_tmpdir(f->root, sizeof(f->root), "recovery_no_worse", "canonical-replay");
    chain_params_select(CHAIN_REGTEST);
    SetDataDir(f->root);
    GetDataDir(true, f->dir, sizeof(f->dir));
    if (mkdir(f->dir, 0700) != 0 && errno != EEXIST) return false;
    char path[640];
    snprintf(path, sizeof(path), "%s/blocks", f->dir);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
    snprintf(path, sizeof(path), "%s/node.db", f->root);
    if (!node_db_open(&f->ndb, path) || !progress_store_open(f->root)) return false;
    f->view_open = coins_view_sqlite_open(&f->view, f->ndb.db);
    if (!f->view_open) return false;
    coins_view_cache_init(&f->cache, &f->view.view);
    return true;
}

static bool nw_replay_chain(struct nw_replay *f, int target)
{
    const struct chain_params *cp = chain_params_get();
    if (!nw_build_one(&f->one, cp)) return false;
    block_get_hash(&f->one, &f->hash);
    f->genesis = chainstate_insert_block_index((struct chainstate *)&f->ms, &cp->consensus.hashGenesisBlock);
    struct block_index *one = chainstate_insert_block_index((struct chainstate *)&f->ms, &f->hash);
    if (!f->genesis || !one) return false;
    f->genesis->nHeight = 0;
    f->genesis->nStatus = BLOCK_VALID_SCRIPTS; /* Canonical index; no genesis body. */
    f->genesis->nBits = f->one.header.nBits;
    f->genesis->nTx = 1; f->genesis->nChainTx = 1;
    f->genesis->nChainWork = GetBlockProof(f->genesis);
    one->pprev = f->genesis; one->nHeight = 1; one->nStatus = BLOCK_VALID_SCRIPTS;
    one->nVersion = f->one.header.nVersion; one->nTime = f->one.header.nTime;
    one->nBits = f->one.header.nBits; one->nTx = 1; one->nChainTx = 2;
    disk_block_pos_init(&f->pos);
    if (!write_block_to_disk(&f->one, &f->pos, f->dir, cp->pchMessageStart) ||
        !block_index_set_have_data_verified(one, &f->pos, f->dir)) return false;
    snprintf(f->file, sizeof(f->file), "%s/blocks/blk%05d.dat", f->dir, f->pos.nFile);
    struct block_index *tip = target ? one : f->genesis;
    active_chain_move_window_tip(&f->ms.chain_active, tip);
    f->ms.pindex_best_header = tip;
    coins_view_cache_set_best_block(&f->cache, &cp->consensus.hashGenesisBlock);
    return node_db_exec(&f->ndb,
        "INSERT INTO utxos(txid,vout,value,script,script_type,address_hash,height,is_coinbase) "
        "VALUES(zeroblob(32),0,5000,x'51',0,NULL,777,0)") &&
        node_db_state_set(&f->ndb, "coins_best_block", cp->consensus.hashGenesisBlock.data, 32);
}

static void nw_replay_close(struct nw_replay *f)
{
    seed_integrity_gate_reset_for_testing();
    tip_finalize_stage_shutdown();
    if (f->view_open) {
        coins_view_cache_free(&f->cache);
        coins_view_sqlite_close(&f->view);
    }
    progress_store_close();
    if (f->ndb.open) node_db_close(&f->ndb);
    block_free(&f->one);
    main_state_free(&f->ms);
    SetDataDir(""); ClearDataDirCache();
    chain_params_select(CHAIN_MAIN);
    test_cleanup_tmpdir(f->root);
}

static bool nw_flip_body(struct nw_replay *f)
{
    FILE *file = fopen(f->file, "r+b");
    if (!file) return false;
    bool ok = fseek(file, (long)f->pos.nPos, SEEK_SET) == 0;
    int byte = ok ? fgetc(file) : EOF;
    ok = byte != EOF && fseek(file, (long)f->pos.nPos, SEEK_SET) == 0;
    if (ok) ok = fputc(byte ^ 1, file) != EOF;
    return fclose(file) == 0 && ok;
}

static bool nw_replay_refuses_unchanged(struct nw_replay *f)
{
    disk_block_io_close_cache();
    uint8_t before[32], after[32], cache[32], cache_after[32];
    uint64_t before_count = 0, after_count = 0, generation = 0, after_generation = 0;
    size_t len = 0;
    utxo_commitment_sha3_compute(f->ndb.db, before, &before_count);
    bool captured = node_db_state_get(&f->ndb, "coins_best_block", cache, sizeof(cache), &len) && len == 32 &&
        coins_kv_get_authority_generation(progress_store_db(), &generation);
    bool executable = boot_index_reindex_replay_executable(&f->ms, NULL, false, f->dir);
    bool replayed = reindex_chainstate(&f->ms, &f->view, &f->cache, &f->ndb, f->root, f->dir);
    utxo_commitment_sha3_compute(f->ndb.db, after, &after_count);
    return captured && !executable && !replayed && before_count == after_count &&
        memcmp(before, after, 32) == 0 &&
        node_db_state_get(&f->ndb, "coins_best_block", cache_after, sizeof(cache_after), &len) && len == 32 &&
        memcmp(cache, cache_after, 32) == 0 &&
        coins_kv_get_authority_generation(progress_store_db(), &after_generation) && generation == after_generation;
}

static bool nw_replay_complete(sqlite3 *db)
{
    int64_t cursor;
    bool found;
    for (int pool = 0; pool < 2; pool++)
        if (!anchor_kv_activation_cursor(db, pool, &cursor, &found) || !found || cursor != 0) return false;
    if (!nullifier_kv_activation_cursor(db, &cursor, &found) || !found || cursor != 0) return false;
    uint8_t bytes[32]; size_t len;
    return progress_meta_get_blob_exact(db, SHIELDED_REPLAY_NEXT_KEY, bytes, sizeof(bytes), &len, &found) && !found;
}

static bool nw_replay_caches_match(struct nw_replay *f, int target,
    const uint8_t root[32], uint64_t count)
{
    uint8_t stamp[32], best[32];
    uint64_t stamp_count = 0;
    int32_t height = -1;
    size_t len = 0;
    const uint8_t *expected = target ? f->hash.data : chain_params_get()->consensus.hashGenesisBlock.data;
    return node_db_state_get(&f->ndb, "coins_best_block", best, sizeof(best), &len) && len == 32 && memcmp(best, expected, 32) == 0 &&
        utxo_commitment_sha3_load(f->ndb.db, stamp, &height, &stamp_count) && height == target && stamp_count == count && memcmp(root, stamp, 32) == 0;
}

static int nw_replay_terminal(struct nw_replay *f, int target, uint64_t prior_generation)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    uint64_t count = 0, generation = 0;
    uint8_t root[32], kernel[32];
    int32_t applied = -1, hstar = -1, served = -1;
    utxo_commitment_sha3_compute(f->ndb.db, root, &count);
    NW_CHECK("canonical replay: stale coin removed and kernel commitment matches",
        nw_count(&f->ndb, "SELECT count(*) FROM utxos WHERE height=777") == 0 &&
        coins_kv_count_sqlite(db) == (int64_t)count && coins_kv_commitment(db, kernel) == 0 && memcmp(root, kernel, 32) == 0);
    NW_CHECK("canonical replay: real H1 coinbase or empty genesis delta",
        target ? coins_kv_exists(db, f->one.vtx[0].hash.data, 0) : count == 0);
    NW_CHECK("canonical replay: next height and single generation transition",
        coins_kv_get_applied_height(db, &applied, NULL) && applied == target + 1 &&
        coins_kv_get_authority_generation(db, &generation) && generation == prior_generation + 1);
    NW_CHECK("canonical replay: exact tip cache and commitment stamp",
        nw_replay_caches_match(f, target, root, count));
    NW_CHECK("canonical replay: served tip and H* agree",
        active_chain_height(&f->ms.chain_active) == target && reducer_frontier_compute_hstar(db, &hstar, &served) && hstar == target && served == target);
    NW_CHECK("canonical replay: complete shielded history and retired session", nw_replay_complete(db));
    return failures;
}

static int nw_canonical_replay_case(int target)
{
    int failures = 0;
    struct nw_replay f = {0};
    bool ready = nw_replay_open(&f) && nw_replay_chain(&f, target);
    NW_CHECK("canonical replay: valid mined H1 with bodyless canonical genesis fixture", ready);
    if (!ready) { nw_replay_close(&f); return failures; }
    if (target) {
        struct uint256 foreign = *f.genesis->phashBlock;
        foreign.data[0] ^= 1;
        const struct uint256 *original = f.genesis->phashBlock;
        f.genesis->phashBlock = &foreign;
        NW_CHECK("canonical replay: foreign H0 refuses without mutation", nw_replay_refuses_unchanged(&f));
        f.genesis->phashBlock = original;
        char retained[704]; snprintf(retained, sizeof(retained), "%s.retained", f.file);
        disk_block_io_close_cache();
        NW_CHECK("canonical replay: remove H1 fixture", rename(f.file, retained) == 0);
        NW_CHECK("canonical replay: missing H1 refuses without mutation", nw_replay_refuses_unchanged(&f));
        NW_CHECK("canonical replay: restore H1 fixture", rename(retained, f.file) == 0);
        disk_block_io_close_cache();
        NW_CHECK("canonical replay: corrupt H1 fixture", nw_flip_body(&f));
        NW_CHECK("canonical replay: corrupt H1 refuses without mutation", nw_replay_refuses_unchanged(&f));
        NW_CHECK("canonical replay: repair H1 fixture", nw_flip_body(&f));
        disk_block_io_close_cache();
    }
    uint64_t generation = UINT64_MAX;
    NW_CHECK("canonical replay: prior generation readable", coins_kv_get_authority_generation(progress_store_db(), &generation));
    seed_integrity_gate_set_node_db_for_testing(&f.ndb);
    NW_CHECK("canonical replay: loaded chain is executable", boot_index_reindex_replay_executable(&f.ms, NULL, false, f.dir));
    NW_CHECK("canonical replay: actual reindex_chainstate succeeds", reindex_chainstate(&f.ms, &f.view, &f.cache, &f.ndb, f.root, f.dir));
    failures += nw_replay_terminal(&f, target, generation);
    nw_replay_close(&f);
    return failures;
}

int test_recovery_no_worse(void);
int test_recovery_no_worse(void)
{
    printf("\n=== recovery_no_worse: RECOVERY NEVER MAKES IT WORSE ===\n");
    int failures = 0;
    failures += nw_canonical_replay_case(1);
    failures += nw_canonical_replay_case(0);

    /* ════════════════════════════════════════════════════════════════
     * SECTION B — reindex-chainstate / coins-state clear: compose the
     * executability probe and the destructive clear in the exact order
     * engine/composition/src/boot.c uses them. A bodyless datadir must REFUSE.
     * ════════════════════════════════════════════════════════════════ */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "reindex_bodyless");
        char dbpath[512];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

        struct node_db ndb;
        NW_CHECK("B: node_db opens", node_db_open(&ndb, dbpath));
        NW_CHECK("B: seed a near-tip utxo row",
                 node_db_exec(&ndb,
                     "INSERT INTO utxos(txid,vout,value,script,script_type,"
                     "address_hash,height,is_coinbase) "
                     "VALUES(x'2222',0,5000,x'00',0,NULL,777,0)"));
        NW_CHECK("B: seed coins-best + commitment cache",
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('coins_best_block',x'deadbeef')") &&
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('utxo_sha3',x'01')") &&
                 node_db_exec(&ndb,
                     "INSERT OR REPLACE INTO node_state(key,value)"
                     " VALUES('utxo_commitment',x'02')"));

        char btpath[512];
        snprintf(btpath, sizeof(btpath), "%s/blocktree", dir);
        struct block_tree_db btdb;
        bool btdb_open = block_tree_db_open(&btdb, btpath, 1 << 20, false, true);
        NW_CHECK("B: bodyless block-tree db opens (no genesis body)", btdb_open);

        bool executable = boot_index_reindex_replay_executable(NULL, &btdb,
                                                               btdb_open, dir);
        NW_CHECK("B: replay NOT executable on a bodyless datadir "
                 "(genesis unreadable -> refuses)", !executable);

        /* Mirror boot.c's guard exactly: the destructive clear is gated
         * STRICTLY on the executability probe. */
        if (executable)
            boot_index_clear_coins_state(&ndb);

        NW_CHECK("B: no-worse (1) — utxos row survives (never wipe state we "
                 "cannot rebuild)",
                 nw_count(&ndb, "SELECT COUNT(*) FROM utxos") == 1);
        NW_CHECK("B: no-worse (1) — coins-best/commitment cache survives",
                 nw_count(&ndb,
                     "SELECT COUNT(*) FROM node_state WHERE key IN "
                     "('coins_best_block','utxo_commitment','utxo_sha3')") == 3);

        node_db_close(&ndb);
        if (btdb_open)
            block_tree_db_close(&btdb);

        /* No-worse (3): simulated reboot — the preserved state is DURABLE. */
        struct node_db ndb2;
        NW_CHECK("B: reboot — node_db reopens", node_db_open(&ndb2, dbpath));
        NW_CHECK("B: reboot — utxos row still present after reopen",
                 nw_count(&ndb2, "SELECT COUNT(*) FROM utxos") == 1);
        NW_CHECK("B: reboot — commitment cache still present after reopen",
                 nw_count(&ndb2,
                     "SELECT COUNT(*) FROM node_state WHERE key IN "
                     "('coins_best_block','utxo_commitment','utxo_sha3')") == 3);
        node_db_close(&ndb2);

        test_rm_rf(dir);
    }

    /* ════════════════════════════════════════════════════════════════
     * SECTION D — auto_refold sentinel: bounded-budget convergence.
     * The boot_auto_refold sibling of the proven auto_reindex sentinel.
     * ════════════════════════════════════════════════════════════════ */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "refold_sentinel");
        const int32_t ANCHOR = 3056758;

        int n1 = boot_auto_refold_request(dir, ANCHOR);
        NW_CHECK("D: fresh arm -> count 1, pending, not terminal",
                 n1 == 1 && boot_auto_refold_pending(dir) &&
                 !boot_auto_refold_is_terminal(dir));

        /* Re-arming at the SAME anchor before any consume must NOT climb the
         * count — only a real boot attempt spends budget. */
        NW_CHECK("D: re-arm before consume does not climb the budget",
                 boot_auto_refold_request(dir, ANCHOR) == 1);

        bool climbs = true;
        for (int i = 1; i <= BOOT_AUTO_REFOLD_MAX; i++) {
            NW_CHECK("D: consume within budget returns true",
                     boot_auto_refold_consume(dir));
            int32_t a = 0;
            int cnt = -1;
            boot_auto_refold_status(dir, &a, &cnt);
            climbs &= (cnt == i && a == ANCHOR);
        }
        NW_CHECK("D: attempts climb 1..MAX at CONSUME time (never at arm time)",
                 climbs);

        /* The MAX+1'th boot's consume: budget exhausted -> a NAMED terminal
         * marker, never an unbounded destructive retry loop. */
        NW_CHECK("D: exhausted consume returns false (never retries past "
                 "budget)", !boot_auto_refold_consume(dir));
        NW_CHECK("D: terminal marker persisted, no longer pending",
                 boot_auto_refold_is_terminal(dir) &&
                 !boot_auto_refold_pending(dir));

        /* No-worse (3): many further simulated reboots — durably immutable,
         * never silently re-arming a fresh destructive attempt. */
        bool durable = true;
        for (int i = 0; i < 25; i++) {
            durable &= (boot_auto_refold_request(dir, ANCHOR) ==
                            BOOT_AUTO_REFOLD_TERMINAL) &&
                       !boot_auto_refold_consume(dir) &&
                       boot_auto_refold_is_terminal(dir);
        }
        NW_CHECK("D: 25 simulated reboots never re-arm the exhausted budget",
                 durable);

        test_cleanup_tmpdir(dir);
    }

    /* Section D companion: a genuinely RECOVERED episode is not falsely
     * exhausted — the reindex sentinel's proven pattern, for refold. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "recovery_no_worse",
                         "refold_recover");
        const int32_t A1 = 111, A2 = 222;

        NW_CHECK("D2: fresh arm", boot_auto_refold_request(dir, A1) == 1);
        NW_CHECK("D2: attempt 1 consumes", boot_auto_refold_consume(dir));
        boot_auto_refold_clear(dir);  /* the refold reset committed: success */
        NW_CHECK("D2: clear -> not pending, not terminal",
                 !boot_auto_refold_pending(dir) &&
                 !boot_auto_refold_is_terminal(dir));
        NW_CHECK("D2: a genuinely-new episode starts fresh at count 1",
                 boot_auto_refold_request(dir, A2) == 1);

        test_cleanup_tmpdir(dir);
    }

    if (failures == 0)
        printf("=== recovery_no_worse: ALL PASS ===\n\n");
    else
        printf("recovery_no_worse: failures=%d\n", failures);
    return failures;
}
