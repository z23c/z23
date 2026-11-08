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
#include "validation/chain_linkage_check.h"

#include "config/boot_internal.h"
#include "config/boot_wallet_pending_restore.h"
#include "jobs/block_header_emit.h"
#include "services/chain_state_service.h"
#include "services/island_anchor.h"
#include "wallet/wallet_sqlite.h"
#include "storage/event_log_singleton.h"
#include "storage/block_index_projection.h"
#include "bloom/merkle.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "chain/subsidy.h"
#include "coins/utxo_commitment.h"
#include "core/arith_uint256.h"
#include "domain/consensus/coinbase.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "services/consensus_state_publication_cas.h"
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

#include <fcntl.h>
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
static bool nw_build_block(struct block *blk, const struct chain_params *cp,
                            int height, const struct uint256 *prev)
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
        .n_height = height, .subsidy = get_block_subsidy(height, &cp->consensus),
        .miner_script = &script, .params = &cp->consensus,
    };
    struct zcl_result result = domain_consensus_coinbase_build(&inputs, &blk->vtx[0]);
    if (!result.ok) return false;
    blk->header.hashMerkleRoot = compute_merkle_root(&blk->vtx[0].hash, 1);
    blk->header.hashPrevBlock = *prev;
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700000000u + (uint32_t)height;
    struct arith_uint256 limit;
    uint256_to_arith(&limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&limit, false);
    return mine_block_pow(blk, height, cp, 0);
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
    if (!nw_build_block(&f->one, cp, 1, &cp->consensus.hashGenesisBlock)) return false;
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

static bool nw_replay_refuses_state(struct nw_replay *f, bool require_probe_refusal)
{
    disk_block_io_close_cache();
    int kernel_writes = sqlite3_total_changes(progress_store_db());
    int mirror_writes = sqlite3_total_changes(f->ndb.db);
    uint8_t before[32], after[32], cache[32], cache_after[32];
    uint64_t before_count = 0, after_count = 0, generation = 0, after_generation = 0;
    size_t len = 0;
    utxo_commitment_sha3_compute(f->ndb.db, before, &before_count);
    bool captured = node_db_state_get(&f->ndb, "coins_best_block", cache, sizeof(cache), &len) && len == 32 &&
        coins_kv_get_authority_generation(progress_store_db(), &generation);
    bool executable = boot_index_reindex_replay_executable(&f->ms, NULL, false, f->dir);
    bool replayed = reindex_chainstate(&f->ms, &f->view, &f->cache, &f->ndb, f->root, f->dir);
    utxo_commitment_sha3_compute(f->ndb.db, after, &after_count);
    return captured && (!require_probe_refusal || !executable) && !replayed && before_count == after_count &&
        kernel_writes == sqlite3_total_changes(progress_store_db()) &&
        mirror_writes == sqlite3_total_changes(f->ndb.db) &&
        memcmp(before, after, 32) == 0 &&
        node_db_state_get(&f->ndb, "coins_best_block", cache_after, sizeof(cache_after), &len) && len == 32 &&
        memcmp(cache, cache_after, 32) == 0 &&
        coins_kv_get_authority_generation(progress_store_db(), &after_generation) && generation == after_generation;
}

static bool nw_replay_refuses_unchanged(struct nw_replay *f)
{
    return nw_replay_refuses_state(f, true);
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

/* Admit real H2/H3 indexes and bodies, then hide only the middle body. */
static bool nw_pending_missing_middle(struct nw_replay *f, bool begin_pending)
{
    const struct chain_params *cp = chain_params_get();
    struct block_index *prev = active_chain_at(&f->ms.chain_active, 1);
    struct block_index *middle = NULL;
    struct disk_block_pos middle_pos;
    for (int h = 2; h <= 3; h++) {
        struct block blk;
        if (!nw_build_block(&blk, cp, h, prev->phashBlock)) return false;
        struct uint256 hash;
        block_get_hash(&blk, &hash);
        struct block_index *pi = chainstate_insert_block_index((struct chainstate *)&f->ms, &hash);
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        bool ok = pi && write_block_to_disk(&blk, &pos, f->dir, cp->pchMessageStart);
        if (ok) {
            pi->nHeight = h; pi->pprev = prev; pi->nBits = blk.header.nBits;
            pi->nTx = 1; pi->nChainTx = h + 1; pi->nStatus = BLOCK_VALID_SCRIPTS;
            ok = block_index_set_have_data_verified(pi, &pos, f->dir);
        }
        block_free(&blk);
        if (!ok) return false;
        if (h == 2) { middle = pi; middle_pos = pos; }
        prev = pi;
    }
    active_chain_move_window_tip(&f->ms.chain_active, prev);
    if (begin_pending && !shielded_history_begin_full_replay(progress_store_db(), 3)) return false;
    disk_block_io_close_cache();
    middle->nDataPos = UINT32_MAX; /* only the indexed H2 body becomes unreadable */
    bool fixture = active_chain_height(&f->ms.chain_active) == 3 &&
        active_chain_at(&f->ms.chain_active, 2) == middle &&
        (middle->nStatus & BLOCK_HAVE_DATA) && (prev->nStatus & BLOCK_HAVE_DATA) &&
        !block_index_have_data_readable(middle, f->dir) &&
        block_index_have_data_readable(prev, f->dir);
    bool refused = fixture && nw_replay_refuses_state(f, false);
    middle->nDataPos = middle_pos.nPos;
    return refused;
}

static int nw_fresh_missing_middle_case(void)
{
    int failures = 0;
    struct nw_replay f = {0};
    bool ready = nw_replay_open(&f) && nw_replay_chain(&f, 1);
    NW_CHECK("fresh replay missing-middle fixture ready", ready);
    if (!ready) { nw_replay_close(&f); return failures; }
    struct shielded_replay_session session;
    bool pending = true;
    progress_store_tx_lock();
    bool absent = shielded_history_read_full_replay(progress_store_db(), &session, &pending) && !pending;
    progress_store_tx_unlock();
    NW_CHECK("fresh replay has no pending session", absent);
    struct block_index *one = block_map_find(&f.ms.map_block_index, &f.hash);
    disk_block_io_close_cache();
    NW_CHECK("fresh replay real indexed H1 is readable", one && block_index_have_data_readable(one, f.dir));
    NW_CHECK("fresh replay populated H3 chain with missing H2 refuses without state loss",
        nw_pending_missing_middle(&f, false));
    pending = true;
    progress_store_tx_lock();
    absent = shielded_history_read_full_replay(progress_store_db(), &session, &pending) && !pending;
    progress_store_tx_unlock();
    NW_CHECK("fresh replay refusal creates no replay session", absent);
    uint64_t generation = UINT64_MAX;
    NW_CHECK("fresh replay restored H2 body is readable",
        block_index_have_data_readable(active_chain_at(&f.ms.chain_active, 2), f.dir));
    NW_CHECK("fresh replay prior generation readable",
        coins_kv_get_authority_generation(progress_store_db(), &generation));
    /* Capture the independent expected tip before replay can modify the chain. */
    struct block_index *expected_tip = active_chain_at(&f.ms.chain_active, 3);
    NW_CHECK("fresh replay expected H3 hash exists", expected_tip && expected_tip->phashBlock);
    if (!expected_tip || !expected_tip->phashBlock) { nw_replay_close(&f); return failures; }
    f.hash = *expected_tip->phashBlock;
    seed_integrity_gate_set_node_db_for_testing(&f.ndb);
    NW_CHECK("fresh replay restored full span succeeds through H3",
        reindex_chainstate(&f.ms, &f.view, &f.cache, &f.ndb, f.root, f.dir));
    failures += nw_replay_terminal(&f, 3, generation);
    nw_replay_close(&f);
    return failures;
}

static int nw_pending_replay_case(void)
{
    int failures = 0;
    struct nw_replay f = {0};
    bool ready = nw_replay_open(&f) && nw_replay_chain(&f, 1);
    NW_CHECK("pending replay fixture ready", ready);
    if (!ready) { nw_replay_close(&f); return failures; }
    sqlite3 *db = progress_store_db();
    struct block_index *one = block_map_find(&f.ms.map_block_index, &f.hash);
    NW_CHECK("pending replay bound-body fixture", shielded_history_begin_full_replay(db, 1));
    const struct uint256 *own_hash = one->phashBlock;
    one->phashBlock = NULL;
    NW_CHECK("pending replay unbound body refuses without writes", nw_replay_refuses_state(&f, false));
    one->phashBlock = own_hash;
    struct block_index foreign = *f.genesis;
    struct uint256 foreign_hash = *foreign.phashBlock;
    foreign_hash.data[0] ^= 1;
    foreign.phashBlock = &foreign_hash;
    one->pprev = &foreign;
    NW_CHECK("pending replay body parent mismatch refuses without writes", nw_replay_refuses_state(&f, false));
    one->pprev = f.genesis;
    NW_CHECK("pending replay lower target refuses without state loss",
        shielded_history_begin_full_replay(db, 0) && nw_replay_refuses_state(&f, false));
    NW_CHECK("pending replay higher target refuses without state loss",
        shielded_history_begin_full_replay(db, 2) && nw_replay_refuses_state(&f, false));
    NW_CHECK("pending replay malformed session refuses without state loss",
        progress_meta_set(db, SHIELDED_REPLAY_NEXT_KEY, "00", 2) && nw_replay_refuses_state(&f, false));
    NW_CHECK("pending replay missing middle body refuses without state loss", nw_pending_missing_middle(&f, true));
    active_chain_move_window_tip(&f.ms.chain_active, one);
    NW_CHECK("pending endpoint session is restored",
        shielded_history_begin_full_replay(db, 1) && progress_meta_set(db, SHIELDED_REPLAY_NEXT_KEY, "2", 1));
    uint64_t generation = UINT64_MAX;
    NW_CHECK("pending endpoint prior generation readable", coins_kv_get_authority_generation(db, &generation));
    seed_integrity_gate_set_node_db_for_testing(&f.ndb);
    NW_CHECK("pending endpoint restarts replay from genesis",
        reindex_chainstate(&f.ms, &f.view, &f.cache, &f.ndb, f.root, f.dir));
    failures += nw_replay_terminal(&f, 1, generation);
    nw_replay_close(&f);
    return failures;
}

static bool nw_event_log_preserves_authority(sqlite3 *db, const char *dir)
{
    int writes = sqlite3_total_changes(db);
    bool opened = boot_ensure_event_log(dir) && boot_ensure_event_log(dir);
    uint8_t byte;
    size_t len = 0;
    bool found = true;
    bool absent = progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY, &byte, 1, &len, &found) && !found;
    absent = absent && progress_meta_get(db, COINS_KV_SELF_FOLDED_KEY, &byte, 1, &len, &found) && !found;
    return opened && absent && writes == sqlite3_total_changes(db);
}

static bool nw_migration_stamps_present(sqlite3 *db)
{
    const char *keys[] = {COINS_KV_MIGRATION_COMPLETE_KEY, COINS_KV_SELF_FOLDED_KEY};
    for (unsigned i = 0; i < 2; i++) {
        uint8_t value = 0;
        size_t len = 0;
        bool found = false;
        if (!progress_meta_get(db, keys[i], &value, 1, &len, &found) ||
            !found || len != 1 || value != 1) return false;
    }
    return true;
}

struct nw_boot_wallet {
    struct node_db *node;
    struct wallet_sqlite *store;
};

static bool nw_boot_wallet_open(struct nw_boot_wallet *fixture, const char *root)
{
    struct wallet *wallet;
    struct main_state *main;
    boot_wallet_cutover_test_slots(&fixture->node, &fixture->store, &wallet, &main);
    if (!fixture->node || !fixture->store || fixture->node->open || fixture->store->open) {
        fixture->node = NULL;
        fixture->store = NULL;
        return false;
    }
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/node.db", root);
    if (n <= 0 || (size_t)n >= sizeof(path) || !node_db_open(fixture->node, path))
        return false;
    if (!wallet_sqlite_open_r(fixture->store, fixture->node->db).ok) {
        node_db_close(fixture->node);
        return false;
    }
    struct wallet_cutover_binding binding;
    return wallet_sqlite_cutover_read(fixture->store, &binding) == WALLET_CUTOVER_ABSENT &&
           boot_wallet_allows_coin_repair();
}

static void nw_boot_wallet_close(struct nw_boot_wallet *fixture)
{
    if (fixture->store && fixture->store->open) wallet_sqlite_close(fixture->store);
    if (fixture->node && fixture->node->open) node_db_close(fixture->node);
}

static int nw_pending_migration_case(void)
{
    int failures = 0;
    struct nw_replay f = {0};
    bool ready = nw_replay_open(&f);
    NW_CHECK("pending migration fixture open", ready);
    if (!ready) { nw_replay_close(&f); return failures; }
    struct nw_boot_wallet boot_wallet = {0};
    bool wallet_ready = nw_boot_wallet_open(&boot_wallet, f.root);
    NW_CHECK("global wallet has an absent cutover binding", wallet_ready);
    if (!wallet_ready) { nw_boot_wallet_close(&boot_wallet); nw_replay_close(&f); return failures; }
    sqlite3 *db = progress_store_db();
    uint8_t txid[32] = {0x42};
    NW_CHECK("pending migration unstamped resident coins fixture",
        coins_kv_ensure_schema(db) && coins_kv_add(db, txid, 0, 5000, 1, false, NULL, 0) &&
        progress_meta_delete(db, COINS_KV_MIGRATION_COMPLETE_KEY) &&
        progress_meta_delete(db, COINS_KV_SELF_FOLDED_KEY) &&
        shielded_history_begin_full_replay(db, 3));
    NW_CHECK("pending first/already-open event log cannot stamp authority",
        boot_wallet_allows_coin_repair() && nw_event_log_preserves_authority(db, f.root));
    boot_stop_projection_storage();
    NW_CHECK("make replay session invalid", progress_meta_delete(db, SHIELDED_REPLAY_NEXT_KEY));
    NW_CHECK("invalid first/already-open event log cannot stamp authority",
        boot_wallet_allows_coin_repair() && nw_event_log_preserves_authority(db, f.root));
    boot_stop_projection_storage();
    NW_CHECK("retire replay migration fixture",
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        shielded_history_cancel_full_replay_in_tx(db) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
    NW_CHECK("absent replay still permits ordinary authority migration",
        boot_wallet_allows_coin_repair() && boot_ensure_event_log(f.root) && nw_migration_stamps_present(db));
    boot_stop_projection_storage();
    nw_boot_wallet_close(&boot_wallet);
    nw_replay_close(&f);
    return failures;
}

struct nw_pending_restore_fixture {
    struct nw_replay replay;
    struct chain_state_repository csr;
    struct event_log *log;
    struct block_index_projection *projection;
    struct block_index *tip;
    struct uint256 tip_hash;
    struct uint256 installed_hash;
    struct incremental_merkle_tree tree;
    bool csr_open;
};

static bool nw_pending_restore_add_header(struct nw_pending_restore_fixture *f,
    struct block_index *parent, const struct block_header *header, struct uint256 *hash)
{
    block_header_get_hash(header, hash);
    struct block_index *tip = chainstate_insert_block_index(
        (struct chainstate *)&f->replay.ms, hash);
    if (!tip) return false;
    tip->nHeight = parent->nHeight + 1; tip->pprev = parent; tip->nVersion = header->nVersion;
    tip->nTime = header->nTime; tip->nBits = header->nBits;
    tip->hashFinalSaplingRoot = header->hashFinalSaplingRoot; tip->nStatus = BLOCK_VALID_TREE;
    if (!block_index_set_hdrext(tip, &header->hashMerkleRoot, &header->nNonce,
                                header->nSolution, header->nSolutionSize)) return false;
    if (!block_index_emit_header_event(tip, "pending-restore-test", NULL, NULL)) return false;
    f->tip = tip;
    return true;
}

static bool nw_pending_restore_open(struct nw_pending_restore_fixture *f)
{
    if (!nw_replay_open(&f->replay)) return false;
    struct nw_replay *r = &f->replay;
    char log_path[640], projection_path[640];
    snprintf(log_path, sizeof(log_path), "%s/events.log", r->root);
    snprintf(projection_path, sizeof(projection_path), "%s/projection.db", r->root);
    if (event_log_singleton() || block_index_projection_singleton()) return false;
    f->log = event_log_open(log_path);
    f->projection = f->log ? block_index_projection_open(projection_path, f->log) : NULL;
    if (!f->projection) return false;
    event_log_set_singleton(f->log);
    block_index_projection_set_singleton(f->projection);
    const struct chain_params *cp = chain_params_get();
    struct block_index *genesis = chainstate_insert_block_index(
        (struct chainstate *)&r->ms, &cp->consensus.hashGenesisBlock);
    if (!genesis) return false;
    genesis->nHeight = 0;
    sapling_tree_init(&f->tree);
    struct uint256 leaf = {0}; leaf.data[0] = 0x41;
    incremental_tree_append(&f->tree, &leaf);
    struct block_header header;
    block_header_init(&header);
    header.nVersion = 4; header.nTime = 1700000001u; header.nBits = 0x1f07ffffu;
    header.hashPrevBlock = cp->consensus.hashGenesisBlock;
    incremental_tree_root(&f->tree, &header.hashFinalSaplingRoot);
    header.nSolutionSize = 1; header.nSolution[0] = 7;
    if (!nw_pending_restore_add_header(f, genesis, &header, &f->installed_hash)) return false;
    header.hashPrevBlock = f->installed_hash;
    header.nTime++; header.nSolution[0]++;
    struct block_index *installed = f->tip;
    if (!nw_pending_restore_add_header(f, installed, &header, &f->tip_hash) ||
        !event_log_flush(f->log) || block_index_projection_catch_up(f->projection) == UINT64_MAX)
        return false;
    sqlite3 *db = progress_store_db();
    if (!anchor_kv_ensure_schema(db) || !anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &f->tree, 0))
        return false;
    csr_init(&f->csr, &r->ms.map_block_index, &r->ms.chain_active,
             &r->ms.pindex_best_header, &r->cache, &r->ndb, NULL);
    f->csr_open = true;
    return csr_restore_in_memory_view(&f->csr, genesis, genesis, &cp->consensus.hashGenesisBlock);
}

static void nw_pending_restore_close(struct nw_pending_restore_fixture *f)
{
    if (f->csr_open) csr_free(&f->csr);
    if (block_index_projection_singleton() == f->projection) block_index_projection_set_singleton(NULL);
    if (event_log_singleton() == f->log) event_log_set_singleton(NULL);
    if (f->projection) block_index_projection_close(f->projection);
    if (f->log) event_log_close(f->log);
    nw_replay_close(&f->replay);
}

static bool nw_restore_view_is(struct nw_pending_restore_fixture *f,
                               struct block_index *tip, bool loaded,
                               const struct uint256 *tree_root)
{
    struct uint256 coins, root;
    coins_view_cache_get_best_block(&f->replay.cache, &coins);
    incremental_tree_root(&f->replay.ms.sapling_tree, &root);
    return active_chain_tip(&f->replay.ms.chain_active) == tip &&
        f->replay.ms.pindex_best_header == tip && tip && tip->phashBlock &&
        uint256_eq(&coins, tip->phashBlock) && f->replay.ms.sapling_tree_loaded == loaded &&
        uint256_eq(&root, tree_root);
}

static int nw_prebinding_generation(void)
{
    int failures = 0; sqlite3 *db = progress_store_db();
    uint8_t zero[8] = {0}, malformed = 7; bool present = false; uint64_t generation = 99;
    progress_store_tx_lock();
    bool begun = db && sqlite3_get_autocommit(db) && sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool cleared = begun && progress_meta_delete_in_tx(db, COINS_KV_AUTHORITY_GENERATION_KEY);
    NW_CHECK("generation absent stays distinct", cleared && boot_wallet_authority_generation(db, &present, &generation) && !present && generation == 0);
    bool set = begun && progress_meta_set_in_tx(db, COINS_KV_AUTHORITY_GENERATION_KEY, zero, sizeof(zero));
    NW_CHECK("generation zero is present", set && boot_wallet_authority_generation(db, &present, &generation) && present && generation == 0);
    set = begun && progress_meta_set_in_tx(db, COINS_KV_AUTHORITY_GENERATION_KEY, &malformed, sizeof(malformed));
    NW_CHECK("malformed generation refused", set && !boot_wallet_authority_generation(db, &present, &generation));
    bool rolled_back = begun && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    NW_CHECK("generation fixture rolled back", rolled_back);
    progress_store_tx_unlock();
    return failures;
}
static int nw_prebinding_unavailable(struct nw_pending_restore_fixture *f,
                                     struct block_index *old_tip, const struct uint256 *old_root)
{
    int failures = 0, changes = sqlite3_total_changes(progress_store_db());
    int fd = open(f->replay.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    NW_CHECK("prebinding fixture opens retained datadir", fd >= 0);
    NW_CHECK("prebinding refuses absent durable frontier without publication",
        boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) == BOOT_PENDING_RESTORE_AUTHORITY_UNAVAILABLE &&
        nw_restore_view_is(f, old_tip, false, old_root) && sqlite3_total_changes(progress_store_db()) == changes);
    NW_CHECK("prebinding rejects unbound repository",
        boot_wallet_prebinding_restore(&f->replay.ms, NULL, fd) == BOOT_PENDING_RESTORE_INVALID_CONTEXT &&
        nw_restore_view_is(f, old_tip, false, old_root));
    if (fd >= 0) close(fd);
    return failures;
}
static int nw_pending_restore_case(void)
{
    int failures = 0;
    struct nw_pending_restore_fixture f = {0};
    bool ready = nw_pending_restore_open(&f);
    NW_CHECK("pending restore synthetic fixture opens", ready);
    if (!ready) { nw_pending_restore_close(&f); return failures; }
    struct block_index *old_tip = active_chain_tip(&f.replay.ms.chain_active);
    struct uint256 old_root;
    incremental_tree_root(&f.replay.ms.sapling_tree, &old_root);
    failures += nw_prebinding_generation();
    int changes = sqlite3_total_changes(progress_store_db());
    failures += nw_prebinding_unavailable(&f, old_tip, &old_root);
    NW_CHECK("wrong height refuses without publishing",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, 3, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    struct uint256 wrong_target = f.installed_hash; wrong_target.data[0] ^= 1;
    NW_CHECK("wrong installed target refuses without publishing",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &wrong_target) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    block_index_projection_set_singleton(NULL);
    NW_CHECK("missing header refuses without publishing",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_HEADER_UNAVAILABLE &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    block_index_projection_set_singleton(f.projection);
    struct block_index *parent = f.tip->pprev;
    f.tip->pprev = NULL;
    NW_CHECK("broken ancestry refuses without publishing",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    f.tip->pprev = parent;
    bool removed = sqlite3_exec(progress_store_db(), "DELETE FROM sapling_anchors", NULL, NULL, NULL) == SQLITE_OK;
    NW_CHECK("missing tree refuses without publishing",
        removed && boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_TREE_UNAVAILABLE &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    NW_CHECK("synthetic tree restored for publication checks",
        anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &f.tree, 0));
    changes = sqlite3_total_changes(progress_store_db());
    chain_linkage_hold_set("pending_restore_fixture", 1, "fixture refusal");
    NW_CHECK("CSR refusal leaves the prior view and tree intact",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_CSR_REFUSED &&
        nw_restore_view_is(&f, old_tip, false, &old_root));
    chain_linkage_hold_clear("pending_restore_fixture");
    struct uint256 wanted_root;
    incremental_tree_root(&f.tree, &wanted_root);
    enum boot_pending_restore_result restored = boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash);
    printf("pending restore result=%d progress_changes=%d expected=%d\n",
           (int)restored, sqlite3_total_changes(progress_store_db()), changes);
    NW_CHECK("verified snapshot restores exact in-memory view",
        restored == BOOT_PENDING_RESTORE_OK && nw_restore_view_is(&f, f.tip, true, &wanted_root) &&
        sqlite3_total_changes(progress_store_db()) == changes);
    struct uint256 leaf = {0}; leaf.data[0] = 0x42;
    incremental_tree_append(&f.tree, &leaf);
    bool changed = anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &f.tree, 2);
    NW_CHECK("different durable tree refuses without changing restored view",
        changed && boot_wallet_pending_restore(&f.replay.ms, &f.csr, 2, &f.tip_hash, 1, &f.installed_hash) == BOOT_PENDING_RESTORE_TREE_MISMATCH &&
        nw_restore_view_is(&f, f.tip, true, &wanted_root));
    nw_pending_restore_close(&f);
    return failures;
}

void reducer_frontier_test_set_compiled_anchor(int32_t height);
bool test_reducer_prebinding_seed(sqlite3 *db, struct block_index *genesis,
                                  const uint8_t served[32], const uint8_t coins[32]);
bool test_reducer_prebinding_anchor(sqlite3 *db, const uint8_t *hash);

struct nw_generation_change { sqlite3 *db; bool ok; };
static void nw_change_generation(void *context)
{
    struct nw_generation_change *change = context; const uint8_t one[8] = {1};
    progress_store_tx_lock();
    bool begun = sqlite3_exec(change->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool wrote = begun && progress_meta_set_in_tx(change->db, COINS_KV_AUTHORITY_GENERATION_KEY, one, sizeof(one));
    change->ok = begun && sqlite3_exec(change->db, wrote ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK && wrote;
    progress_store_tx_unlock();
}
static bool nw_prebinding_view(struct nw_pending_restore_fixture *f, struct block_index *tip,
                               struct block_index *header, bool loaded, const struct uint256 *tree_root)
{
    struct uint256 coins, root; coins_view_cache_get_best_block(&f->replay.cache, &coins);
    incremental_tree_root(&f->replay.ms.sapling_tree, &root);
    struct active_chain_window_snapshot window;
    bool window_ok = active_chain_capture_window(&f->replay.ms.chain_active, -1, &window);
    bool ok = tip && tip->phashBlock && window_ok && window.tip == tip &&
        f->replay.ms.pindex_best_header == header && uint256_eq(&coins, tip->phashBlock) &&
        f->replay.ms.sapling_tree_loaded == loaded && uint256_eq(&root, tree_root) &&
        reducer_frontier_provable_tip_is_published() && reducer_frontier_provable_tip_cached() == 0;
    return ok;
}
static int nw_prebinding_refusals(struct nw_pending_restore_fixture *f, struct block_index *old,
                                  struct block_index *tip, const struct uint256 *old_root, int fd)
{
    int failures = 0; sqlite3 *db = progress_store_db();
    f->replay.ms.pindex_best_header = old;
    NW_CHECK("prebinding rejects a lower existing header",
        boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_prebinding_view(f, old, old, false, old_root));
    f->replay.ms.pindex_best_header = tip;
    uint8_t wrong[32] = {0x7f};
    bool replaced = test_reducer_prebinding_anchor(db, wrong);
    NW_CHECK("prebinding rejects different served hash", replaced &&
        boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_prebinding_view(f, old, tip, false, old_root));
    NW_CHECK("restore correct served hash", test_reducer_prebinding_anchor(db, f->installed_hash.data));
    tip->nStatus |= BLOCK_FAILED_TRANSIENT;
    NW_CHECK("prebinding transient failure does not publish",
        boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID &&
        nw_prebinding_view(f, old, tip, false, old_root));
    tip->nStatus &= ~(unsigned)BLOCK_FAILED_TRANSIENT;
    struct nw_generation_change change = {.db = db};
    boot_wallet_prebinding_test_before_recheck(nw_change_generation, &change);
    enum boot_pending_restore_result stale = boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd);
    boot_wallet_prebinding_test_before_recheck(NULL, NULL);
    NW_CHECK("prebinding generation change does not publish", change.ok && stale == BOOT_PENDING_RESTORE_AUTHORITY_UNAVAILABLE &&
        nw_prebinding_view(f, old, tip, false, old_root));
    chain_linkage_hold_set("prebinding_fixture", 1, "fixture refusal");
    enum boot_pending_restore_result held = boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd);
    chain_linkage_hold_clear("prebinding_fixture");
    NW_CHECK("prebinding CSR refusal does not publish", held == BOOT_PENDING_RESTORE_CSR_REFUSED &&
        nw_prebinding_view(f, old, tip, false, old_root));
    return failures;
}
static int nw_prebinding_durable_refusal(struct nw_pending_restore_fixture *f, struct block_index *old,
                                         struct block_index *tip, const struct uint256 *old_root, int fd)
{
    int failures = 0; sqlite3 *db = progress_store_db(); int32_t h = -1; uint8_t hash[32];
    bool removed = test_reducer_prebinding_anchor(db, NULL);
    progress_store_tx_lock();
    bool fallback = consensus_state_publication_cas_capture_frontier_locked(db, &h, hash);
    progress_store_tx_unlock();
    NW_CHECK("runtime genesis fallback actually exists", removed && fallback && h == 0);
    NW_CHECK("prebinding rejects missing durable H* despite runtime genesis",
        boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) == BOOT_PENDING_RESTORE_AUTHORITY_UNAVAILABLE &&
        nw_prebinding_view(f, old, tip, false, old_root));
    NW_CHECK("restore durable anchor fixture", test_reducer_prebinding_anchor(db, f->installed_hash.data));
    return failures;
}
static int nw_prebinding_success(struct nw_pending_restore_fixture *f, struct block_index *tip, int fd)
{
    int failures = 0; struct uint256 root; incremental_tree_root(&f->tree, &root);
    int changes = sqlite3_total_changes(progress_store_db());
    (void)boot_wallet_prebinding_test_take_header_reads();
    enum boot_pending_restore_result result = boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd);
    unsigned same_reads = boot_wallet_prebinding_test_take_header_reads();
    NW_CHECK("prebinding restores proven distinct served and coins frontiers",
        result == BOOT_PENDING_RESTORE_OK && nw_prebinding_view(f, tip, tip, true, &root) &&
        sqlite3_total_changes(progress_store_db()) == changes && same_reads == 2);
    struct block_header header; block_header_init(&header);
    header.nVersion = 4; header.nTime = 1700000003u; header.nBits = 0x1f07ffffu;
    header.hashPrevBlock = f->tip_hash; header.hashFinalSaplingRoot = root;
    header.nSolutionSize = 1; header.nSolution[0] = 9;
    struct uint256 newer_hash;
    bool added = nw_pending_restore_add_header(f, tip, &header, &newer_hash) &&
        event_log_flush(f->log) && block_index_projection_catch_up(f->projection) != UINT64_MAX;
    struct block_index *newer = f->tip;
    if (added) f->replay.ms.pindex_best_header = newer;
    changes = sqlite3_total_changes(progress_store_db());
    (void)boot_wallet_prebinding_test_take_header_reads();
    result = added ? boot_wallet_prebinding_restore(&f->replay.ms, &f->csr, fd) : BOOT_PENDING_RESTORE_INVALID_CONTEXT;
    unsigned newer_reads = boot_wallet_prebinding_test_take_header_reads();
    NW_CHECK("prebinding keeps verified higher header without rereading old chain",
        added && result == BOOT_PENDING_RESTORE_OK && nw_prebinding_view(f, tip, newer, true, &root) &&
        sqlite3_total_changes(progress_store_db()) == changes && newer_reads == 3);
    printf("prebinding header reads: same=%u higher=%u\n", same_reads, newer_reads);
    return failures;
}
static int nw_open_blocks_dir(const struct nw_pending_restore_fixture *f)
{
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/blocks", f->replay.dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}
static int nw_prebinding_case(void)
{
    int failures = 0; struct nw_pending_restore_fixture f = {0};
    bool ready = nw_pending_restore_open(&f); NW_CHECK("prebinding fixture opens", ready);
    if (!ready) { nw_pending_restore_close(&f); return failures; }
    struct active_chain_window_snapshot window;
    bool captured = active_chain_capture_window(&f.replay.ms.chain_active, -1, &window);
    struct block_index *tip = f.tip, *old = captured ? window.tip : NULL;
    struct block_index *genesis = tip->pprev->pprev; struct uint256 old_root;
    int fd = open(f.replay.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int wrong_fd = nw_open_blocks_dir(&f);
    incremental_tree_root(&f.replay.ms.sapling_tree, &old_root);
    sqlite3 *db = progress_store_db();
    ready = old && fd >= 0 && wrong_fd >= 0 && block_index_initialize_genesis(genesis, chain_params_get()) &&
        sqlite3_exec(db, "DELETE FROM sapling_anchors", NULL, NULL, NULL) == SQLITE_OK &&
        anchor_kv_initialize_history(db, 0);
    sapling_tree_init(&f.tree);
    if (ready) {
        reducer_frontier_test_set_compiled_anchor(1);
        ready = test_reducer_prebinding_seed(progress_store_db(), genesis, f.installed_hash.data, f.tip_hash.data);
    }
    NW_CHECK("prebinding actual reducer fixture seeds", ready);
    if (ready) {
        f.replay.ms.pindex_best_header = tip;
        int changes = sqlite3_total_changes(progress_store_db());
        NW_CHECK("prebinding rejects a different retained directory",
            boot_wallet_prebinding_restore(&f.replay.ms, &f.csr, wrong_fd) == BOOT_PENDING_RESTORE_INVALID_CONTEXT &&
            nw_prebinding_view(&f, old, tip, false, &old_root) && sqlite3_total_changes(progress_store_db()) == changes);
        failures += nw_prebinding_refusals(&f, old, tip, &old_root, fd);
        failures += nw_prebinding_durable_refusal(&f, old, tip, &old_root, fd);
        failures += nw_prebinding_success(&f, tip, fd);
    }
    boot_wallet_prebinding_test_before_recheck(NULL, NULL);
    tip_finalize_stage_test_reset(); reducer_frontier_provable_tip_reset();
    reducer_frontier_test_set_compiled_anchor(-1);
    if (fd >= 0) close(fd);
    if (wrong_fd >= 0) close(wrong_fd);
    nw_pending_restore_close(&f); return failures;
}

/* The seeded fact here is synthetic; the real caller verifies its window first. */
static struct block_index *nw_old_seeded(struct nw_pending_restore_fixture *f,
                                          struct wallet_cutover_binding *binding)
{
    struct island_anchor a = {0};
    struct island_anchor_rows rows = {0};
    a.root_height = 73;
    a.rung_height = 100;
    a.root_hash.data[0] = 0x61;
    a.rung_hash.data[0] = 0x62;
    a.root_work.pn[0] = 1;
    rows.hash[0] = a.root_hash;
    rows.hash[ISLAND_ANCHOR_WINDOW - 1] = a.rung_hash;
    struct block_index *rung = chainstate_insert_block_index(
        (struct chainstate *)&f->replay.ms, &a.rung_hash);
    if (!rung) return NULL;
    rung->nHeight = a.rung_height;
    if (!island_anchor_save(progress_store_db(), &a, &rows).ok ||
        !island_anchor_register(&a).ok) return NULL;
    binding->target_height = a.rung_height;
    memcpy(binding->target_hash, a.rung_hash.data, 32);
    return rung;
}

static int nw_old_partial_tree_refusals(struct nw_pending_restore_fixture *f,
                                         const struct wallet_cutover_binding *binding)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    struct block_index *before = active_chain_tip(&f->replay.ms.chain_active);
    struct uint256 root;
    incremental_tree_root(&f->replay.ms.sapling_tree, &root);
    NW_CHECK("old partial missing history cursor refuses",
        sqlite3_exec(db, "DELETE FROM anchor_state WHERE pool=1", NULL, NULL, NULL) == SQLITE_OK &&
        boot_wallet_old_partial_restore(&f->replay.ms, &f->csr, binding) == BOOT_PENDING_RESTORE_TREE_UNAVAILABLE &&
        nw_restore_view_is(f, before, false, &root));
    NW_CHECK("old partial nonzero history cursor refuses",
        anchor_kv_initialize_history(db, 1) &&
        boot_wallet_old_partial_restore(&f->replay.ms, &f->csr, binding) == BOOT_PENDING_RESTORE_TREE_UNAVAILABLE &&
        nw_restore_view_is(f, before, false, &root));
    NW_CHECK("old partial nonempty preactivation tree refuses",
        sqlite3_exec(db, "UPDATE anchor_state SET activation_cursor=0 WHERE pool=1", NULL, NULL, NULL) == SQLITE_OK &&
        anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &f->tree, 0) &&
        boot_wallet_old_partial_restore(&f->replay.ms, &f->csr, binding) == BOOT_PENDING_RESTORE_TREE_UNAVAILABLE &&
        nw_restore_view_is(f, before, false, &root));
    NW_CHECK("old partial corrupt tree refuses",
        sqlite3_exec(db, "UPDATE sapling_anchors SET tree=zeroblob(1)", NULL, NULL, NULL) == SQLITE_OK &&
        boot_wallet_old_partial_restore(&f->replay.ms, &f->csr, binding) == BOOT_PENDING_RESTORE_TREE_UNAVAILABLE &&
        nw_restore_view_is(f, before, false, &root));
    return failures;
}

static int nw_old_partial_case(void)
{
    int failures = 0;
    struct nw_pending_restore_fixture f = {0};
    bool ready = nw_pending_restore_open(&f);
    NW_CHECK("old partial fixture opens", ready);
    if (!ready) { nw_pending_restore_close(&f); return failures; }
    struct wallet_cutover_binding b = {0};
    b.old_height = 2;
    memcpy(b.old_hash, f.tip_hash.data, 32);
    sqlite3 *db = progress_store_db();
    ready = sqlite3_exec(db, "DELETE FROM sapling_anchors", NULL, NULL, NULL) == SQLITE_OK &&
        anchor_kv_initialize_history(db, 0);
    NW_CHECK("old partial empty history setup", ready);
    if (ready) failures += nw_old_partial_tree_refusals(&f, &b);
    ready = sqlite3_exec(db, "DELETE FROM sapling_anchors", NULL, NULL, NULL) == SQLITE_OK;
    struct block_index *parent = f.tip->pprev;
    f.tip->pprev = NULL;
    NW_CHECK("old partial broken ancestry refuses",
        ready && boot_wallet_old_partial_restore(&f.replay.ms, &f.csr, &b) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID);
    f.tip->pprev = parent;
    int changes = sqlite3_total_changes(db);
    NW_CHECK("old partial no island restores implicit empty tree",
        boot_wallet_old_partial_restore(&f.replay.ms, &f.csr, &b) == BOOT_PENDING_RESTORE_OK &&
        active_chain_tip(&f.replay.ms.chain_active) == f.tip &&
        f.replay.ms.pindex_best_header == f.tip && f.replay.ms.sapling_tree_loaded &&
        incremental_tree_size(&f.replay.ms.sapling_tree) == 0 && sqlite3_total_changes(db) == changes);
    struct block_index *rung = nw_old_seeded(&f, &b);
    struct wallet_cutover_binding wrong = b;
    wrong.target_hash[0] ^= 1;
    NW_CHECK("old partial wrong island target refuses",
        rung && boot_wallet_old_partial_restore(&f.replay.ms, &f.csr, &wrong) == BOOT_PENDING_RESTORE_INVALID_CONTEXT);
    changes = sqlite3_total_changes(db);
    NW_CHECK("old partial keeps verified target header",
        rung && boot_wallet_old_partial_restore(&f.replay.ms, &f.csr, &b) == BOOT_PENDING_RESTORE_OK &&
        active_chain_tip(&f.replay.ms.chain_active) == f.tip && f.replay.ms.pindex_best_header == rung &&
        sqlite3_total_changes(db) == changes);
    island_anchor_unregister();
    nw_pending_restore_close(&f);
    return failures;
}

int test_recovery_no_worse(void);
int test_recovery_no_worse(void)
{
    printf("\n=== recovery_no_worse: RECOVERY NEVER MAKES IT WORSE ===\n");
    int failures = 0;
    failures += nw_pending_restore_case();
    failures += nw_prebinding_case();
    failures += nw_old_partial_case();
    failures += nw_canonical_replay_case(1);
    failures += nw_canonical_replay_case(0);
    failures += nw_pending_replay_case();
    failures += nw_fresh_missing_middle_case();
    failures += nw_pending_migration_case();

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
