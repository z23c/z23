/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_bg_validation_delta_undo — blocks this node connects itself must be
 * fully script-verifiable by background validation.
 *
 * The real utxo_apply stage folds a short chain of mined regtest blocks
 * (coinbase, a two-input spend of outside coins, and a spend of an output
 * created earlier in the same block). Its co-committed utxo_apply_delta row
 * is the only undo record such a block ever gets, so the group proves:
 *   - every applied height yields a block_undo naming exactly the spent
 *     outputs, and that undo survives the rev-format serialize round trip;
 *   - the background verifier checks every transparent script of those
 *     blocks with zero undo-missing skips, against the delta's scripts;
 *   - a row for another block hash, or one that does not match the block's
 *     inputs, gives no undo (fail closed: counted as skips, never trusted);
 *   - a kill -9 at any commit of the fold leaves every applied height with
 *     its undo and no unapplied height with one, and the restarted fold
 *     completes the record. */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "base/serialize_le.h"
#include "bloom/merkle.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/undo.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_delta_undo.h"
#include "jobs/utxo_apply_stage.h"
#include "mining/miner.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "services/bg_validation_service.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <signal.h>
#include <stdatomic.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

/* Sibling-private production verifier (engine/services/src). */
bool bg_validation_validate_block_proofs(const struct block *block,
                                         struct block_index *pindex,
                                         const char *datadir,
                                         const struct chain_params *params,
                                         int num_workers,
                                         size_t max_script_batch,
                                         int64_t *sigs_out,
                                         int64_t *proofs_out,
                                         int64_t *skips_out);

#define DU_BLOCKS 3
#define DU_OUTSIDE_VALUE 2000
#define DU_INNER_VALUE 1500
#define DU_OP_TRUE 0x51
#define DU_OP_FALSE 0x00

struct du_chain {
    struct block_index idx[DU_BLOCKS];
    struct uint256 hash[DU_BLOCKS];
    struct block body[DU_BLOCKS];
    uint8_t outside_script;  /* scriptPubKey byte the lookup reports */
};

static void du_outside_txid(struct uint256 *out, int h, int which)
{
    memset(out->data, 0x5a, sizeof(out->data));
    out->data[0] = (uint8_t)h;
    out->data[1] = (uint8_t)which;
}

static bool du_tx(struct transaction *tx, size_t nin, int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, nin, 1))
        return false;
    for (size_t i = 0; i < nin; i++)
        tx->vin[i].sequence = UINT32_MAX;
    tx->vout[0].value = out_value;
    tx->vout[0].script_pub_key.data[0] = DU_OP_TRUE;
    tx->vout[0].script_pub_key.size = 1;
    return true;
}

/* coinbase | tx1 spends two outside coins | tx2 spends tx1:0 in-block. */
static bool du_block_build(struct block *blk, int h,
                           const struct chain_params *cp)
{
    block_init(blk);
    blk->vtx = zcl_calloc(3, sizeof(*blk->vtx), "du_vtx");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 3;
    if (!du_tx(&blk->vtx[0], 1, 1000 + h) ||
        !du_tx(&blk->vtx[1], 2, DU_INNER_VALUE) ||
        !du_tx(&blk->vtx[2], 1, 1000))
        return false;
    outpoint_set_null(&blk->vtx[0].vin[0].prevout);
    for (uint32_t i = 0; i < 2; i++) {
        du_outside_txid(&blk->vtx[1].vin[i].prevout.hash, h, (int)i);
        blk->vtx[1].vin[i].prevout.n = i;
    }
    transaction_compute_hash(&blk->vtx[0]);
    transaction_compute_hash(&blk->vtx[1]);
    blk->vtx[2].vin[0].prevout.hash = blk->vtx[1].hash;
    blk->vtx[2].vin[0].prevout.n = 0;
    transaction_compute_hash(&blk->vtx[2]);

    struct uint256 txids[3] = {
        blk->vtx[0].hash, blk->vtx[1].hash, blk->vtx[2].hash };
    blk->header.nVersion = 4;
    blk->header.hashMerkleRoot = compute_merkle_root(txids, 3);
    uint256_set_null(&blk->header.hashPrevBlock);
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1600000000u + (uint32_t)h;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk->header.nBits = arith_uint256_get_compact(&pow_limit, false);
    return mine_block_pow(blk, h, cp, 0);
}

static bool du_chain_build(struct du_chain *c, const struct chain_params *cp)
{
    memset(c, 0, sizeof(*c));
    c->outside_script = DU_OP_TRUE;
    for (int h = 0; h < DU_BLOCKS; h++) {
        if (!du_block_build(&c->body[h], h, cp))
            return false;
        block_get_hash(&c->body[h], &c->hash[h]);
        struct block_index *bi = &c->idx[h];
        block_index_init(bi);
        bi->phashBlock = &c->hash[h];
        tbi_ext(bi)->hashMerkleRoot = c->body[h].header.hashMerkleRoot;
        bi->nHeight = h;
        bi->nVersion = c->body[h].header.nVersion;
        bi->nTime = c->body[h].header.nTime;
        bi->nBits = c->body[h].header.nBits;
        bi->nStatus = BLOCK_HAVE_DATA;
        if (h > 0)
            bi->pprev = &c->idx[h - 1];
    }
    return true;
}

static void du_chain_free(struct du_chain *c)
{
    for (int h = 0; h < DU_BLOCKS; h++)
        block_free(&c->body[h]);
}

static bool du_reader(struct block *out, const struct block_index *bi,
                      const char *datadir, void *user)
{
    (void)datadir;
    struct du_chain *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= DU_BLOCKS)
        return false;
    return test_block_copy(out, &c->body[bi->nHeight], "du_read");
}

static bool du_lookup(const struct uint256 *txid, uint32_t vout,
                      struct utxo_apply_lookup *out, void *user)
{
    struct du_chain *c = user;
    memset(out, 0, sizeof(*out));
    for (int h = 0; h < DU_BLOCKS; h++) {
        for (int which = 0; which < 2; which++) {
            struct uint256 want;
            du_outside_txid(&want, h, which);
            if (uint256_eq(&want, txid) && vout == (uint32_t)which) {
                out->found = true;
                out->value = DU_OUTSIDE_VALUE;
                out->height = 0;
                out->script_len = 1;
                out->script[0] = c->outside_script;
                return true;
            }
        }
    }
    return true;
}

static bool du_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) {
        printf("[du] sql failed: %s\n", err);
        sqlite3_free(err);
    }
    return rc == SQLITE_OK;
}

/* Upstream verdicts the stage requires before it folds a height. */
static bool du_seed_upstream(sqlite3 *db, const struct du_chain *c)
{
    if (!du_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        "  ok INTEGER NOT NULL, sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL, block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO proof_validate_log (height, status, ok, "
            "sapling_spends_total, sapling_outputs_total, "
            "sprout_joinsplits_total, block_hash, validated_at) "
            "VALUES (?, 'verified', 1, 0, 0, 0, ?, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (int h = 0; ok && h < DU_BLOCKS; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, c->hash[h].data, 32, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
             "VALUES('proof_validate', %d, 1)", DU_BLOCKS);
    return ok && du_exec(db, sql);
}

static bool du_seed_script_verdicts(sqlite3 *db, const struct du_chain *c)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log (height, status, ok, "
            "tx_count, input_count, validated_at, block_hash) "
            "VALUES (?, 'verified', 1, 3, 3, 1, ?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (int h = 0; ok && h < DU_BLOCKS; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, c->hash[h].data, 32, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    return ok;
}

/* Open the datadir's stores and arm the real utxo_apply stage over `c`.
 * Opening an existing datadir runs the stage's own startup recovery. */
static bool du_open(const char *dir, struct main_state *ms, struct du_chain *c)
{
    SetDataDir(dir);
    if (!progress_store_open(dir) || !projection_store_open(dir))
        return false;
    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    block_map_init(&ms->map_block_index);
    active_chain_move_window_tip(&ms->chain_active, &c->idx[DU_BLOCKS - 1]);
    if (!du_seed_upstream(progress_store_db(), c) ||
        !utxo_apply_stage_init(ms) ||
        !du_seed_script_verdicts(progress_store_db(), c))
        return false;
    utxo_apply_stage_set_reader(du_reader, c);
    utxo_apply_stage_set_lookup(du_lookup, c);
    return true;
}

static void du_close(struct main_state *ms)
{
    utxo_apply_stage_shutdown();
    active_chain_free(&ms->chain_active);
    block_map_free(&ms->map_block_index);
    projection_store_close();
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
}

static bool du_script_is(const struct script *s, uint8_t op)
{
    return s->size == 1 && s->data[0] == op;
}

/* The undo the fold must have recorded for height h of `c`. */
static bool du_undo_matches(const struct block_undo *u, int h)
{
    if (u->num_txundo != 2 || u->vtxundo[0].num_prevout != 2 ||
        u->vtxundo[1].num_prevout != 1)
        return false;
    for (size_t i = 0; i < 2; i++) {
        const struct tx_in_undo *in = &u->vtxundo[0].vprevout[i];
        if (in->txout.value != DU_OUTSIDE_VALUE || in->height != 0 ||
            in->coinbase || !du_script_is(&in->txout.script_pub_key,
                                          DU_OP_TRUE))
            return false;
    }
    const struct tx_in_undo *inner = &u->vtxundo[1].vprevout[0];
    return inner->txout.value == DU_INNER_VALUE &&
           inner->height == (unsigned)h && !inner->coinbase &&
           du_script_is(&inner->txout.script_pub_key, DU_OP_TRUE);
}

/* The rev-file encoding of the reconstructed undo must round-trip. */
static bool du_undo_roundtrips(const struct block_undo *u, int h)
{
    struct byte_stream s;
    stream_init(&s, 0);
    bool ok = block_undo_serialize(u, &s);
    struct block_undo back;
    block_undo_init(&back);
    if (ok) {
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        ok = block_undo_deserialize(&back, &r) && du_undo_matches(&back, h);
    }
    block_undo_free(&back);
    stream_free(&s);
    return ok;
}

static enum utxo_apply_delta_undo_status du_load(
    const struct du_chain *c, int h, struct block_undo *out)
{
    return utxo_apply_delta_block_undo_load(progress_store_db(), h,
                                            &c->hash[h], &c->body[h], out);
}

/* A background-validation index for height h: same identity, no parent
 * (the contextual header rules are not what this group exercises), and no
 * rev position, exactly like a block this node connected itself. */
static void du_bg_index(struct block_index *bi, struct du_chain *c, int h)
{
    block_index_init(bi);
    bi->phashBlock = &c->hash[h];
    bi->nHeight = h;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nFile = 0;
    bi->nDataPos = 8;
}

/* One folded chain shared by the forward-record cases, in order. */
struct du_fixture {
    const struct chain_params *cp;
    char dir[256];
    struct du_chain c;
    struct main_state ms;
    bool built;
    bool opened;
};

static int du_case_record(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: every folded height carries an exact undo record") {
        fx->built = du_chain_build(&fx->c, fx->cp);
        ASSERT(fx->built);
        fx->opened = du_open(fx->dir, &fx->ms, &fx->c);
        ASSERT(fx->opened);
        ASSERT_EQ(utxo_apply_stage_drain(100), DU_BLOCKS);
        ASSERT_EQ(utxo_apply_stage_cursor(), (uint64_t)DU_BLOCKS);
        for (int h = 0; h < DU_BLOCKS; h++) {
            struct block_undo u;
            ASSERT_EQ(du_load(&fx->c, h, &u), UTXO_DELTA_UNDO_FOUND);
            bool exact = du_undo_matches(&u, h);
            bool trip = du_undo_roundtrips(&u, h);
            block_undo_free(&u);
            ASSERT(exact);
            ASSERT(trip);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int du_case_bg_zero_skips(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: bg validation checks every script, zero skips") {
        ASSERT(fx->opened);
        uint64_t from_delta = bg_validation_undo_from_delta_blocks();
        bg_validation_reset_undo_skip_stats();
        for (int h = 0; h < DU_BLOCKS; h++) {
            struct block_index bi;
            du_bg_index(&bi, &fx->c, h);
            int64_t sigs = 0, proofs = 0, skips = 0;
            ASSERT(bg_validation_validate_block_proofs(
                &fx->c.body[h], &bi, fx->dir, fx->cp, 1, 0,
                &sigs, &proofs, &skips));
            ASSERT_EQ(skips, 0);
            ASSERT_EQ(sigs, 3);
        }
        ASSERT_EQ(bg_validation_undo_from_delta_blocks() - from_delta,
                  (uint64_t)DU_BLOCKS);
        ASSERT_EQ(bg_validation_get_undo_skip_stats().blocks, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int du_case_delta_script(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: the delta's scriptPubKey is what gets verified") {
        ASSERT(fx->opened);
        /* Re-author height 0's row as if the spent coins had been locked by
         * OP_FALSE. Present undo must now FAIL the block, not skip it. */
        fx->c.outside_script = DU_OP_FALSE;
        struct delta_summary s;
        memset(&s, 0, sizeof(s));
        utxo_apply_compute_block_delta(&fx->c.body[0], 0, du_lookup, &fx->c,
                                       &s);
        bool computed = s.ok;
        bool persisted = computed &&
            utxo_apply_delta_persist(progress_store_db(), 0, &fx->c.hash[0],
                                     &s);
        if (computed)
            free_delta(&s);
        fx->c.outside_script = DU_OP_TRUE;
        ASSERT(persisted);
        struct block_index bi;
        du_bg_index(&bi, &fx->c, 0);
        int64_t sigs = 0, proofs = 0, skips = 0;
        ASSERT(!bg_validation_validate_block_proofs(
            &fx->c.body[0], &bi, fx->dir, fx->cp, 1, 0,
            &sigs, &proofs, &skips));
        ASSERT_EQ(skips, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int du_case_other_branch(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: a row for another block hash gives no undo") {
        ASSERT(fx->opened);
        ASSERT(du_exec(progress_store_db(),
            "UPDATE utxo_apply_delta SET branch_hash=zeroblob(32) "
            "WHERE height=1"));
        struct block_undo u;
        ASSERT_EQ(du_load(&fx->c, 1, &u), UTXO_DELTA_UNDO_OTHER_BRANCH);
        ASSERT_EQ(u.num_txundo, 0);
        struct block_index bi;
        du_bg_index(&bi, &fx->c, 1);
        bg_validation_reset_undo_skip_stats();
        int64_t sigs = 0, proofs = 0, skips = 0;
        ASSERT(bg_validation_validate_block_proofs(
            &fx->c.body[1], &bi, fx->dir, fx->cp, 1, 0,
            &sigs, &proofs, &skips));
        ASSERT_EQ(skips, 2);
        ASSERT_EQ(sigs, 0);
        ASSERT_EQ(bg_validation_get_undo_skip_stats().blocks, 1);
        bg_validation_reset_undo_skip_stats();
        PASS();
    } _test_next:;
    return failures;
}

static int du_case_input_mismatch(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: a row that does not name the block's inputs is refused") {
        ASSERT(fx->opened);
        struct block other;
        ASSERT(test_block_copy(&other, &fx->c.body[2], "du_other"));
        other.vtx[1].vin[1].prevout.n = 7;
        struct block_undo u;
        enum utxo_apply_delta_undo_status st =
            utxo_apply_delta_block_undo_load(progress_store_db(), 2,
                                             &fx->c.hash[2], &other, &u);
        other.vtx[1].vin[1].prevout.n = 1;
        /* One tx fewer than the row records: its entry is left over. */
        other.num_vtx = 2;
        struct block_undo u2;
        enum utxo_apply_delta_undo_status st2 =
            utxo_apply_delta_block_undo_load(progress_store_db(), 2,
                                             &fx->c.hash[2], &other, &u2);
        other.num_vtx = 3;
        block_free(&other);
        struct block_undo u3;
        enum utxo_apply_delta_undo_status st3 =
            utxo_apply_delta_block_undo_load(progress_store_db(),
                                             DU_BLOCKS + 5, &fx->c.hash[0],
                                             &fx->c.body[0], &u3);
        ASSERT_EQ(st, UTXO_DELTA_UNDO_MISMATCH);
        ASSERT_EQ(u.num_txundo, 0);
        ASSERT_EQ(st2, UTXO_DELTA_UNDO_MISMATCH);
        ASSERT_EQ(u2.num_txundo, 0);
        ASSERT_EQ(st3, UTXO_DELTA_UNDO_ABSENT);
        PASS();
    } _test_next:;
    return failures;
}

/* Hand-encode one spent entry in the delta row's wire format with a
 * caller-chosen value/coinbase byte and no script, to plant fields the real
 * encoder never produces. */
static uint8_t *du_encode_spent_entry(const struct uint256 *txid,
                                      uint32_t vout, int64_t value,
                                      uint8_t coinbase, size_t *out_len)
{
    size_t total = 32 + 4 + 8 + 4 + 1 + 4;
    uint8_t *buf = zcl_malloc(total, "du_spent_entry");
    if (!buf) { *out_len = 0; return NULL; }
    uint8_t *p = buf;
    memcpy(p, txid->data, 32); p += 32;
    zcl_write_u32_le(p, vout); p += 4;
    zcl_write_i64_le(p, value); p += 8;
    zcl_write_u32_le(p, 0); p += 4;   /* height field: unchecked, 0 is fine */
    *p++ = coinbase;
    zcl_write_u32_le(p, 0);          /* script_len = 0 */
    *out_len = total;
    return buf;
}

static bool du_persist_raw_delta(sqlite3 *db, int height,
                                 const struct uint256 *branch_hash,
                                 const uint8_t *spent, size_t spent_len)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta "
            "(height, branch_hash, spent_blob, added_blob) VALUES (?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob(st, 2, branch_hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, spent, (int)spent_len, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, "", 0, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

/* A decoded value outside [0, MAX_MONEY] or a coinbase byte other than 0/1 is
 * a corrupt local row: it must fail closed as MISMATCH (the fold re-derives
 * it), never as a "chain VALIDATION FAILURE". Uses a throwaway height. */
static int du_case_decode_out_of_range(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: an out-of-range value or coinbase byte is refused") {
        ASSERT(fx->opened);
        const int h = DU_BLOCKS + 900;
        struct uint256 branch_hash;
        memset(branch_hash.data, 0x77, sizeof(branch_hash.data));
        struct uint256 prev_txid;
        memset(prev_txid.data, 0x11, sizeof(prev_txid.data));

        struct block blk;
        block_init(&blk);
        blk.vtx = zcl_calloc(2, sizeof(*blk.vtx), "du_bounds_vtx");
        ASSERT(blk.vtx);
        blk.num_vtx = 2;
        ASSERT(du_tx(&blk.vtx[0], 1, 1000));
        outpoint_set_null(&blk.vtx[0].vin[0].prevout);
        ASSERT(du_tx(&blk.vtx[1], 1, 1000));
        blk.vtx[1].vin[0].prevout.hash = prev_txid;
        blk.vtx[1].vin[0].prevout.n = 0;
        ASSERT(transaction_is_coinbase(&blk.vtx[0]));

        size_t len = 0;
        uint8_t *bad_value = du_encode_spent_entry(
            &prev_txid, 0, INT64_MAX, 0, &len);
        ASSERT(bad_value);
        ASSERT(du_persist_raw_delta(progress_store_db(), h, &branch_hash,
                                    bad_value, len));
        free(bad_value);
        struct block_undo u1;
        enum utxo_apply_delta_undo_status st1 =
            utxo_apply_delta_block_undo_load(progress_store_db(), h,
                                             &branch_hash, &blk, &u1);
        ASSERT_EQ(st1, UTXO_DELTA_UNDO_MISMATCH);

        uint8_t *bad_coinbase = du_encode_spent_entry(
            &prev_txid, 0, 1000, 2, &len);
        ASSERT(bad_coinbase);
        ASSERT(du_persist_raw_delta(progress_store_db(), h, &branch_hash,
                                    bad_coinbase, len));
        free(bad_coinbase);
        struct block_undo u2;
        enum utxo_apply_delta_undo_status st2 =
            utxo_apply_delta_block_undo_load(progress_store_db(), h,
                                             &branch_hash, &blk, &u2);
        ASSERT_EQ(st2, UTXO_DELTA_UNDO_MISMATCH);

        uint8_t *good = du_encode_spent_entry(&prev_txid, 0, 1000, 1, &len);
        ASSERT(good);
        ASSERT(du_persist_raw_delta(progress_store_db(), h, &branch_hash,
                                    good, len));
        free(good);
        struct block_undo u3;
        enum utxo_apply_delta_undo_status st3 =
            utxo_apply_delta_block_undo_load(progress_store_db(), h,
                                             &branch_hash, &blk, &u3);
        ASSERT_EQ(st3, UTXO_DELTA_UNDO_FOUND);
        ASSERT_EQ(u3.num_txundo, 1);
        ASSERT(u3.vtxundo[0].vprevout[0].coinbase);

        block_undo_free(&u3);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

/* A stored spent_blob of length zero (SQLite may return a NULL pointer) must
 * not become `NULL + 0` pointer arithmetic. The block carries a shielded-only
 * transaction (no transparent vin) so tx_undo_alloc(0) runs inside build_undo's
 * per-tx loop. */
static int du_case_decode_empty_blob(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: a zero-length spent blob decodes with no undo, no crash") {
        ASSERT(fx->opened);
        const int h = DU_BLOCKS + 901;
        struct uint256 branch_hash;
        memset(branch_hash.data, 0x88, sizeof(branch_hash.data));

        struct block blk;
        block_init(&blk);
        blk.vtx = zcl_calloc(2, sizeof(*blk.vtx), "du_empty_vtx");
        ASSERT(blk.vtx);
        blk.num_vtx = 2;
        ASSERT(du_tx(&blk.vtx[0], 1, 1000));
        outpoint_set_null(&blk.vtx[0].vin[0].prevout);
        ASSERT(transaction_is_coinbase(&blk.vtx[0]));

        transaction_init(&blk.vtx[1]);
        ASSERT(transaction_alloc(&blk.vtx[1], 0, 0));
        ASSERT(!transaction_is_coinbase(&blk.vtx[1]));

        ASSERT(du_persist_raw_delta(progress_store_db(), h, &branch_hash,
                                    (const uint8_t *)"", 0));
        struct block_undo u;
        enum utxo_apply_delta_undo_status st =
            utxo_apply_delta_block_undo_load(progress_store_db(), h,
                                             &branch_hash, &blk, &u);
        ASSERT_EQ(st, UTXO_DELTA_UNDO_FOUND);
        /* One tx_undo entry (the shielded-only tx), with zero prevouts —
         * the loop ran, and correctly found nothing to undo for it. */
        ASSERT_EQ(u.num_txundo, 1);
        ASSERT_EQ(u.vtxundo[0].num_prevout, 0);

        block_undo_free(&u);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

static int du_case_unfolded_store(struct du_fixture *fx)
{
    int failures = 0;
    TEST("delta_undo: a store the fold never touched has no undo") {
        ASSERT(fx->opened);
        sqlite3 *mem = NULL;
        ASSERT(sqlite3_open(":memory:", &mem) == SQLITE_OK);
        struct block_undo u;
        enum utxo_apply_delta_undo_status st =
            utxo_apply_delta_block_undo_load(mem, 0, &fx->c.hash[0],
                                             &fx->c.body[0], &u);
        sqlite3_close(mem);
        uint64_t next = 7;
        bool found = false;
        ASSERT_EQ(st, UTXO_DELTA_UNDO_ABSENT);
        ASSERT(utxo_apply_delta_undo_next_unapplied(progress_store_db(),
                                                    &next, &found));
        ASSERT(found);
        ASSERT_EQ(next, (uint64_t)DU_BLOCKS);
        PASS();
    } _test_next:;
    return failures;
}

/* ── The walk across a branch switch the fold has not caught up with ──
 * Height 1's delta row is stamped with another block (the store's state after
 * an active-chain switch and before the reducer rewinds). The walk must wait
 * that out instead of booking skips, and verify the block once the fold
 * re-applies it. The verifier is the real one, given a parentless copy of the
 * index. */
static struct du_fixture *g_wk_fx;
/* Set right after bg_validation_start so wk_validate can tell a forward-walk
 * call from the always-on sampled re-verify loop's call (they share this
 * stub). */
static struct bg_validation_service *g_wk_svc;
static _Atomic int g_wk_h1_probes;
static _Atomic int g_wk_validate_calls;
static int g_wk_progress = -1;
static int64_t g_wk_version = 0;
static int64_t g_wk_skips = -1;

static bool wk_load_progress(void *self, int *out)
{ (void)self; *out = g_wk_progress; return true; }
static bool wk_save_progress(void *self, int h)
{ (void)self; g_wk_progress = h; return true; }
static bool wk_load_skips(void *self, int64_t *out)
{ (void)self; *out = g_wk_skips; return true; }
static bool wk_save_skips(void *self, int64_t v)
{ (void)self; g_wk_skips = v; return true; }
static bool wk_load_version(void *self, int64_t *out)
{ (void)self; *out = g_wk_version; return true; }
static bool wk_save_version(void *self, int64_t v)
{ (void)self; g_wk_version = v; return true; }

static bool wk_read_body(struct block *out, const struct block_index *bi,
                         const char *datadir)
{
    (void)datadir;
    if (!bi || bi->nHeight < 0 || bi->nHeight >= DU_BLOCKS)
        return false;
    block_free(out);
    return test_block_copy(out, &g_wk_fx->c.body[bi->nHeight], "wk_read");
}

/* The reducer's rewind + re-apply of the active block at h=1. */
static bool wk_reapply_h1(void)
{
    struct delta_summary s;
    memset(&s, 0, sizeof(s));
    utxo_apply_compute_block_delta(&g_wk_fx->c.body[1], 1, du_lookup,
                                   &g_wk_fx->c, &s);
    if (!s.ok)
        return false;
    progress_store_tx_lock();
    bool ok = utxo_apply_delta_persist(progress_store_db(), 1,
                                       &g_wk_fx->c.hash[1], &s);
    progress_store_tx_unlock();
    free_delta(&s);
    return ok;
}

static bool wk_validate(const struct block *block, struct block_index *index,
                        const char *datadir, const struct chain_params *params,
                        int num_workers, size_t max_script_batch,
                        int64_t *sigs_out, int64_t *proofs_out,
                        int64_t *skips_out)
{
    /* Count only the forward walk's own validations, not the sampled
     * re-verify loop's. */
    if (!g_wk_svc || !atomic_load(&g_wk_svc->progress.reverify_active))
        atomic_fetch_add(&g_wk_validate_calls, 1);
    struct block_index parentless = *index;
    parentless.pprev = NULL;
    return bg_validation_validate_block_proofs(
        block, &parentless, datadir, params, num_workers, max_script_batch,
        sigs_out, proofs_out, skips_out);
}

/* The bounded row-probe hook: the walk polls it (no block body, no crypto)
 * before paying for a full validation. The first probe at h=1 reports the
 * stale other-branch row; the second reports the reducer's re-apply resolved,
 * so wk_validate runs exactly once for h=1. */
static const char *wk_row_probe(int h, const struct block_index *pindex)
{
    (void)pindex;
    if (h != 1)
        return NULL;
    if (atomic_fetch_add(&g_wk_h1_probes, 1) == 0)
        return "fold still holds another branch's block";
    if (!wk_reapply_h1())
        return "fold still holds another branch's block";
    return NULL;
}

static void wk_no_sleep(int ms) { (void)ms; }

static int du_case_walk_waits_out_branch_switch(struct du_fixture *fx)
{
    int failures = 0;
    struct bg_validation_service svc;
    memset(&svc, 0, sizeof(svc));
    bool started = false;
    TEST("delta_undo: a branch switch the fold lags is waited out, not booked") {
        ASSERT(fx->opened);
        struct block_undo u;
        ASSERT_EQ(du_load(&fx->c, 1, &u), UTXO_DELTA_UNDO_OTHER_BRANCH);
        g_wk_fx = fx;
        g_wk_svc = &svc;
        atomic_store(&g_wk_h1_probes, 0);
        atomic_store(&g_wk_validate_calls, 0);
        g_wk_progress = -1;
        g_wk_version = 0;
        g_wk_skips = -1;
        svc.ms = &fx->ms;
        svc.datadir = fx->dir;
        svc.params = fx->cp;
        svc.num_workers = 1;
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = wk_load_progress,
            .save_progress = wk_save_progress,
            .load_skips = wk_load_skips,
            .save_skips = wk_save_skips,
            .load_coverage_version = wk_load_version,
            .save_coverage_version = wk_save_version,
        };
        bg_validation_test_set_body_repair_stubs(wk_read_body, NULL);
        bg_validation_test_set_validate_stub(wk_validate);
        bg_validation_test_set_row_backoff_stubs(wk_row_probe, wk_no_sleep);
        started = bg_validation_start(&svc);
        ASSERT(started);
        for (int i = 0; i < 200 &&
             atomic_load(&svc.progress.state) != BG_VALIDATION_COMPLETE &&
             atomic_load(&svc.progress.state) != BG_VALIDATION_FAILED; i++)
            platform_sleep_ms(100);
        /* Stop the service first: the always-on sampled re-verify loop would
         * otherwise re-validate a verified height before the assertions run. */
        ASSERT_EQ(atomic_load(&svc.progress.state), BG_VALIDATION_COMPLETE);
        bg_validation_stop(&svc);
        started = false;
        ASSERT_EQ(atomic_load(&svc.progress.verified_height), DU_BLOCKS - 1);
        /* The first probe saw the other branch, the second the re-apply; full
         * validation for h=1 never ran until the row resolved. */
        ASSERT(atomic_load(&g_wk_h1_probes) >= 2);
        ASSERT_EQ(atomic_load(&svc.progress.script_verif_skipped_no_undo), 0);
        ASSERT_EQ(g_wk_skips, 0);
        ASSERT_EQ(atomic_load(&svc.progress.sigs_verified),
                  (int64_t)(3 * (DU_BLOCKS - 1)));
        /* Exactly one full validation ran for h=1: the wait was served by the
         * cheap probe alone. One call per height, DU_BLOCKS-1 non-genesis
         * heights. */
        ASSERT_EQ(atomic_load(&g_wk_validate_calls), DU_BLOCKS - 1);
        PASS();
    } _test_next:;
    if (started)
        bg_validation_stop(&svc);
    g_wk_svc = NULL;
    bg_validation_test_set_validate_stub(NULL);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    bg_validation_test_set_row_backoff_stubs(NULL, NULL);
    return failures;
}

/* A row that reports "other branch" on EVERY probe. A booked skip is permanent
 * and blocks C6 authority, so the walk must never book here: it keeps polling
 * at a growing, capped backoff, which this stub's recorded wait_ms proves. */
static const char *wk_row_probe_stuck(int h, const struct block_index *pindex)
{
    (void)pindex;
    if (h == 1)
        atomic_fetch_add(&g_wk_h1_probes, 1);
    return h == 1 ? "fold still holds another branch's block" : NULL;
}

/* Records each backoff sleep instead of sleeping, so the test can bound the
 * attempts and prove the requested delay grows. */
static _Atomic int g_wk_stuck_sleep_calls;
static _Atomic int g_wk_stuck_last_wait_ms;
static void wk_capture_sleep(int ms)
{
    atomic_store(&g_wk_stuck_last_wait_ms, ms);
    atomic_fetch_add(&g_wk_stuck_sleep_calls, 1);
}

/* A row that reports "other branch" on every probe, forever. The walk must
 * never book a skip it could not confirm. Proves: no COMPLETE, verified_height
 * never advances past h=0, no skip booked, and the backoff keeps growing. */
static int du_case_walk_row_never_resolves(struct du_fixture *fx)
{
    int failures = 0;
    struct bg_validation_service svc;
    memset(&svc, 0, sizeof(svc));
    bool started = false;
    TEST("delta_undo: a row stuck on another branch never books a skip") {
        ASSERT(fx->opened);
        /* Re-seed h=1 on the wrong branch. */
        ASSERT(du_exec(progress_store_db(),
            "UPDATE utxo_apply_delta SET branch_hash=zeroblob(32) "
            "WHERE height=1"));
        struct block_undo u;
        ASSERT_EQ(du_load(&fx->c, 1, &u), UTXO_DELTA_UNDO_OTHER_BRANCH);
        g_wk_fx = fx;
        g_wk_svc = &svc;
        atomic_store(&g_wk_h1_probes, 0);
        atomic_store(&g_wk_stuck_sleep_calls, 0);
        atomic_store(&g_wk_stuck_last_wait_ms, 0);
        g_wk_progress = -1;
        g_wk_version = 0;
        g_wk_skips = -1;
        svc.ms = &fx->ms;
        svc.datadir = fx->dir;
        svc.params = fx->cp;
        svc.num_workers = 1;
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = wk_load_progress,
            .save_progress = wk_save_progress,
            .load_skips = wk_load_skips,
            .save_skips = wk_save_skips,
            .load_coverage_version = wk_load_version,
            .save_coverage_version = wk_save_version,
        };
        bg_validation_reset_undo_skip_stats();
        bg_validation_test_set_body_repair_stubs(wk_read_body, NULL);
        bg_validation_test_set_validate_stub(wk_validate);
        bg_validation_test_set_row_backoff_stubs(wk_row_probe_stuck,
                                                 wk_capture_sleep);
        started = bg_validation_start(&svc);
        ASSERT(started);
        /* Accumulate a bounded number of backoff attempts; the walk must never
         * reach COMPLETE. */
        for (int i = 0; i < 200 &&
             atomic_load(&g_wk_stuck_sleep_calls) < 6 &&
             atomic_load(&svc.progress.state) != BG_VALIDATION_FAILED; i++)
            platform_sleep_ms(20);
        bg_validation_stop(&svc);
        started = false;
        /* Never reached COMPLETE, never advanced past genesis, never booked
         * the skip it could not confirm. */
        ASSERT(atomic_load(&svc.progress.state) != BG_VALIDATION_COMPLETE);
        ASSERT_EQ(atomic_load(&svc.progress.verified_height), 0);
        ASSERT_EQ(atomic_load(&svc.progress.script_verif_skipped_no_undo), 0);
        ASSERT_EQ(bg_validation_get_undo_skip_stats().blocks, (uint64_t)0);
        /* It retried, and the backoff grows: each attempt sleeps in 1s slices
         * (so shutdown stays responsive), so slice calls outgrow probe attempts
         * once the backoff exceeds 1s. */
        int probes = atomic_load(&g_wk_h1_probes);
        int sleeps = atomic_load(&g_wk_stuck_sleep_calls);
        ASSERT(sleeps >= 2);
        ASSERT(probes >= 2);
        ASSERT(sleeps > probes);
        PASS();
    } _test_next:;
    if (started)
        bg_validation_stop(&svc);
    g_wk_svc = NULL;
    bg_validation_test_set_validate_stub(NULL);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    bg_validation_test_set_row_backoff_stubs(NULL, NULL);
    return failures;
}

/* Fast-forwards the first few backoff calls (no real sleep), then sleeps for
 * real, so a concurrent stop request tests how quickly the walk's sleep
 * notices stop_requested: sliced, this is called many times with ms=1000;
 * unsliced, once with the whole wait. */
static _Atomic int g_wk_stop_test_calls;
static void wk_stop_test_sleep(int ms)
{
    if (atomic_fetch_add(&g_wk_stop_test_calls, 1) < 3)
        return;
    platform_sleep_ms(ms);
}

/* bg_validation_row_backoff must sleep in interruptible slices so
 * bg_validation_stop's pthread_join returns quickly even while the walk sleeps
 * inside a multi-second backoff wait. */
static int du_case_walk_stop_during_backoff(struct du_fixture *fx)
{
    int failures = 0;
    struct bg_validation_service svc;
    memset(&svc, 0, sizeof(svc));
    bool started = false;
    TEST("delta_undo: stop returns quickly even mid-backoff") {
        ASSERT(fx->opened);
        ASSERT(du_exec(progress_store_db(),
            "UPDATE utxo_apply_delta SET branch_hash=zeroblob(32) "
            "WHERE height=1"));
        struct block_undo u;
        ASSERT_EQ(du_load(&fx->c, 1, &u), UTXO_DELTA_UNDO_OTHER_BRANCH);
        g_wk_fx = fx;
        atomic_store(&g_wk_h1_probes, 0);
        atomic_store(&g_wk_stop_test_calls, 0);
        g_wk_progress = -1;
        g_wk_version = 0;
        g_wk_skips = -1;
        svc.ms = &fx->ms;
        svc.datadir = fx->dir;
        svc.params = fx->cp;
        svc.num_workers = 1;
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = wk_load_progress,
            .save_progress = wk_save_progress,
            .load_skips = wk_load_skips,
            .save_skips = wk_save_skips,
            .load_coverage_version = wk_load_version,
            .save_coverage_version = wk_save_version,
        };
        bg_validation_reset_undo_skip_stats();
        bg_validation_test_set_body_repair_stubs(wk_read_body, NULL);
        bg_validation_test_set_validate_stub(wk_validate);
        bg_validation_test_set_row_backoff_stubs(wk_row_probe_stuck,
                                                 wk_stop_test_sleep);
        started = bg_validation_start(&svc);
        ASSERT(started);
        /* Wait past the fast-forwarded calls into a real sleep, then request
         * stop mid-sleep. */
        for (int i = 0; i < 200 && atomic_load(&g_wk_stop_test_calls) < 4; i++)
            platform_sleep_ms(20);
        platform_sleep_ms(300);
        int64_t t0 = platform_time_monotonic_ms();
        bg_validation_stop(&svc);
        started = false;
        int64_t elapsed_ms = platform_time_monotonic_ms() - t0;
        ASSERT(elapsed_ms < 5000);
        PASS();
    } _test_next:;
    if (started)
        bg_validation_stop(&svc);
    bg_validation_test_set_validate_stub(NULL);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    bg_validation_test_set_row_backoff_stubs(NULL, NULL);
    return failures;
}

/* The reorg race: bg_validation_read_body_resilient can swap `pindex` under
 * cs_main between the pre-check probe and the body read (a one-block reorg at
 * the tip). The first read for h=1 returns the pre-reorg body (so the reader's
 * recheck retries) and performs the reorg, moving the window tip onto a block
 * whose delta row was never seeded. Only the sleep is stubbed, so the real
 * bg_validation_row_unresolved_reason post-check must refuse to book. */
static struct du_fixture *g_wk_reorg_fx;
static struct block_index g_wk_reorg_alt_idx;
static struct uint256 g_wk_reorg_alt_hash;
static _Atomic int g_wk_reorg_read_calls;

static bool wk_read_body_reorg(struct block *out, const struct block_index *bi,
                               const char *datadir)
{
    (void)datadir;
    if (!bi || bi->nHeight < 0 || bi->nHeight >= DU_BLOCKS)
        return false;
    if (bi->nHeight == 1 &&
        atomic_fetch_add(&g_wk_reorg_read_calls, 1) == 0) {
        zcl_mutex_lock(&g_wk_reorg_fx->ms.cs_main);
        active_chain_move_window_tip(&g_wk_reorg_fx->ms.chain_active,
                                     &g_wk_reorg_alt_idx);
        zcl_mutex_unlock(&g_wk_reorg_fx->ms.cs_main);
    }
    block_free(out);
    return test_block_copy(out, &g_wk_reorg_fx->c.body[bi->nHeight],
                           "wk_reorg_read");
}

static int du_case_walk_reorg_race(struct du_fixture *fx)
{
    int failures = 0;
    struct bg_validation_service svc;
    memset(&svc, 0, sizeof(svc));
    bool started = false;
    TEST("delta_undo: a reorg between the probe and the body read books "
        "no skip") {
        ASSERT(fx->opened);
        /* Re-seed h=1's row against its original identity. */
        ASSERT(wk_reapply_h1());
        struct block_undo u;
        ASSERT_EQ(du_load(&fx->c, 1, &u), UTXO_DELTA_UNDO_FOUND);
        block_undo_free(&u);

        g_wk_fx = fx;
        g_wk_reorg_fx = fx;
        memset(g_wk_reorg_alt_hash.data, 0x77,
               sizeof(g_wk_reorg_alt_hash.data));
        g_wk_reorg_alt_idx = fx->c.idx[1];
        g_wk_reorg_alt_idx.phashBlock = &g_wk_reorg_alt_hash;
        atomic_store(&g_wk_reorg_read_calls, 0);
        atomic_store(&g_wk_stuck_sleep_calls, 0);
        g_wk_progress = -1;
        g_wk_version = 0;
        g_wk_skips = -1;
        svc.ms = &fx->ms;
        svc.datadir = fx->dir;
        svc.params = fx->cp;
        svc.num_workers = 1;
        svc.progress_store = (struct bg_validation_store_port) {
            .self = &svc,
            .load_progress = wk_load_progress,
            .save_progress = wk_save_progress,
            .load_skips = wk_load_skips,
            .save_skips = wk_save_skips,
            .load_coverage_version = wk_load_version,
            .save_coverage_version = wk_save_version,
        };
        bg_validation_reset_undo_skip_stats();
        bg_validation_test_set_body_repair_stubs(wk_read_body_reorg, NULL);
        /* Real validate function and row probe (only the sleep is stubbed). */
        bg_validation_test_set_row_backoff_stubs(NULL, wk_capture_sleep);
        started = bg_validation_start(&svc);
        ASSERT(started);
        /* The reorged identity's row never resolves, so wait for a bounded
         * number of backoff attempts instead of COMPLETE. */
        for (int i = 0; i < 200 &&
             atomic_load(&g_wk_stuck_sleep_calls) < 4 &&
             atomic_load(&svc.progress.state) != BG_VALIDATION_FAILED; i++)
            platform_sleep_ms(20);
        bg_validation_stop(&svc);
        started = false;
        ASSERT(atomic_load(&g_wk_reorg_read_calls) >= 2);
        /* The reorg happened (read called at least twice for h=1), and the
         * post-check refused to book the reorged identity's unresolved row: no
         * skip, no advance past genesis, never COMPLETE. */
        ASSERT_EQ(atomic_load(&svc.progress.script_verif_skipped_no_undo), 0);
        ASSERT_EQ(atomic_load(&svc.progress.verified_height), 0);
        ASSERT(atomic_load(&svc.progress.state) != BG_VALIDATION_COMPLETE);
        PASS();
    } _test_next:;
    if (started)
        bg_validation_stop(&svc);
    bg_validation_test_set_body_repair_stubs(NULL, NULL);
    bg_validation_test_set_row_backoff_stubs(NULL, NULL);
    return failures;
}

static int test_delta_undo_forward_record(const struct chain_params *cp)
{
    struct du_fixture fx;
    memset(&fx, 0, sizeof(fx));
    fx.cp = cp;
    test_make_tmpdir(fx.dir, sizeof(fx.dir), "delta_undo", "forward");
    int failures = du_case_record(&fx);
    failures += du_case_bg_zero_skips(&fx);
    failures += du_case_delta_script(&fx);
    failures += du_case_other_branch(&fx);
    failures += du_case_input_mismatch(&fx);
    failures += du_case_decode_out_of_range(&fx);
    failures += du_case_decode_empty_blob(&fx);
    failures += du_case_unfolded_store(&fx);
    failures += du_case_walk_waits_out_branch_switch(&fx);
    failures += du_case_walk_row_never_resolves(&fx);
    failures += du_case_walk_stop_during_backoff(&fx);
    failures += du_case_walk_reorg_race(&fx);
    if (fx.opened)
        du_close(&fx.ms);
    if (fx.built)
        du_chain_free(&fx.c);
    (void)test_rm_rf_recursive(fx.dir);
    return failures;
}

#if !defined(_WIN32)
/* Die, as kill -9 would, on the Nth commit of the store connection: the
 * hook runs before the commit record reaches the WAL, so the transaction
 * that was about to land is lost exactly as in a power cut. */
static int g_du_commit_countdown;

static int du_die_on_commit(void *user)
{
    (void)user;
    if (--g_du_commit_countdown == 0)
        raise(SIGKILL);
    return 0;
}

static void du_child_fold(const char *dir, const struct chain_params *cp,
                          int die_at_commit)
{
    struct du_chain c;
    struct main_state ms;
    if (!du_chain_build(&c, cp) || !du_open(dir, &ms, &c))
        _exit(3);
    g_du_commit_countdown = die_at_commit;
    sqlite3_commit_hook(progress_store_db(), du_die_on_commit, NULL);
    /* One height per drain: each block is its own commit, so the crash
     * points fall between blocks as well as inside one. */
    for (int i = 0; i < DU_BLOCKS; i++)
        (void)utxo_apply_stage_drain(1);
    sqlite3_commit_hook(progress_store_db(), NULL, NULL);
    _exit(utxo_apply_stage_cursor() == DU_BLOCKS ? 0 : 4);
}

/* After a crash: heights below the durable cursor have their exact undo,
 * heights at/above it have none. */
static bool du_crash_invariant(const struct du_chain *c, uint64_t *next_out)
{
    bool found = false;
    if (!utxo_apply_delta_undo_next_unapplied(progress_store_db(), next_out,
                                              &found))
        return false;
    uint64_t next = found ? *next_out : 0;
    for (int h = 0; h < DU_BLOCKS; h++) {
        struct block_undo u;
        enum utxo_apply_delta_undo_status st = du_load(c, h, &u);
        bool exact = st == UTXO_DELTA_UNDO_FOUND && du_undo_matches(&u, h);
        block_undo_free(&u);
        if ((uint64_t)h < next ? !exact : st != UTXO_DELTA_UNDO_ABSENT) {
            printf("[du] h=%d next=%llu status=%s\n", h,
                   (unsigned long long)next,
                   utxo_apply_delta_undo_status_name(st));
            return false;
        }
    }
    return true;
}

/* One crash round: fold in a child that dies at commit `k`, then reopen the
 * datadir (running the stage's startup recovery), check the crash invariant,
 * finish the fold and check it again. */
struct du_round {
    bool died;
    bool completed;
    uint64_t durable_next;  /* the cursor the kill left behind */
};

static bool du_kill_round(const struct chain_params *cp, int k,
                          struct du_round *r)
{
    char dir[256];
    char tag[32];
    snprintf(tag, sizeof(tag), "kill9_%d", k);
    test_make_tmpdir(dir, sizeof(dir), "delta_undo", tag);
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0)
        du_child_fold(dir, cp, k);
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        return false;
    r->died = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    r->completed = WIFEXITED(status) && WEXITSTATUS(status) == 0;

    struct du_chain c;
    struct main_state ms;
    bool built = du_chain_build(&c, cp);
    bool opened = built && du_open(dir, &ms, &c);
    bool before = opened && du_crash_invariant(&c, &r->durable_next);
    bool advanced = opened && utxo_apply_stage_drain(100) >= 0;
    uint64_t next = 0;
    bool after = advanced && du_crash_invariant(&c, &next) &&
                 next == DU_BLOCKS;
    if (opened)
        du_close(&ms);
    du_chain_free(&c);
    (void)test_rm_rf_recursive(dir);
    return (r->died || r->completed) && before && after;
}

static int test_delta_undo_kill9(const struct chain_params *cp)
{
    int failures = 0;

    TEST("delta_undo: kill -9 at every fold commit keeps undo exact") {
        int killed = 0;
        unsigned crash_fronts = 0;  /* durable cursors seen after a kill */
        bool completed = false;
        for (int k = 1; k <= 64 && !completed; k++) {
            struct du_round r = {0};
            bool held = du_kill_round(cp, k, &r);
            if (!held)
                printf("[du] crash round k=%d broke the invariant ", k);
            ASSERT(held);
            completed = r.completed;
            killed += r.died ? 1 : 0;
            if (r.died && r.durable_next < 32)
                crash_fronts |= 1u << r.durable_next;
        }
        /* The loop must have crossed every commit and then run clean. */
        ASSERT(completed);
        ASSERT(killed >= DU_BLOCKS);
        /* ...and a kill landed with each of 0, 1 and 2 blocks durable. */
        ASSERT_EQ(crash_fronts & ((1u << DU_BLOCKS) - 1u),
                  (1u << DU_BLOCKS) - 1u);
        printf("(%d crash points) ", killed);
        PASS();
    } _test_next:;
    return failures;
}
#else
static int test_delta_undo_kill9(const struct chain_params *cp)
{
    (void)cp;
    printf("delta_undo: kill -9 SKIP (Windows has no fork/SIGKILL)\n");
    return 0;
}
#endif

int test_bg_validation_delta_undo(void)
{
    printf("\n=== bg_validation delta undo ===\n");
    int failures = 0;
    blocker_module_init();
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    if (!cp) {
        printf("delta_undo: regtest params unavailable... FAIL\n");
        chain_params_select(CHAIN_MAIN);
        return 1;
    }
    failures += test_delta_undo_forward_record(cp);
    failures += test_delta_undo_kill9(cp);
    chain_params_select(CHAIN_MAIN);
    return failures;
}
