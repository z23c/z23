/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_reducer_ingest_e2e - in-process end-to-end proof of the reducer
 * ingest path: tip_finalize moves the in-memory active-chain window,
 * utxo_apply authors the UTXO projection plus the per-block inverse delta
 * and drives reorg unwind, and tip_finalize runs post-finalize side effects.
 *
 * Equihash constraint: reducer_ingest_block's first gate is check_block with
 * check_pow=true, which always verifies a real Equihash 200,9 solution, so
 * no synthetic block passes it. The accept / invalid-UTXO / reorg scenarios
 * therefore drive the real stage drains (as reducer_drain_to_convergence
 * does) with no stubbed verification, and one case calls the literal
 * reducer_ingest_block() to assert a no-Equihash block is rejected.
 *
 * The UTXO delta, reorg inverse delta and SHA3-256 projection commitment are
 * real; only the upstream proof_validate cursor/log is seeded (covered in
 * its own suites, as in test_stage_reorg_unwind_parity).
 */

#include "test/test_core.h"
#include "test/test_block_map.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "services/chain_activation_service.h"
#include "services/reducer_ingest_service.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RIE_CHECK(name, expr) do {                       \
    printf("reducer_ingest_e2e: %s... ", (name));        \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* ── External base coins (the pre-fork UTXO set the spends consume) ──── */

struct rie_ext_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    uint32_t height;
    bool is_coinbase;
    uint8_t script[8];
    uint32_t script_len;
};

/* One branch: real bodies + hashes + block_index entries (index by height,
 * 0 == genesis). */
struct rie_branch {
    struct block       *bodies;
    struct uint256     *hashes;
    struct block_index *blocks;
    int n;
};

/* ── tmp-dir helpers ─────────────────────────────────────────────────── */

static int rie_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── Real block builders (mirror test_stage_reorg_unwind_parity) ─────── */

static void cb_txid(struct uint256 *out, uint8_t branch_tag, int h)
{
    uint256_set_null(out);
    out->data[0] = 0xC0;
    out->data[1] = branch_tag;
    out->data[2] = (uint8_t)h;
}

static void spend_txid(struct uint256 *out, uint8_t branch_tag, int h)
{
    uint256_set_null(out);
    out->data[0] = 0x5E;
    out->data[1] = branch_tag;
    out->data[2] = (uint8_t)h;
}

static void make_coinbase(struct transaction *tx, uint8_t branch_tag, int h)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    /* BIP34-style embedded height as a minimal CScriptNum push; the
     * coinbase-label check reads it back at finalize. */
    {
        uint8_t sig[6];
        uint8_t num[4];
        size_t nl = 0;
        int hh = h;
        while (hh > 0) { num[nl++] = (uint8_t)(hh & 0xff); hh >>= 8; }
        if (nl > 0 && (num[nl - 1] & 0x80)) num[nl++] = 0x00;
        sig[0] = (uint8_t)nl;
        memcpy(sig + 1, num, nl);
        script_set(&tx->vin[0].script_sig, sig, nl + 1);
    }
    tx->vout[0].value = 1000000000LL + h;
    uint8_t pk[3] = { 0x76, 0xa9, (uint8_t)(0x10 + h) };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    cb_txid(&tx->hash, branch_tag, h);
}

/* A spend tx that consumes external coin `ext` and creates one output. */
static void make_spend(struct transaction *tx, uint8_t branch_tag, int h,
                       const struct rie_ext_coin *ext)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    tx->vin[0].prevout.hash = ext->txid;
    tx->vin[0].prevout.n = ext->vout;
    tx->vout[0].value = ext->value - 1000; /* fee */
    uint8_t pk[4] = { 0x76, 0xa9, 0xBB, branch_tag };
    script_set(&tx->vout[0].script_pub_key, pk, 4);
    spend_txid(&tx->hash, branch_tag, h);
}

/* A spend of a non-existent coin (invalid-block case): compute_block_delta
 * rejects with spend_unknown_utxo. */
static void make_bad_spend(struct transaction *tx, uint8_t branch_tag, int h)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    uint256_set_null(&tx->vin[0].prevout.hash);
    tx->vin[0].prevout.hash.data[0] = 0xDE; /* outpoint that exists nowhere */
    tx->vin[0].prevout.hash.data[1] = 0xAD;
    tx->vin[0].prevout.n = 7;
    tx->vout[0].value = 1;
    uint8_t pk[4] = { 0x76, 0xa9, 0xCC, branch_tag };
    script_set(&tx->vout[0].script_pub_key, pk, 4);
    spend_txid(&tx->hash, branch_tag, h);
}

static void finalize_block(struct block *b, int h)
{
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    struct uint256 *leaves =
        zcl_calloc(b->num_vtx, sizeof(struct uint256), "rie_leaves");
    for (size_t i = 0; i < b->num_vtx; i++) leaves[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(leaves, b->num_vtx);
    free(leaves);
}

/* Build one branch. spend kind: 0 = none, 1 = spend ext, 2 = bad spend.
 * Genesis at height 0; nChainWork strictly increases (work monotonicity). */
static bool branch_build(struct rie_branch *br, uint8_t tag, int n,
                         int spend_at, int spend_kind,
                         const struct rie_ext_coin *ext)
{
    memset(br, 0, sizeof(*br));
    br->n = n;
    br->bodies = zcl_calloc((size_t)n, sizeof(struct block), "rie_bodies");
    br->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "rie_hashes");
    br->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "rie_blocks");
    if (!br->bodies || !br->hashes || !br->blocks) return false;

    for (int h = 0; h < n; h++) {
        struct block *b = &br->bodies[h];
        block_init(b);
        bool has_spend = (h == spend_at && spend_kind != 0);
        b->num_vtx = has_spend ? 2u : 1u;
        b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "rie_vtx");
        if (!b->vtx) return false;
        uint8_t cbtag = (h == 0) ? 0x00 : tag;
        make_coinbase(&b->vtx[0], cbtag, h);
        if (has_spend) {
            if (spend_kind == 1) make_spend(&b->vtx[1], tag, h, ext);
            else                 make_bad_spend(&b->vtx[1], tag, h);
        }
        finalize_block(b, h);

        block_header_get_hash(&b->header, &br->hashes[h]);
        block_index_init(&br->blocks[h]);
        br->blocks[h].phashBlock = &br->hashes[h];
        br->blocks[h].nHeight = h;
        br->blocks[h].nVersion = 4;
        br->blocks[h].nTime = b->header.nTime;
        br->blocks[h].nBits = b->header.nBits;
        br->blocks[h].nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        arith_uint256_set_u64(&br->blocks[h].nChainWork, (uint64_t)h + 1);
        if (h > 0) br->blocks[h].pprev = &br->blocks[h - 1];
    }
    return true;
}

static void branch_free(struct rie_branch *br)
{
    if (br->bodies)
        for (int h = 0; h < br->n; h++) block_free(&br->bodies[h]);
    free(br->bodies);
    free(br->hashes);
    free(br->blocks);
    memset(br, 0, sizeof(*br));
}

/* ── Stage plumbing: reader + lookup over the external base set ──────── */

struct rie_ctx {
    struct rie_branch *active;
    const struct rie_ext_coin *ext;
    int n_ext;
};

static bool block_copy(struct block *dst, const struct block *src)
{
    block_init(dst);
    dst->header = src->header;
    dst->num_vtx = src->num_vtx;
    if (src->num_vtx == 0) return true;
    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction), "rie_copy");
    if (!dst->vtx) return false;
    for (size_t i = 0; i < src->num_vtx; i++) {
        transaction_init(&dst->vtx[i]);
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i])) return false;
    }
    return true;
}

static bool rie_reader(struct block *out, const struct block_index *bi,
                       const char *datadir, void *user)
{
    (void)datadir;
    struct rie_ctx *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= c->active->n)
        return false;
    return block_copy(out, &c->active->bodies[bi->nHeight]);
}

static bool rie_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    struct rie_ctx *c = user;
    memset(out, 0, sizeof(*out));
    if (!c) return true;
    for (int i = 0; i < c->n_ext; i++) {
        const struct rie_ext_coin *e = &c->ext[i];
        if (e->vout == vout && uint256_eq(&e->txid, txid)) {
            out->found = true;
            out->value = e->value;
            out->height = e->height;
            out->is_coinbase = e->is_coinbase;
            out->script_len = e->script_len;
            memcpy(out->script, e->script, e->script_len);
            return true;
        }
    }
    return true; /* not found */
}

/* ── Exact upstream evidence seeding (covered by stage suites) ── */

static bool rie_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool rie_create_seed_tables(sqlite3 *db)
{
    if (!rie_exec(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL)") ||
        !rie_exec(db,
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  ok INTEGER NOT NULL, fail_reason TEXT,"
        "  validated_at INTEGER NOT NULL)") ||
        !rie_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)") ||
        !rie_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB)"))
        return false;
    return true;
}

static bool rie_seed_proof_rows(sqlite3 *db, const struct rie_branch *br,
                                int through_height)
{
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *script_st = NULL;
    sqlite3_stmt *header_st = NULL;
    sqlite3_stmt *validate_st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total,"
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 0,0,0,?,1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, block_hash) "
        "VALUES (?, 'verified', 1, 0,0,1,?)",
        -1, &script_st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return false;
    }
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO header_admit_log "
        "(height, hash, parent_hash, admitted_at) VALUES (?, ?, ?, 1)",
        -1, &header_st, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO validate_headers_log "
        "(height, hash, ok, fail_reason, validated_at) "
        "VALUES (?, ?, 1, NULL, 1)",
        -1, &validate_st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        sqlite3_finalize(script_st);
        sqlite3_finalize(header_st);
        sqlite3_finalize(validate_st);
        return false;
    }
    for (int h = 0; h <= through_height; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, br->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
            sqlite3_finalize(header_st);
            sqlite3_finalize(validate_st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(script_st, 1, h);
        sqlite3_bind_blob(script_st, 2, br->hashes[h].data, 32,
                          SQLITE_STATIC);
        if (sqlite3_step(script_st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
            sqlite3_finalize(header_st);
            sqlite3_finalize(validate_st);
            return false;
        }
        sqlite3_reset(script_st);
        sqlite3_clear_bindings(script_st);

        sqlite3_bind_int(header_st, 1, h);
        sqlite3_bind_blob(header_st, 2, br->hashes[h].data, 32,
                          SQLITE_STATIC);
        if (h > 0)
            sqlite3_bind_blob(header_st, 3, br->hashes[h - 1].data, 32,
                              SQLITE_STATIC);
        else
            sqlite3_bind_null(header_st, 3);
        sqlite3_bind_int(validate_st, 1, h);
        sqlite3_bind_blob(validate_st, 2, br->hashes[h].data, 32,
                          SQLITE_STATIC);
        if (sqlite3_step(header_st) != SQLITE_DONE ||
            sqlite3_step(validate_st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
            sqlite3_finalize(header_st);
            sqlite3_finalize(validate_st);
            return false;
        }
        sqlite3_reset(header_st);
        sqlite3_clear_bindings(header_st);
        sqlite3_reset(validate_st);
        sqlite3_clear_bindings(validate_st);
    }
    sqlite3_finalize(st);
    sqlite3_finalize(script_st);
    sqlite3_finalize(header_st);
    sqlite3_finalize(validate_st);
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('proof_validate', ?, 1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, through_height + 1);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_proof_validate(sqlite3 *db, const struct rie_branch *br,
                                int through_height)
{
    if (!db || !br || through_height < 0 || through_height >= br->n)
        return false;
    return rie_create_seed_tables(db) &&
           rie_seed_proof_rows(db, br, through_height);
}

/* Read the tip_finalize_log status string at `height`; false if no row. */
static bool tf_log_status_at(sqlite3 *db, int height,
                             char *out, size_t out_sz)
{
    if (out && out_sz) out[0] = 0;
    sqlite3_stmt *st = NULL;
    if (!db || sqlite3_prepare_v2(db,
        "SELECT status FROM tip_finalize_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(st, 0);
        if (txt && out && out_sz) snprintf(out, out_sz, "%s", (const char *)txt);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

/* The highest height with a "finalized" tip_finalize_log row, or -1
 * (distinct from g_last_advance_height, which also advances over rejected
 * heights). */
static int tf_max_finalized_height(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (!db || sqlite3_prepare_v2(db,
        "SELECT COALESCE(MAX(height), -1) FROM tip_finalize_log "
        "WHERE status = 'finalized'", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int h = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        h = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return h;
}

/* Running cumulative coin count for tip_finalize's utxo_count_diverged
 * check (added - spent over utxo_apply_log). */
struct rie_counter_ctx { int64_t base_count; };
static bool rie_utxo_counter(int height_after, int64_t *out_count, void *user)
{
    sqlite3 *db = progress_store_db();
    struct rie_counter_ctx *cc = user;
    int64_t added = 0, spent = 0;
    sqlite3_stmt *st = NULL;
    if (db && sqlite3_prepare_v2(db,
        "SELECT COALESCE(SUM(added_count),0), COALESCE(SUM(spent_count),0) "
        "FROM utxo_apply_log WHERE ok=1 AND height < ?", -1, &st, NULL)
        == SQLITE_OK) {
        sqlite3_bind_int(st, 1, height_after);
        if (sqlite3_step(st) == SQLITE_ROW) {
            added = sqlite3_column_int64(st, 0);
            spent = sqlite3_column_int64(st, 1);
        }
        sqlite3_finalize(st);
    }
    *out_count = (cc ? cc->base_count : 0) + added - spent;
    return true;
}

/* Drive the eight-stage drain as reducer_drain_to_convergence does for the
 * stages this test owns: utxo_apply then tip_finalize, looping to
 * convergence. The upstream five stages are seeded via
 * proof_validate_log/cursor. */
static int rie_drain_to_convergence(void)
{
    int total = 0;
    for (int round = 0; round < 64; round++) {
        int adv = 0;
        adv += utxo_apply_stage_drain(100);
        adv += tip_finalize_stage_drain(100);
        total += adv;
        if (adv == 0) break;
    }
    return total;
}

/* Seed the pre-fork base UTXO set into coins_kv, the authoritative UTXO
 * store. Seeding coins_kv keeps reorg runs symmetric: a base coin spent on
 * the loser and restored on unwind matches a direct build. */
static void seed_base_coins(sqlite3 *pdb, const struct rie_ext_coin *ext, int n)
{
    (void)coins_kv_ensure_schema(pdb);
    for (int i = 0; i < n; i++) {
        const struct rie_ext_coin *e = &ext[i];
        (void)coins_kv_add(pdb, e->txid.data, e->vout, e->value,
                           (int32_t)e->height, e->is_coinbase,
                           e->script_len ? e->script : NULL, e->script_len);
    }
}

/* ── A reusable environment for one reducer-ingest run ───────────────── */

struct rie_env {
    char dir[256];
    event_log_t *lg;
    struct main_state ms;
    struct rie_ctx ctx;
    struct rie_counter_ctx cc;
    bool ok;
};

/* Open progress/log, init the active chain + stages, seed the base coins,
 * and install the reader/lookup over `active`. */
static bool rie_env_open(struct rie_env *e, const char *tag,
                         struct rie_branch *active,
                         const struct rie_ext_coin *ext, int n_ext)
{
    memset(e, 0, sizeof(*e));
    test_make_tmpdir(e->dir, sizeof(e->dir), "reducer_ingest_e2e", tag);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/events.log", e->dir);

    progress_store_close();
    if (!progress_store_open(e->dir)) return false;
    e->lg = event_log_open(log_path);
    if (!e->lg) return false;

    seed_base_coins(progress_store_db(), ext, n_ext);

    active_chain_init(&e->ms.chain_active);
    block_map_init(&e->ms.map_block_index);

    e->ctx.active = active;
    e->ctx.ext = ext;
    e->ctx.n_ext = n_ext;
    /* utxo_count_diverged compares the live count after H against the
     * stage's cumulative per-block sums, which exclude seeded base coins,
     * so the counter base is 0. */
    e->cc.base_count = 0;

    if (!utxo_apply_stage_init(&e->ms)) return false;
    utxo_apply_stage_set_reader(rie_reader, &e->ctx);
    utxo_apply_stage_set_lookup(rie_lookup, &e->ctx);
    if (!tip_finalize_stage_init(&e->ms)) return false;
    tip_finalize_stage_set_utxo_counter(rie_utxo_counter, &e->cc);

    e->ok = true;
    return true;
}

static void rie_env_close(struct rie_env *e)
{
    tip_finalize_stage_shutdown();
    utxo_apply_stage_shutdown();
    active_chain_free(&e->ms.chain_active);
    block_map_free(&e->ms.map_block_index);
    if (e->lg) event_log_close(e->lg);
    progress_store_close();
    test_cleanup_tmpdir(e->dir);
    memset(e, 0, sizeof(*e));
}

/* Register a branch's block_index entries in the block map and install the
 * candidate tip into chain[] (the extension tip_finalize needs to read
 * active_chain_at(H+1)). Returns the tip block_index. */
static struct block_index *install_branch(struct rie_env *e,
                                          struct rie_branch *br)
{
    for (int h = 0; h < br->n; h++)
        test_block_map_insert(&e->ms.map_block_index, br->blocks[h].phashBlock,
                         &br->blocks[h]);
    active_chain_move_window_tip(&e->ms.chain_active, &br->blocks[br->n - 1]);
    return &br->blocks[br->n - 1];
}

/* ── Test ─────────────────────────────────────────────────────────────── */
static int rie_check_front_door(void)
{
    /* Front door: reducer_ingest_block rejects bad PoW. A synthetic block
     * can never pass the stateless Equihash gate, so accept is driven at
     * the stage level. */
    int failures = 0;
    RIE_CHECK("front-door: reducer is authoritative",
              reducer_is_authoritative());

    struct rie_branch B;
    bool b = branch_build(&B, 0x33, 2, -1, 0, NULL);
    RIE_CHECK("front-door: branch builds", b);
    if (b) {
        struct validation_state vs;
        bool acc = reducer_ingest_block(boot_activation_controller(),
                                        &B.bodies[1], REDUCER_SRC_P2P,
                                        false, &vs);
        RIE_CHECK("front-door: synthetic block fails stateless Equihash",
                  !acc && !validation_state_is_valid(&vs));
        RIE_CHECK("front-door: failed verdict is not valid",
                  !validation_state_is_valid(&vs));
    }
    branch_free(&B);
    return failures;
}

static int rie_run_accept_scenario(const struct rie_ext_coin *ext)
{
    /* SCENARIO 1: a valid block is ingested. Genesis + two coinbase blocks;
     * the stage drain must advance the in-mem tip to the top block and
     * reflect every coinbase in the UTXO projection.
     * tip_finalize looks ahead one block (new_tip = active_chain_at(H+1)),
     * so an n-height chain finalizes 0..n-2 and the tip sits at n-1. */
    int failures = 0;
    const int N = 3;                /* genesis h0 + h1 + h2 */
    struct rie_branch C;
    bool built = branch_build(&C, 0x44, N, -1, 0, NULL);
    RIE_CHECK("accept: chain builds", built);

    struct rie_env e;
    bool opened = built && rie_env_open(&e, "accept", &C, ext, 2);
    RIE_CHECK("accept: env opens", opened);

    if (opened) {
        struct block_index *want_tip = install_branch(&e, &C);

        RIE_CHECK("accept: seed proof_validate through tip",
                  seed_proof_validate(progress_store_db(), &C, C.n - 1));

        int adv = rie_drain_to_convergence();
        RIE_CHECK("accept: reducer drain advanced", adv >= C.n - 1);

        /* Runtime seed-anchor re-seed is loud: reducer_ingest_try_seed_anchor
         * LOG_WARNs and counts a failure without aborting ingest.
         *   - Forced failure: height<0 hits the arg guard, counted.
         *   - Healthy re-seed of genesis after the drain is a monotonic
         *     idempotent no-op and must not trip the counter. */
        {
            uint64_t before =
                reducer_ingest_seed_anchor_reseed_failure_count();
            uint8_t dummy_hash[32] = {0};
            reducer_ingest_try_seed_anchor(-1, dummy_hash,
                                           "unit-forced-failure");
            RIE_CHECK("seed-anchor: forced failure is counted",
                      reducer_ingest_seed_anchor_reseed_failure_count()
                          == before + 1);

            reducer_ingest_try_seed_anchor(0, C.blocks[0].phashBlock->data,
                                           "unit-healthy-reseed");
            RIE_CHECK("seed-anchor: healthy re-seed does not increment",
                      reducer_ingest_seed_anchor_reseed_failure_count()
                          == before + 1);
        }

        /* Every valid height below the top is finalized (lookahead 0..n-2). */
        RIE_CHECK("accept: tip_finalize cursor at n-1",
                  tip_finalize_stage_cursor() == (uint64_t)(C.n - 1));
        /* The reducer drove the in-mem tip to the top block; the
         * highest finalized height is n-2 (lookahead). */
        struct block_index *tip = active_chain_tip(&e.ms.chain_active);
        RIE_CHECK("accept: in-mem tip is the top ingested block (keystone)",
                  tip == want_tip && tip->nHeight == C.n - 1);
        RIE_CHECK("accept: highest finalized height is n-2 (lookahead)",
                  tf_max_finalized_height(progress_store_db()) == C.n - 2);
        char status[32];
        RIE_CHECK("accept: h1 finalized (not rejected)",
                  tf_log_status_at(progress_store_db(), 1,
                                   status, sizeof(status)) &&
                  strcmp(status, "finalized") == 0);

        /* coins_kv reflects all three coinbases. */
        sqlite3 *pdb = progress_store_db();
        bool all_cb_live = true;
        for (int h = 0; h < C.n; h++) {
            struct uint256 cb;
            cb_txid(&cb, (h == 0) ? 0x00 : 0x44, h);
            if (!coins_kv_exists(pdb, cb.data, 0))
                all_cb_live = false;
        }
        RIE_CHECK("accept: every ingested coinbase live in coins_kv",
                  all_cb_live);
        RIE_CHECK("accept: utxo_apply recorded no spend-unknown",
                  utxo_apply_stage_spend_unknown_total() == 0);

        rie_env_close(&e);
    }
    branch_free(&C);
    return failures;
}

static int rie_run_invalid_scenario(const struct rie_ext_coin *ext)
{
    /* SCENARIO 2: an invalid block is rejected and the chain does not
     * progress past it. Genesis h0 + valid h1 + invalid h2 (spends a coin
     * in no UTXO set). compute_block_delta rejects h2, so utxo_apply
     * finalizes h1 and holds its cursor at h2 with a typed blocker.
     * h2 is never finalized and its outputs are never applied. */
    int failures = 0;
    const int N = 3;                /* genesis h0 + valid h1 + bad h2 */
    struct rie_branch D;
    bool built = branch_build(&D, 0x55, N, 2 /*spend_at=h2*/, 2 /*bad*/,
                              NULL);
    RIE_CHECK("invalid: chain builds", built);

    struct rie_env e;
    bool opened = built && rie_env_open(&e, "invalid", &D, ext, 2);
    RIE_CHECK("invalid: env opens", opened);

    if (opened) {
        (void)install_branch(&e, &D);

        RIE_CHECK("invalid: seed proof_validate through tip",
                  seed_proof_validate(progress_store_db(), &D, D.n - 1));

        (void)rie_drain_to_convergence();

        /* The real UTXO consensus check caught the unknown spend at h2. */
        RIE_CHECK("invalid: utxo_apply flagged spend-unknown",
                  utxo_apply_stage_spend_unknown_total() >= 1);

        /* The valid h1 IS finalized; the invalid h2 is NEVER finalized. */
        char s1[32] = {0}, s2[32] = {0};
        bool h1_row = tf_log_status_at(progress_store_db(), 1,
                                       s1, sizeof(s1));
        bool h2_row = tf_log_status_at(progress_store_db(), 2,
                                       s2, sizeof(s2));
        RIE_CHECK("invalid: valid h1 was finalized",
                  h1_row && strcmp(s1, "finalized") == 0);
        RIE_CHECK("invalid: invalid h2 NOT finalized (upstream_failed)",
                  (!h2_row) || strcmp(s2, "finalized") != 0);
        RIE_CHECK("invalid: utxo_apply cursor held at rejected h2",
                  utxo_apply_stage_cursor() == 2);
        RIE_CHECK("invalid: typed blocker records rejected h2",
                  blocker_exists("utxo_apply.apply_failed"));
        /* The highest finalized height is the valid h1, never h2. */
        RIE_CHECK("invalid: highest finalized height is the valid h1",
                  tf_max_finalized_height(progress_store_db()) == 1);

        /* The invalid block's spend output is absent from the UTXO set. */
        sqlite3 *pdb = progress_store_db();
        struct uint256 bad_out;
        spend_txid(&bad_out, 0x55, 2);
        RIE_CHECK("invalid: rejected spend output absent from coins_kv",
                  !coins_kv_exists(pdb, bad_out.data, 0));
        /* h2's coinbase is also absent (its whole delta was rejected). */
        struct uint256 bad_cb;
        cb_txid(&bad_cb, 0x55, 2);
        RIE_CHECK("invalid: rejected block coinbase absent from coins_kv",
                  !coins_kv_exists(pdb, bad_cb.data, 0));
        blocker_clear("utxo_apply.apply_failed");

        rie_env_close(&e);
    }
    branch_free(&D);
    return failures;
}

static int rie_run_reorg_incremental(const struct rie_ext_coin *ext,
                                     struct rie_branch *L,
                                     struct rie_branch *W, uint8_t *cA,
                                     uint64_t *countA, bool *haveA,
                                     int *l_only_absent)
{
    int failures = 0;
    struct rie_env e;
    bool opened = rie_env_open(&e, "reorg_a", L, ext, 2);
    RIE_CHECK("reorg A: env opens", opened);
    if (opened) {
        (void)install_branch(&e, L);
        RIE_CHECK("reorg A: seed L proof_validate",
                  seed_proof_validate(progress_store_db(), L,
                                      L->n - 1));
        int advL = rie_drain_to_convergence();
        RIE_CHECK("reorg A: L drained to tip", advL >= L->n);
        struct block_index *tipL = active_chain_tip(&e.ms.chain_active);
        RIE_CHECK("reorg A: tip at L",
                  tipL && tipL->nHeight == L->n - 1);

        /* Install W's index + tip and extend proof_validate; the
         * reducer must unwind L and apply W. */
        e.ctx.active = W;
        for (int h = 1; h < W->n; h++)  /* h0 shared genesis already in */
            test_block_map_insert(&e.ms.map_block_index,
                             W->blocks[h].phashBlock, &W->blocks[h]);
        /* Make W heavier than L at its tip. */
        for (int h = 0; h < W->n; h++)
            arith_uint256_set_u64(&W->blocks[h].nChainWork,
                                  (uint64_t)(h + 1) * 10u);
        active_chain_move_window_tip(&e.ms.chain_active, &W->blocks[W->n - 1]);
        RIE_CHECK("reorg A: seed W proof_validate",
                  seed_proof_validate(progress_store_db(), W,
                                      W->n - 1));

        (void)rie_drain_to_convergence();
        RIE_CHECK("reorg A: utxo_apply reorg-unwound",
                  utxo_apply_stage_reorg_unwound_total() >= 1);
        struct block_index *tipW = active_chain_tip(&e.ms.chain_active);
        RIE_CHECK("reorg A: tip reorged to W",
                  tipW && tipW->nHeight == W->n - 1 &&
                  tipW == &W->blocks[W->n - 1]);

        /* coins_kv count + SHA3 commitment for the parity proof. */
        sqlite3 *pdb = progress_store_db();
        *countA = (uint64_t)coins_kv_count(pdb);
        *haveA = (coins_kv_commitment(pdb, cA) == 0);

        /* Every L-only outpoint must be ABSENT after the reorg. */
        struct uint256 t; int absent = 0;
        cb_txid(&t, 0x11, 1);
        if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        cb_txid(&t, 0x11, 2);
        if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        cb_txid(&t, 0x11, 3);
        if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        spend_txid(&t, 0x11, 2);
        if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        *l_only_absent = absent;

        rie_env_close(&e);
    }
    return failures;
}

static int rie_run_reorg_direct(const struct rie_ext_coin *ext,
                                struct rie_branch *W2, uint8_t *cB,
                                uint64_t *countB, bool *haveB)
{
    int failures = 0;
    struct rie_env e;
    bool opened = rie_env_open(&e, "reorg_b", W2, ext, 2);
    RIE_CHECK("reorg B: env opens", opened);
    if (opened) {
        for (int h = 0; h < W2->n; h++)
            arith_uint256_set_u64(&W2->blocks[h].nChainWork,
                                  (uint64_t)(h + 1) * 10u);
        (void)install_branch(&e, W2);
        RIE_CHECK("reorg B: seed W proof_validate",
                  seed_proof_validate(progress_store_db(), W2,
                                      W2->n - 1));
        int adv = rie_drain_to_convergence();
        RIE_CHECK("reorg B: W drained to tip", adv >= W2->n);
        RIE_CHECK("reorg B: no reorg unwind",
                  utxo_apply_stage_reorg_unwound_total() == 0);
        struct block_index *tip = active_chain_tip(&e.ms.chain_active);
        RIE_CHECK("reorg B: tip at W", tip && tip->nHeight == W2->n - 1);

        /* coins_kv parity source. */
        sqlite3 *pdb = progress_store_db();
        *countB = (uint64_t)coins_kv_count(pdb);
        *haveB = (coins_kv_commitment(pdb, cB) == 0);
        rie_env_close(&e);
    }
    return failures;
}

static int rie_run_reorg_scenario(const struct rie_ext_coin *ext)
{
    /* SCENARIO 3: a heavier competing branch reorgs byte-exact.
     * RUN A: ingest L (genesis + L1..L3), then W (genesis + W1..W4); the
     * inverse-delta unwind + re-finalize must converge the UTXO set onto W.
     * RUN B: ingest W directly from the fork point.
     * PROOF: commitment(A) == commitment(B) and count(A) == count(B). */
    int failures = 0;
    struct rie_branch L, W, W2;
    bool built = branch_build(&L, 0x11, 4, 2, 1, &ext[0]) &&  /* loser  */
                 branch_build(&W, 0x22, 5, 2, 1, &ext[1]) &&  /* winner */
                 branch_build(&W2, 0x22, 5, 2, 1, &ext[1]);   /* W copy */
    RIE_CHECK("reorg: branches build", built);

    uint8_t cA[32] = {0}, cB[32] = {0};
    uint64_t countA = 0, countB = 0;
    bool haveA = false, haveB = false;
    int l_only_absent = 0;

    /* RUN A: ingest L, then reorg to W. */
    if (built) {
        failures += rie_run_reorg_incremental(ext, &L, &W, cA, &countA,
                                              &haveA, &l_only_absent);
    }

    /* RUN B: direct build of W from the fork point. */
    if (built) {
        failures += rie_run_reorg_direct(ext, &W2, cB, &countB, &haveB);
    }

    bool count_eq = (countA == countB);
    bool cmt_eq = haveA && haveB && (memcmp(cA, cB, 32) == 0);
    printf("[reorg values] countA=%" PRIu64 " countB=%" PRIu64
           " commitment_match=%d l_only_absent=%d/4\n",
           countA, countB, cmt_eq ? 1 : 0, l_only_absent);
    if (!cmt_eq && haveA && haveB)
        printf("[divergence] reducer reorg UTXO set != direct build — a "
               "wrong inverse silently corrupted the reorged UTXO set\n");

    RIE_CHECK("reorg PROOF: reorged count == direct-build count", count_eq);
    RIE_CHECK("reorg PROOF: reorged commitment == direct-build commitment "
              "(byte-exact SHA3 UTXO set)", cmt_eq);
    RIE_CHECK("reorg PROOF: every L-only outpoint absent after reorg",
              l_only_absent == 4);

    branch_free(&L);
    branch_free(&W);
    branch_free(&W2);
    return failures;
}

static int rie_check_no_stage_spin(void)
{
    /* Advance-or-blocker false-fire proof: healthy folds plus a legitimately
     * blocked invalid height (scenario 2) never name a stage as spinning. */
    int failures = 0;
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int bn = blocker_snapshot_all(snaps, BLOCKER_CAP);
    bool any_spin = false;
    for (int i = 0; i < bn; i++)
        if (strncmp(snaps[i].id, "stage_spin_", 11) == 0)
            any_spin = true;
    RIE_CHECK("teardown: no stage_spin_* blocker fired (no false-fire)",
              !any_spin);
    return failures;
}

int test_reducer_ingest_e2e(void);
int test_reducer_ingest_e2e(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== reducer-ingest end-to-end test"
           "(authoritative path, real consensus) ===\n");
    int failures = 0;

    blocker_module_init();
    rie_mkdir_p("./test-tmp");

    /* External base coins consumed by the spend blocks. */
    struct rie_ext_coin ext[2];
    memset(ext, 0, sizeof(ext));
    ext[0].txid.data[0] = 0xE7; ext[0].txid.data[1] = 0x0A; /* EXT_L */
    ext[0].vout = 0; ext[0].value = 500000000LL; ext[0].height = 0;
    ext[0].script[0] = 0x76; ext[0].script[1] = 0xa9; ext[0].script[2] = 0xAA;
    ext[0].script_len = 3;
    ext[1].txid.data[0] = 0xE7; ext[1].txid.data[1] = 0x0B; /* EXT_W */
    ext[1].vout = 0; ext[1].value = 600000000LL; ext[1].height = 0;
    ext[1].script[0] = 0x76; ext[1].script[1] = 0xa9; ext[1].script[2] = 0xBC;
    ext[1].script_len = 3;

    failures += rie_check_front_door();

    failures += rie_run_accept_scenario(ext);

    failures += rie_run_invalid_scenario(ext);

    failures += rie_run_reorg_scenario(ext);

    /* Belt + suspenders: production authority remains reducer-owned. */
    RIE_CHECK("teardown: reducer remains authoritative",
              reducer_is_authoritative());

    failures += rie_check_no_stage_spin();

    printf("=== reducer-ingest end-to-end: %d failures ===\n", failures);
    return failures;
}
