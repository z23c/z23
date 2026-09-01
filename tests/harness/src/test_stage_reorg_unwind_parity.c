/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_reorg_unwind_parity — the KEYSTONE proof for design item 5
 * (stage-side reorg unwind).
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * The authoritative UTXO writer is utxo_apply_stage, which authors the
 * kernel coins_kv (the canonical UTXO set in progress.kv — the one UTXO
 * ledger). A reorg on that path must produce a BYTE-IDENTICAL coins_kv
 * SHA3 commitment to a direct build of the winning branch — otherwise a
 * reorg silently and permanently corrupts the UTXO set (a wrong inverse
 * SPENDs an absent coin = a no-op DELETE, with NO crash). This is the proof
 * the stage-side inverse path (utxo_apply_reorg_unwind_if_needed) is
 * correct, in isolation.
 *
 * WHAT IS DRIVEN
 * --------------
 *   Base UTXO set: a few pre-fork external coins, seeded IDENTICALLY into
 *   both runs' coins_kv (a coin spent on the losing branch and restored on
 *   unwind must already exist in both, or the runs diverge).
 *
 *   RUN 1 (stage reorg path):
 *     - active_chain = losing branch L (genesis h0 + L1..L3, L2 spends an
 *       external coin EXT_L). Seed proof_validate, drive utxo_apply_stage:
 *       it computes the real per-block delta, applies it forward to coins_kv
 *       (as STAGE author), AND persists the inverse-delta rows stamped with
 *       L block hashes.
 *     - Install heavier winning branch W (genesis h0 + W1..W4, W2 spends a
 *       DIFFERENT external coin EXT_W) on active_chain; extend proof_validate.
 *     - Step the stage: utxo_apply_reorg_unwind_if_needed detects the
 *       branch_hash divergence at the tip height, walks down to the fork
 *       (h0), emits the inverse events for L3,L2,L1 (restore→ADD,
 *       erase→SPEND), deletes the L delta/log rows, rewinds the cursor to
 *       the fork boundary, then re-advances forward over W1..W4.
 *   RUN 2 (direct build): same base seed, then active_chain = W only;
 *     drive the stage straight over genesis + W1..W4.
 *
 *   ASSERT: coins_kv_commitment(C1) == coins_kv_commitment(C2) byte-exact
 *     (SHA3-256), count(C1) == count(C2), and every L-only outpoint
 *     (L1/L2/L3 coinbases + L2's spend output) is ABSENT from C1, EXT_L is
 *     restored live, and EXT_W is spent.
 *
 * No legacy coins.db is involved — this is coins_kv-vs-coins_kv over the
 * SHA3 commitment of each derived UTXO set, exercising the stage inverse
 * path. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/utxo_apply_stage.h"
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

#define SRU_CHECK(name, expr) do {                       \
    printf("stage_reorg_unwind: %s... ", (name));        \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* ── External base coins (the pre-fork UTXO set the spends consume) ──── */

struct ext_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    uint32_t height;
    bool is_coinbase;
    uint8_t script[8];
    uint32_t script_len;
};

/* Chain bodies for one branch (index by height; 0 = genesis). */
struct branch {
    struct block       *bodies;
    struct uint256     *hashes;
    struct block_index *blocks;
    int n;            /* number of heights (genesis at 0 .. n-1) */
};

/* ── tmp-dir helpers ─────────────────────────────────────────────────── */

static int sru_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── Builders (mirror test_utxo_apply_stage's synthetic shapes) ──────── */

/* Deterministic coinbase txid: (branch_tag, height). Distinct branches
 * produce distinct coinbase txids at the same height (forks share
 * heights, not hashes). */
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
    tx->vout[0].value = 1000000000LL + h;
    uint8_t pk[3] = { 0x76, 0xa9, (uint8_t)(0x10 + h) };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    cb_txid(&tx->hash, branch_tag, h);
}

/* A spend tx that consumes external coin `ext` and creates one output. */
static void make_spend(struct transaction *tx, uint8_t branch_tag, int h,
                       const struct ext_coin *ext)
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

static void finalize_block(struct block *b, int h)
{
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    struct uint256 *leaves =
        zcl_calloc(b->num_vtx, sizeof(struct uint256), "sru_leaves");
    for (size_t i = 0; i < b->num_vtx; i++) leaves[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(leaves, b->num_vtx);
    free(leaves);
}

/* Build one branch. `spend_at` is the height with a spend (-1 = none),
 * consuming external coin `ext`. Genesis at height 0 (coinbase only). */
static bool branch_build(struct branch *br, uint8_t tag, int n,
                         int spend_at, const struct ext_coin *ext)
{
    memset(br, 0, sizeof(*br));
    br->n = n;
    br->bodies = zcl_calloc((size_t)n, sizeof(struct block), "sru_bodies");
    br->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "sru_hashes");
    br->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "sru_blocks");
    if (!br->bodies || !br->hashes || !br->blocks) return false;

    for (int h = 0; h < n; h++) {
        struct block *b = &br->bodies[h];
        block_init(b);
        bool has_spend = (h == spend_at);
        b->num_vtx = has_spend ? 2u : 1u;
        b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "sru_vtx");
        if (!b->vtx) return false;
        /* Genesis (h0) uses tag 0 so both branches share the SAME genesis
         * coinbase (a real shared fork point); h>0 uses the branch tag. */
        uint8_t cbtag = (h == 0) ? 0x00 : tag;
        make_coinbase(&b->vtx[0], cbtag, h);
        if (has_spend) make_spend(&b->vtx[1], tag, h, ext);
        finalize_block(b, h);

        block_header_get_hash(&b->header, &br->hashes[h]);
        block_index_init(&br->blocks[h]);
        br->blocks[h].phashBlock = &br->hashes[h];
        br->blocks[h].nHeight = h;
        br->blocks[h].nStatus = BLOCK_HAVE_DATA;
        if (h > 0) br->blocks[h].pprev = &br->blocks[h - 1];
    }
    return true;
}

static void branch_free(struct branch *br)
{
    if (br->bodies) {
        for (int h = 0; h < br->n; h++) block_free(&br->bodies[h]);
    }
    free(br->bodies);
    free(br->hashes);
    free(br->blocks);
    memset(br, 0, sizeof(*br));
}

/* ── Stage plumbing: reader + lookup over the external base set ──────── */

struct sru_ctx {
    struct branch *active;        /* branch whose bodies the reader serves */
    const struct ext_coin *ext;   /* external base coins */
    int n_ext;
};

static bool block_copy(struct block *dst, const struct block *src)
{
    block_init(dst);
    dst->header = src->header;
    dst->num_vtx = src->num_vtx;
    if (src->num_vtx == 0) return true;
    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction), "sru_copy");
    if (!dst->vtx) return false;
    for (size_t i = 0; i < src->num_vtx; i++) {
        transaction_init(&dst->vtx[i]);
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i])) return false;
    }
    return true;
}

static bool sru_reader(struct block *out, const struct block_index *bi,
                       const char *datadir, void *user)
{
    (void)datadir;
    struct sru_ctx *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= c->active->n)
        return false;
    return block_copy(out, &c->active->bodies[bi->nHeight]);
}

/* Resolve a prevout against the external base set ONLY. On-chain coins
 * created earlier in the same block are resolved by compute_block_delta
 * itself; coinbase outputs are NOT registered here, so the output
 * collision-check correctly returns found=false at creation time. */
static bool sru_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    struct sru_ctx *c = user;
    memset(out, 0, sizeof(*out));
    if (!c) return true;
    for (int i = 0; i < c->n_ext; i++) {
        const struct ext_coin *e = &c->ext[i];
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
    return true; /* not found (e.g. a freshly created output) */
}

/* ── proof_validate seeding (mirror test_utxo_apply_stage) ───────────── */

static bool sru_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool seed_proof_validate(sqlite3 *db, const struct branch *br,
                                int through_height)
{
    if (!db || !br || through_height < 0 || through_height >= br->n)
        return false;
    if (!sru_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)") ||
        !sru_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB)"))
        return false;
    sqlite3_stmt *st = NULL, *script_st = NULL;
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
    for (int h = 0; h <= through_height; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, br->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
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
            return false;
        }
        sqlite3_reset(script_st);
        sqlite3_clear_bindings(script_st);
    }
    sqlite3_finalize(st);
    sqlite3_finalize(script_st);
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('proof_validate', ?, 1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, through_height + 1);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Seed the pre-fork base UTXO set into coins_kv — the authoritative live
 * UTXO store the reducer reads/writes after the projection dual-write was
 * removed. (The forward apply + inverse unwind now author only coins_kv.) */
static void seed_base_coins(sqlite3 *pdb, const struct ext_coin *ext, int n)
{
    (void)coins_kv_ensure_schema(pdb);
    for (int i = 0; i < n; i++) {
        const struct ext_coin *e = &ext[i];
        (void)coins_kv_add(pdb, e->txid.data, e->vout, e->value,
                           (int32_t)e->height, e->is_coinbase,
                           e->script_len ? e->script : NULL, e->script_len);
    }
}

/* ── Test ─────────────────────────────────────────────────────────────── */

int test_stage_reorg_unwind_parity(void);
int test_stage_reorg_unwind_parity(void)
{
    printf("\n=== stage-side reorg-unwind parity test "
           "(STAGE-authoritative projection through reorg) ===\n");
    int failures = 0;

    blocker_module_init();
    sru_mkdir_p("./test-tmp");

    /* External base coins: EXT_L is spent by L, EXT_W by W. Both live in
     * the pre-fork base set seeded into BOTH runs. */
    struct ext_coin ext[2];
    memset(ext, 0, sizeof(ext));
    ext[0].txid.data[0] = 0xE7; ext[0].txid.data[1] = 0x0A; /* EXT_L */
    ext[0].vout = 0; ext[0].value = 500000000LL; ext[0].height = 0;
    ext[0].is_coinbase = false;
    ext[0].script[0] = 0x76; ext[0].script[1] = 0xa9; ext[0].script[2] = 0xAA;
    ext[0].script_len = 3;
    ext[1].txid.data[0] = 0xE7; ext[1].txid.data[1] = 0x0B; /* EXT_W */
    ext[1].vout = 0; ext[1].value = 600000000LL; ext[1].height = 0;
    ext[1].is_coinbase = false;
    ext[1].script[0] = 0x76; ext[1].script[1] = 0xa9; ext[1].script[2] = 0xBC;
    ext[1].script_len = 3;

    /* Branch L: genesis + 3 (spend at h2 of EXT_L). Branch W: genesis + 4
     * (heavier; spend at h2 of EXT_W). Shared genesis at h0. */
    struct branch L, W;
    bool built = branch_build(&L, 0x11, 4, 2, &ext[0]) &&
                 branch_build(&W, 0x22, 5, 2, &ext[1]);
    SRU_CHECK("branches build", built);

    uint8_t c1[32] = {0}, c2[32] = {0};
    uint64_t count1 = 0, count2 = 0;
    bool have_c1 = false, have_c2 = false;
    int l_only_absent = 0;

    /* ── RUN 1: stage reorg path ─────────────────────────────────────── */
    if (built) {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "stage_reorg_unwind", "run1");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        SRU_CHECK("run1: progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);
        SRU_CHECK("run1: event log opens", lg != NULL);

        if (lg) {
            seed_base_coins(progress_store_db(), ext, 2);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            active_chain_init(&ms.chain_active);
            active_chain_move_window_tip(&ms.chain_active, &L.blocks[L.n - 1]);

            struct sru_ctx ctx = { .active = &L, .ext = ext, .n_ext = 2 };
            SRU_CHECK("run1: stage init", utxo_apply_stage_init(&ms));
            utxo_apply_stage_set_reader(sru_reader, &ctx);
            utxo_apply_stage_set_lookup(sru_lookup, &ctx);

            /* Apply losing branch L (heights 0..3). */
            SRU_CHECK("run1: L seed proof_validate",
                      seed_proof_validate(progress_store_db(), &L, L.n - 1));
            int adv_l = utxo_apply_stage_drain(100);
            SRU_CHECK("run1: L drains all", adv_l == L.n);
            SRU_CHECK("run1: cursor at L tip",
                      utxo_apply_stage_cursor() == (uint64_t)L.n);

            /* Install heavier winning branch W on active_chain + extend
             * proof_validate to W's tip. The live driver swapped the tip;
             * the stage now OBSERVES the swap via branch_hash divergence. */
            ctx.active = &W;
            active_chain_move_window_tip(&ms.chain_active, &W.blocks[W.n - 1]);
            SRU_CHECK("run1: W seed proof_validate",
                      seed_proof_validate(progress_store_db(), &W, W.n - 1));

            /* Step the stage: first the reorg-unwind fires (emits inverse
             * events for L3,L2,L1, rewinds cursor to fork+1 == 1), then
             * forward re-apply over W. */
            int adv_w = utxo_apply_stage_drain(100);
            SRU_CHECK("run1: reorg-unwind counter fired",
                      utxo_apply_stage_reorg_unwound_total() == 1);
            SRU_CHECK("run1: cursor at W tip after reorg",
                      utxo_apply_stage_cursor() == (uint64_t)W.n);
            /* Unwound 3 L heights (1..3) then re-applied 4 W heights (1..4). */
            SRU_CHECK("run1: re-advanced over W", adv_w >= W.n - 1);

            /* coins_kv is the authoritative UTXO store (the projection
             * dual-write was removed) — read the post-reorg count + SHA3
             * commitment from coins_kv, which the stage authored in-txn through
             * the forward apply and the inverse unwind. */
            sqlite3 *pdb = progress_store_db();
            count1 = (uint64_t)coins_kv_count(pdb);
            have_c1 = (coins_kv_commitment(pdb, c1) == 0);
            SRU_CHECK("run1: commitment computed", have_c1);

            /* Every L-only outpoint must be ABSENT after the unwind — coins_kv
             * unwound them with the cursor (no orphaned above-fork coins). */
            struct uint256 t; int ck_absent = 0;
            cb_txid(&t, 0x11, 1); if (!coins_kv_exists(pdb, t.data, 0)) ck_absent++;
            cb_txid(&t, 0x11, 2); if (!coins_kv_exists(pdb, t.data, 0)) ck_absent++;
            cb_txid(&t, 0x11, 3); if (!coins_kv_exists(pdb, t.data, 0)) ck_absent++;
            spend_txid(&t, 0x11, 2); if (!coins_kv_exists(pdb, t.data, 0)) ck_absent++;
            l_only_absent = ck_absent;
            SRU_CHECK("run1: coins_kv all 4 L-only outpoints absent",
                      ck_absent == 4);
            /* EXT_L was spent on L then RESTORED on unwind (W never spends it) —
             * the inverse-delta re-ADD must make it live again. */
            SRU_CHECK("run1: coins_kv EXT_L restored live after unwind",
                      coins_kv_exists(pdb, ext[0].txid.data, 0));
            /* EXT_W spent on W — absent. */
            SRU_CHECK("run1: coins_kv EXT_W spent on W (absent)",
                      !coins_kv_exists(pdb, ext[1].txid.data, 0));

            utxo_apply_stage_shutdown();
            active_chain_free(&ms.chain_active);
        }
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── RUN 2: direct build of W ─────────────────────────────────────── */
    if (built) {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "stage_reorg_unwind", "run2");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        SRU_CHECK("run2: progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);
        SRU_CHECK("run2: event log opens", lg != NULL);

        if (lg) {
            seed_base_coins(progress_store_db(), ext, 2);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            active_chain_init(&ms.chain_active);
            active_chain_move_window_tip(&ms.chain_active, &W.blocks[W.n - 1]);

            struct sru_ctx ctx = { .active = &W, .ext = ext, .n_ext = 2 };
            SRU_CHECK("run2: stage init", utxo_apply_stage_init(&ms));
            utxo_apply_stage_set_reader(sru_reader, &ctx);
            utxo_apply_stage_set_lookup(sru_lookup, &ctx);

            SRU_CHECK("run2: W seed proof_validate",
                      seed_proof_validate(progress_store_db(), &W, W.n - 1));
            int adv = utxo_apply_stage_drain(100);
            SRU_CHECK("run2: W drains all", adv == W.n);
            SRU_CHECK("run2: no reorg unwind",
                      utxo_apply_stage_reorg_unwound_total() == 0);

            /* Direct build: coins_kv is the authoritative store. Read its count
             * + commitment for the cross-run parity proof against RUN1. */
            sqlite3 *pdb = progress_store_db();
            count2 = (uint64_t)coins_kv_count(pdb);
            have_c2 = (coins_kv_commitment(pdb, c2) == 0);
            SRU_CHECK("run2: commitment computed", have_c2);

            utxo_apply_stage_shutdown();
            active_chain_free(&ms.chain_active);
        }
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── THE PROOF ────────────────────────────────────────────────────── */
    bool count_eq = (count1 == count2);
    bool cmt_eq = have_c1 && have_c2 && (memcmp(c1, c2, 32) == 0);

    printf("[values] count1=%" PRIu64 " count2=%" PRIu64
           " commitment_match=%d l_only_absent=%d/4\n",
           count1, count2, cmt_eq ? 1 : 0, l_only_absent);
    if (!cmt_eq && have_c1 && have_c2) {
        printf("[divergence] stage reorg projection != direct build — a wrong "
               "inverse mapping silently corrupted the STAGE-authored UTXO set\n");
    }

    SRU_CHECK("PROOF: stage-reorg P1 count == direct P2 count", count_eq);
    SRU_CHECK("PROOF: stage-reorg P1 commitment == direct P2 commitment "
              "(byte-exact SHA3 UTXO set via STAGE inverse path)", cmt_eq);
    SRU_CHECK("PROOF: every L-only outpoint absent from P1", l_only_absent == 4);

    branch_free(&L);
    branch_free(&W);

    printf("=== stage-side reorg-unwind parity: %d failures ===\n", failures);
    return failures;
}
