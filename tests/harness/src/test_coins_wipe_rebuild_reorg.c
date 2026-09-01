/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_coins_wipe_rebuild_reorg — Program H1 refutation proof: after the
 * event-log-fed UTXO projection (the third UTXO copy) was deleted, a WIPED
 * coin set still rebuilds byte-identically THROUGH A REORG from block bodies
 * alone.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * Program H1 (9b5add018) deleted engine/modules/storage/src/utxo_projection.c +
 * coins_view_projection.c: a third writable UTXO copy fed by
 * EV_UTXO_ADD/EV_UTXO_SPEND. Its ONE surviving production role was a boot
 * migration source — coins_kv_boot_rebuild_if_needed copied from it when
 * coins_kv was empty. That copy is gone; an empty coins_kv now re-derives
 * from block bodies via the normal fold.
 *
 * The load-bearing claim behind that deletion is therefore a RECOVERY claim,
 * and recovery paths are exactly where a forgotten reader hides because they
 * run rarely. The existing tests/harness/src/test_stage_reorg_unwind_parity.c
 * proves reorg-vs-linear parity within one live store; it never wipes. The
 * existing linear rebuild proofs wipe but never reorg. Neither covers the
 * crash-recovery shape that actually matters:
 *
 *     wipe the coin set  ->  rebuild it  ->  and the rebuild itself reorgs.
 *
 * A LINEAR-FOLD-ONLY rebuild proof is the weak version: it cannot catch an
 * inverse-delta path that silently depended on projection state to restore a
 * coin spent on the losing branch, because a linear rebuild never runs the
 * inverse path at all. This test forces the rebuild through the inverse path.
 *
 * WHAT IS DRIVEN (one datadir, wiped in the middle)
 * -------------------------------------------------
 *   RUN A (original):  seed pre-fork base coins; drive utxo_apply_stage over
 *     losing branch L (h0 + L1..L3, L2 spends EXT_L); install heavier winning
 *     branch W (h0 + W1..W4, W2 spends EXT_W); step the stage so
 *     utxo_apply_reorg_unwind_if_needed fires and re-advances over W.
 *     Capture coins_kv count + SHA3 commitment (A).
 *
 *   WIPE (the production primitive):  coins_kv_reset_for_reseed() — the exact
 *     call engine/services/src/reindex_epilogue.c makes after a from-genesis
 *     replay — plus the stage cursor / delta / apply-log rows. Asserted to
 *     leave coins_kv EMPTY and its commitment DIFFERENT from A, so a
 *     no-op "wipe" cannot make this test pass vacuously.
 *
 *   RUN B (rebuild, SAME datadir):  re-seed the base coins and re-drive the
 *     SAME history — L first, then the reorg onto W. The rebuild is asserted
 *     to have actually unwound (reorg_unwound_total == 1), so it is not
 *     silently downgraded to a linear fold.
 *
 *   RUN C (cross-check, fresh datadir):  direct linear build of W only.
 *
 * ASSERTS
 * -------
 *   1. A == B byte-exact (SHA3 coins_kv commitment) and count(A) == count(B).
 *   2. RUN B genuinely reorged (unwind counter fired) — not a linear fold.
 *   3. A == C: the reorged rebuild equals a direct build of the winner.
 *   4. Post-rebuild coin-level facts: every L-only outpoint absent, EXT_L
 *      restored live by the inverse path, EXT_W spent.
 *   5. THE H1 INVARIANT: across the whole wipe+reorg+rebuild the event log
 *      carries ZERO EV_UTXO_ADD / EV_UTXO_SPEND events. Tags 5/6 survive as
 *      reserved wire slots (renumbering them would break the on-disk log),
 *      but no production emitter may resurrect. tools/scripts/
 *      check_no_utxo_projection.sh proves that by grep at build time; this
 *      proves it at RUNTIME, through the recovery path, where a re-added
 *      emitter would actually show up. Verified against the GUARD and not
 *      against a bare zero (docs/AGENT_TRAPS.md §4): a positive control
 *      plants one EV_UTXO_ADD afterwards and requires the same scanner to
 *      report exactly 1, so a broken scan cannot pass as an absence proof.
 *
 * No legacy coins.db and no projection are involved anywhere: coins_kv is the
 * one UTXO ledger and block bodies are the only rebuild input. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/utxo_apply_stage.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
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

#define CWR_CHECK(name, expr) do {                        \
    printf("coins_wipe_rebuild_reorg: %s... ", (name));   \
    if ((expr)) printf("OK\n");                           \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* ── Pre-fork base coins (the external UTXO set the spends consume) ───── */

struct cwr_ext_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    uint32_t height;
    bool is_coinbase;
    uint8_t script[8];
    uint32_t script_len;
};

/* Chain bodies for one branch (index by height; 0 = genesis). */
struct cwr_branch {
    struct block       *bodies;
    struct uint256     *hashes;
    struct block_index *blocks;
    int n;            /* number of heights (genesis at 0 .. n-1) */
};

/* ── Builders (mirror test_stage_reorg_unwind_parity's synthetic shapes) ─ */

/* Deterministic coinbase txid: (branch_tag, height). Distinct branches
 * produce distinct coinbase txids at the same height. */
static void cwr_cb_txid(struct uint256 *out, uint8_t branch_tag, int h)
{
    uint256_set_null(out);
    out->data[0] = 0xC0;
    out->data[1] = branch_tag;
    out->data[2] = (uint8_t)h;
}

static void cwr_spend_txid(struct uint256 *out, uint8_t branch_tag, int h)
{
    uint256_set_null(out);
    out->data[0] = 0x5E;
    out->data[1] = branch_tag;
    out->data[2] = (uint8_t)h;
}

static void cwr_make_coinbase(struct transaction *tx, uint8_t branch_tag, int h)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vout[0].value = 1000000000LL + h;
    uint8_t pk[3] = { 0x76, 0xa9, (uint8_t)(0x10 + h) };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    cwr_cb_txid(&tx->hash, branch_tag, h);
}

/* A spend tx that consumes external coin `ext` and creates one output. */
static void cwr_make_spend(struct transaction *tx, uint8_t branch_tag, int h,
                           const struct cwr_ext_coin *ext)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    tx->vin[0].prevout.hash = ext->txid;
    tx->vin[0].prevout.n = ext->vout;
    tx->vout[0].value = ext->value - 1000; /* fee */
    uint8_t pk[4] = { 0x76, 0xa9, 0xBB, branch_tag };
    script_set(&tx->vout[0].script_pub_key, pk, 4);
    cwr_spend_txid(&tx->hash, branch_tag, h);
}

static void cwr_finalize_block(struct block *b, int h)
{
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    struct uint256 *leaves =
        zcl_calloc(b->num_vtx, sizeof(struct uint256), "cwr_leaves");
    if (!leaves) return;
    for (size_t i = 0; i < b->num_vtx; i++) leaves[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(leaves, b->num_vtx);
    free(leaves);
}

/* Build one branch. `spend_at` is the height with a spend (-1 = none),
 * consuming external coin `ext`. Genesis at height 0 (coinbase only,
 * SHARED by both branches — a real fork point). */
static bool cwr_branch_build(struct cwr_branch *br, uint8_t tag, int n,
                             int spend_at, const struct cwr_ext_coin *ext)
{
    memset(br, 0, sizeof(*br));
    br->n = n;
    br->bodies = zcl_calloc((size_t)n, sizeof(struct block), "cwr_bodies");
    br->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "cwr_hashes");
    br->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "cwr_blocks");
    if (!br->bodies || !br->hashes || !br->blocks) return false;

    for (int h = 0; h < n; h++) {
        struct block *b = &br->bodies[h];
        block_init(b);
        bool has_spend = (h == spend_at);
        b->num_vtx = has_spend ? 2u : 1u;
        b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "cwr_vtx");
        if (!b->vtx) return false;
        uint8_t cbtag = (h == 0) ? 0x00 : tag;
        cwr_make_coinbase(&b->vtx[0], cbtag, h);
        if (has_spend) cwr_make_spend(&b->vtx[1], tag, h, ext);
        cwr_finalize_block(b, h);

        block_header_get_hash(&b->header, &br->hashes[h]);
        block_index_init(&br->blocks[h]);
        br->blocks[h].phashBlock = &br->hashes[h];
        br->blocks[h].nHeight = h;
        br->blocks[h].nStatus = BLOCK_HAVE_DATA;
        if (h > 0) br->blocks[h].pprev = &br->blocks[h - 1];
    }
    return true;
}

static void cwr_branch_free(struct cwr_branch *br)
{
    if (br->bodies) {
        for (int h = 0; h < br->n; h++) block_free(&br->bodies[h]);
    }
    free(br->bodies);
    free(br->hashes);
    free(br->blocks);
    memset(br, 0, sizeof(*br));
}

/* ── Stage plumbing: body reader + prevout lookup over the base set ───── */

struct cwr_ctx {
    struct cwr_branch *active;        /* branch whose bodies the reader serves */
    const struct cwr_ext_coin *ext;   /* external base coins */
    int n_ext;
};

static bool cwr_block_copy(struct block *dst, const struct block *src)
{
    block_init(dst);
    dst->header = src->header;
    dst->num_vtx = src->num_vtx;
    if (src->num_vtx == 0) return true;
    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction), "cwr_copy");
    if (!dst->vtx) return false;
    for (size_t i = 0; i < src->num_vtx; i++) {
        transaction_init(&dst->vtx[i]);
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i])) return false;
    }
    return true;
}

static bool cwr_reader(struct block *out, const struct block_index *bi,
                       const char *datadir, void *user)
{
    (void)datadir;
    struct cwr_ctx *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= c->active->n)
        return false;
    return cwr_block_copy(out, &c->active->bodies[bi->nHeight]);
}

/* Resolve a prevout against the external base set ONLY. Same-block outputs
 * are resolved by compute_block_delta itself. */
static bool cwr_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    struct cwr_ctx *c = user;
    memset(out, 0, sizeof(*out));
    if (!c) return true;
    for (int i = 0; i < c->n_ext; i++) {
        const struct cwr_ext_coin *e = &c->ext[i];
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

/* ── Upstream (proof/script validate) seeding ─────────────────────────── */

static bool cwr_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool cwr_seed_upstream(sqlite3 *db, const struct cwr_branch *br,
                              int through_height)
{
    if (!db || !br || through_height < 0 || through_height >= br->n)
        return false;
    if (!cwr_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)") ||
        !cwr_exec(db,
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
        sqlite3_bind_blob(script_st, 2, br->hashes[h].data, 32, SQLITE_STATIC);
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

/* Seed the pre-fork base UTXO set into coins_kv — the one live UTXO ledger.
 * In production this is what the baked SHA3 checkpoint / snapshot install
 * provides; here it stands in for "state below the rebuild range". */
static void cwr_seed_base_coins(sqlite3 *pdb, const struct cwr_ext_coin *ext,
                                int n)
{
    (void)coins_kv_ensure_schema(pdb);
    for (int i = 0; i < n; i++) {
        const struct cwr_ext_coin *e = &ext[i];
        (void)coins_kv_add(pdb, e->txid.data, e->vout, e->value,
                           (int32_t)e->height, e->is_coinbase,
                           e->script_len ? e->script : NULL, e->script_len);
    }
}

/* THE WIPE. coins_kv_reset_for_reseed() is the production primitive
 * engine/services/src/reindex_epilogue.c calls after a from-genesis replay:
 * DELETE FROM coins + clear the migration stamp, the self-folded provenance
 * bit and the applied frontier, in ONE BEGIN IMMEDIATE. On top of it we drop
 * the reducer's own bookkeeping (stage cursor + per-block delta/apply-log
 * rows) so the rebuild starts from genuinely nothing but block bodies. */
static bool cwr_wipe_coin_state(sqlite3 *pdb)
{
    if (!pdb) return false;
    if (!coins_kv_reset_for_reseed(pdb)) return false;
    return cwr_exec(pdb, "DELETE FROM stage_cursor WHERE name='utxo_apply'") &&
           cwr_exec(pdb, "DROP TABLE IF EXISTS utxo_apply_delta") &&
           cwr_exec(pdb, "DROP TABLE IF EXISTS utxo_apply_log") &&
           cwr_exec(pdb, "DELETE FROM proof_validate_log") &&
           cwr_exec(pdb, "DELETE FROM script_validate_log") &&
           cwr_exec(pdb, "DELETE FROM stage_cursor WHERE name='proof_validate'");
}

/* ── Event-log scan: the H1 "stays dead" runtime invariant ────────────── */

struct cwr_evscan { uint64_t utxo_events; uint64_t total_events; };

static bool cwr_evscan_cb(uint64_t offset, enum event_log_type type,
                          const void *payload, size_t len, void *user)
{
    (void)offset; (void)payload; (void)len;
    struct cwr_evscan *s = user;
    if (!s) return false;
    s->total_events++;
    if (type == EV_UTXO_ADD || type == EV_UTXO_SPEND)
        s->utxo_events++;
    return true;
}

/* Drive one full L-then-reorg-to-W history against the currently open
 * progress_store. Returns the stage advance count of the reorg leg, or -1. */
struct cwr_run_result {
    uint64_t count;
    uint8_t  commitment[32];
    bool     have_commitment;
    uint64_t unwound;
    uint64_t cursor;
    int      l_only_absent;
    bool     ext_l_live;
    bool     ext_w_spent;
    bool     ok;
};

static void cwr_drive_reorg_history(struct cwr_branch *L, struct cwr_branch *W,
                                    const struct cwr_ext_coin *ext,
                                    struct cwr_run_result *r)
{
    memset(r, 0, sizeof(*r));

    sqlite3 *pdb = progress_store_db();
    if (!pdb) return;
    cwr_seed_base_coins(pdb, ext, 2);

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    active_chain_move_window_tip(&ms.chain_active, &L->blocks[L->n - 1]);

    struct cwr_ctx ctx = { .active = L, .ext = ext, .n_ext = 2 };
    if (!utxo_apply_stage_init(&ms)) {
        active_chain_free(&ms.chain_active);
        return;
    }
    utxo_apply_stage_set_reader(cwr_reader, &ctx);
    utxo_apply_stage_set_lookup(cwr_lookup, &ctx);

    /* Losing branch L first. */
    if (!cwr_seed_upstream(pdb, L, L->n - 1)) goto done;
    (void)utxo_apply_stage_drain(100);

    /* Swap to the heavier winner W and step: the stage observes the
     * branch-hash divergence, runs the inverse unwind, then re-advances. */
    ctx.active = W;
    active_chain_move_window_tip(&ms.chain_active, &W->blocks[W->n - 1]);
    if (!cwr_seed_upstream(pdb, W, W->n - 1)) goto done;
    (void)utxo_apply_stage_drain(100);

    r->unwound = utxo_apply_stage_reorg_unwound_total();
    r->cursor  = utxo_apply_stage_cursor();
    r->count   = (uint64_t)coins_kv_count(pdb);
    r->have_commitment = (coins_kv_commitment(pdb, r->commitment) == 0);

    {
        struct uint256 t;
        int absent = 0;
        cwr_cb_txid(&t, 0x11, 1); if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        cwr_cb_txid(&t, 0x11, 2); if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        cwr_cb_txid(&t, 0x11, 3); if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        cwr_spend_txid(&t, 0x11, 2); if (!coins_kv_exists(pdb, t.data, 0)) absent++;
        r->l_only_absent = absent;
    }
    r->ext_l_live  = coins_kv_exists(pdb, ext[0].txid.data, 0);
    r->ext_w_spent = !coins_kv_exists(pdb, ext[1].txid.data, 0);
    r->ok = true;

done:
    utxo_apply_stage_shutdown();
    active_chain_free(&ms.chain_active);
}

/* ── Test ─────────────────────────────────────────────────────────────── */

int test_coins_wipe_rebuild_reorg(void);
int test_coins_wipe_rebuild_reorg(void)
{
    printf("\n=== coins wipe -> rebuild-across-a-reorg identity "
           "(Program H1: no third UTXO copy) ===\n");
    int failures = 0;

    blocker_module_init();

    struct cwr_ext_coin ext[2];
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

    struct cwr_branch L, W;
    bool built = cwr_branch_build(&L, 0x11, 4, 2, &ext[0]) &&
                 cwr_branch_build(&W, 0x22, 5, 2, &ext[1]);
    CWR_CHECK("branches build", built);

    struct cwr_run_result A, B, C;
    memset(&A, 0, sizeof(A));
    memset(&B, 0, sizeof(B));
    memset(&C, 0, sizeof(C));
    uint64_t wiped_count = 1;          /* must become 0 */
    bool wipe_changed_commitment = false;
    struct cwr_evscan evscan = { 0, 0 };
    bool evscan_ran = false;
    bool evscan_control_ok = false;

    /* ── RUN A + WIPE + RUN B: one datadir, wiped in the middle ──────── */
    if (built) {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "coins_wipe_rebuild_reorg", "ab");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        CWR_CHECK("progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);
        CWR_CHECK("event log opens", lg != NULL);

        if (lg) {
            /* RUN A — the original reorged history. */
            cwr_drive_reorg_history(&L, &W, ext, &A);
            CWR_CHECK("A: history drove to completion", A.ok);
            CWR_CHECK("A: cursor at W tip", A.cursor == (uint64_t)W.n);
            CWR_CHECK("A: reorg unwind fired once", A.unwound == 1);
            CWR_CHECK("A: commitment computed", A.have_commitment);

            /* THE WIPE — the production reindex-epilogue primitive. */
            sqlite3 *pdb = progress_store_db();
            CWR_CHECK("wipe: coin state reset", cwr_wipe_coin_state(pdb));
            wiped_count = (uint64_t)coins_kv_count(pdb);
            CWR_CHECK("wipe: coins_kv is EMPTY (the wipe is real)",
                      wiped_count == 0);
            {
                uint8_t empty_cmt[32] = {0};
                bool have_empty = (coins_kv_commitment(pdb, empty_cmt) == 0);
                wipe_changed_commitment =
                    have_empty && A.have_commitment &&
                    memcmp(empty_cmt, A.commitment, 32) != 0;
            }
            CWR_CHECK("wipe: commitment differs from A "
                      "(no vacuous pass)", wipe_changed_commitment);

            /* RUN B — rebuild the SAME history, reorg included, from block
             * bodies alone. There is no projection left to copy from. */
            cwr_drive_reorg_history(&L, &W, ext, &B);
            CWR_CHECK("B: rebuild drove to completion", B.ok);
            CWR_CHECK("B: cursor at W tip", B.cursor == (uint64_t)W.n);
            CWR_CHECK("B: rebuild REORGED (not a linear fold)",
                      B.unwound == 1);
            CWR_CHECK("B: commitment computed", B.have_commitment);
            CWR_CHECK("B: all 4 L-only outpoints absent",
                      B.l_only_absent == 4);
            CWR_CHECK("B: EXT_L restored live by the inverse path",
                      B.ext_l_live);
            CWR_CHECK("B: EXT_W spent on the winner", B.ext_w_spent);

            /* THE H1 RUNTIME INVARIANT: no EV_UTXO_* was emitted anywhere in
             * the wipe + reorg + rebuild. Tags 5/6 stay reserved; no
             * production emitter may come back. */
            if (event_log_stream(lg, 0, cwr_evscan_cb, &evscan) == 0)
                evscan_ran = true;
            CWR_CHECK("event log scanned", evscan_ran);
            CWR_CHECK("H1 INVARIANT: zero EV_UTXO_ADD/EV_UTXO_SPEND events "
                      "emitted across wipe+reorg+rebuild",
                      evscan_ran && evscan.utxo_events == 0);

            /* POSITIVE CONTROL — verify against the GUARD, not against a
             * count of zero (docs/AGENT_TRAPS.md §4). A scanner that silently
             * failed would also report zero. Append ONE EV_UTXO_ADD by hand
             * and re-scan: the detector must now report exactly 1. Only then
             * is the zero above evidence of anything. This runs AFTER every
             * proof below has already read its inputs. */
            {
                uint8_t ctl[EV_UTXO_ADD_HDR_WIRE_LEN];
                memset(ctl, 0, sizeof(ctl));
                (void)event_log_append(lg, EV_UTXO_ADD, ctl, sizeof(ctl));
                struct cwr_evscan ctl_scan = { 0, 0 };
                bool ctl_ran =
                    (event_log_stream(lg, 0, cwr_evscan_cb, &ctl_scan) == 0);
                evscan_control_ok = ctl_ran && ctl_scan.utxo_events == 1 &&
                                    ctl_scan.total_events ==
                                        evscan.total_events + 1;
            }
            CWR_CHECK("CONTROL: the EV_UTXO detector actually fires on a "
                      "planted event (the zero above is not vacuous)",
                      evscan_control_ok);

            event_log_close(lg);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── RUN C: fresh datadir, direct linear build of the winner ─────── */
    if (built) {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "coins_wipe_rebuild_reorg", "c");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        CWR_CHECK("C: progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);
        CWR_CHECK("C: event log opens", lg != NULL);

        if (lg) {
            sqlite3 *pdb = progress_store_db();
            cwr_seed_base_coins(pdb, ext, 2);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            active_chain_init(&ms.chain_active);
            active_chain_move_window_tip(&ms.chain_active, &W.blocks[W.n - 1]);

            struct cwr_ctx ctx = { .active = &W, .ext = ext, .n_ext = 2 };
            CWR_CHECK("C: stage init", utxo_apply_stage_init(&ms));
            utxo_apply_stage_set_reader(cwr_reader, &ctx);
            utxo_apply_stage_set_lookup(cwr_lookup, &ctx);

            CWR_CHECK("C: upstream seeded",
                      cwr_seed_upstream(pdb, &W, W.n - 1));
            int adv = utxo_apply_stage_drain(100);
            CWR_CHECK("C: W drains all", adv == W.n);
            CWR_CHECK("C: no reorg unwind",
                      utxo_apply_stage_reorg_unwound_total() == 0);

            C.count = (uint64_t)coins_kv_count(pdb);
            C.have_commitment = (coins_kv_commitment(pdb, C.commitment) == 0);
            C.ok = true;
            CWR_CHECK("C: commitment computed", C.have_commitment);

            utxo_apply_stage_shutdown();
            active_chain_free(&ms.chain_active);
            event_log_close(lg);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── THE PROOF ───────────────────────────────────────────────────── */
    bool ab_count_eq = (A.count == B.count) && A.ok && B.ok;
    bool ab_cmt_eq = A.have_commitment && B.have_commitment &&
                     memcmp(A.commitment, B.commitment, 32) == 0;
    bool ac_cmt_eq = A.have_commitment && C.have_commitment &&
                     memcmp(A.commitment, C.commitment, 32) == 0;

    printf("[values] countA=%" PRIu64 " countB=%" PRIu64 " countC=%" PRIu64
           " AB_match=%d AC_match=%d wiped_count=%" PRIu64
           " unwoundA=%" PRIu64 " unwoundB=%" PRIu64
           " ev_utxo=%" PRIu64 "/%" PRIu64 " ev_detector_control=%d"
           " l_only_absent=%d/4\n",
           A.count, B.count, C.count, ab_cmt_eq ? 1 : 0, ac_cmt_eq ? 1 : 0,
           wiped_count, A.unwound, B.unwound,
           evscan.utxo_events, evscan.total_events,
           evscan_control_ok ? 1 : 0, B.l_only_absent);
    if (!ab_cmt_eq && A.have_commitment && B.have_commitment) {
        printf("[divergence] wiped rebuild != original THROUGH A REORG — the "
               "deleted UTXO projection was load-bearing for recovery, or the "
               "inverse-delta path depends on residual coin state\n");
    }

    CWR_CHECK("PROOF: wiped rebuild count == original count", ab_count_eq);
    CWR_CHECK("PROOF: wiped rebuild commitment == original commitment "
              "(byte-exact SHA3, ACROSS A REORG, from block bodies alone)",
              ab_cmt_eq);
    CWR_CHECK("PROOF: reorged rebuild == direct build of the winner",
              ac_cmt_eq && A.count == C.count);

    cwr_branch_free(&L);
    cwr_branch_free(&W);

    printf("=== coins wipe -> rebuild-across-a-reorg: %d failures ===\n",
           failures);
    return failures;
}
