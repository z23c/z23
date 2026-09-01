/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_coins_applied_frontier — the invariant proof for self-heal P2:
 * coins_applied_height (the canonical contiguous applied-frontier counter for
 * the coins_kv UTXO set) ALWAYS equals the durable utxo_apply stage cursor.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * MAX(coins.height) is the most-recent SURVIVING coin's creation height, NOT a
 * contiguous applied frontier — a missing-fsync interior drop is invisible to
 * it. P2 co-commits coins_applied_height inside the SAME transaction as every
 * coin mutation so the frontier cannot hide an interior hole and gives the
 * self-heal a single non-divergent coins-frontier input. This test pins the
 * load-bearing invariant — coins_applied_height == stage_cursor('utxo_apply') —
 * on the advancing/rewinding/seeding/blocking paths:
 *
 *   (1) a forward apply advance   → frontier == cursor (== tip+1)
 *   (2) failed verdicts           → frontier == cursor because both stay held
 *       at the unresolved height; later heights cannot apply over a hole
 *   (3) a reorg rewind            → frontier PULLED BACK to fork+1 == cursor
 *       (a PLAIN set: the decrease must NOT be blocked by a monotonic floor)
 *   (4) a virgin progress.kv      → get returns found=false (ABSENT, never
 *       0-as-applied); after the boot backfill seeds it from the cursor →
 *       found=true and == cursor.
 *
 * Built on the same synthetic-branch harness as test_stage_reorg_unwind_parity
 * (the closest existing reducer fixture). */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_repair.h"
#include "jobs/utxo_apply_delta.h"
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

#define CAF_CHECK(name, expr) do {                       \
    printf("coins_applied_frontier: %s... ", (name));    \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* No-op step for a throwaway stage_t handle. utxo_apply_reorg_unwind_if_needed
 * uses its `stage` argument ONLY as a non-NULL guard (it reads the cursor from
 * the DB), so this handle is never stepped — it just satisfies stage_create's
 * non-NULL-step requirement so we can fire the unwind directly, bypassing the
 * forward re-advance that would otherwise hide the reorg frontier decrease. */
static job_result_t caf_noop_step(struct stage_step_ctx *c)
{
    (void)c;
    return JOB_IDLE;
}

/* ── External base coins (the pre-fork UTXO set the spends consume) ──── */

struct caf_ext_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    uint32_t height;
    bool is_coinbase;
    uint8_t script[8];
    uint32_t script_len;
};

/* Chain bodies for one branch (index by height; 0 = genesis). */
struct caf_branch {
    struct block       *bodies;
    struct uint256     *hashes;
    struct block_index *blocks;
    int n;            /* number of heights (genesis at 0 .. n-1) */
};

static int caf_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

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

static void make_spend(struct transaction *tx, uint8_t branch_tag, int h,
                       const struct caf_ext_coin *ext)
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
        zcl_calloc(b->num_vtx, sizeof(struct uint256), "caf_leaves");
    for (size_t i = 0; i < b->num_vtx; i++) leaves[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(leaves, b->num_vtx);
    free(leaves);
}

static bool branch_build(struct caf_branch *br, uint8_t tag, int n,
                         int spend_at, const struct caf_ext_coin *ext)
{
    memset(br, 0, sizeof(*br));
    br->n = n;
    br->bodies = zcl_calloc((size_t)n, sizeof(struct block), "caf_bodies");
    br->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "caf_hashes");
    br->blocks = zcl_calloc((size_t)n, sizeof(struct block_index), "caf_blocks");
    if (!br->bodies || !br->hashes || !br->blocks) return false;

    for (int h = 0; h < n; h++) {
        struct block *b = &br->bodies[h];
        block_init(b);
        bool has_spend = (h == spend_at);
        b->num_vtx = has_spend ? 2u : 1u;
        b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "caf_vtx");
        if (!b->vtx) return false;
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

static void branch_free(struct caf_branch *br)
{
    if (br->bodies) {
        for (int h = 0; h < br->n; h++) block_free(&br->bodies[h]);
    }
    free(br->bodies);
    free(br->hashes);
    free(br->blocks);
    memset(br, 0, sizeof(*br));
}

struct caf_ctx {
    struct caf_branch *active;
    const struct caf_ext_coin *ext;
    int n_ext;
};

static bool block_copy(struct block *dst, const struct block *src)
{
    block_init(dst);
    dst->header = src->header;
    dst->num_vtx = src->num_vtx;
    if (src->num_vtx == 0) return true;
    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction), "caf_copy");
    if (!dst->vtx) return false;
    for (size_t i = 0; i < src->num_vtx; i++) {
        transaction_init(&dst->vtx[i]);
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i])) return false;
    }
    return true;
}

static bool caf_reader(struct block *out, const struct block_index *bi,
                       const char *datadir, void *user)
{
    (void)datadir;
    struct caf_ctx *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= c->active->n)
        return false;
    return block_copy(out, &c->active->bodies[bi->nHeight]);
}

static bool caf_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    struct caf_ctx *c = user;
    memset(out, 0, sizeof(*out));
    if (!c) return true;
    for (int i = 0; i < c->n_ext; i++) {
        const struct caf_ext_coin *e = &c->ext[i];
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
    return true;
}

static bool caf_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* Seed proof_validate_log + its cursor. `ok_through` heights are ok=1; if
 * `fail_at >= 0` that single height is recorded ok=0 (drives the
 * upstream_failed blocked path). */
static bool seed_proof_validate(sqlite3 *db, const struct caf_branch *br,
                                int through_height, int fail_at)
{
    if (!db || !br || through_height < 0 || through_height >= br->n)
        return false;
    if (!caf_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)") ||
        !caf_exec(db,
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
        "VALUES (?, ?, ?, 0,0,0,?,1)",
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
        int ok = (h == fail_at) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "verified" : "proof_failed", -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, ok);
        sqlite3_bind_blob(st, 4, br->hashes[h].data, 32, SQLITE_STATIC);
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

static void seed_base_coins(sqlite3 *pdb, const struct caf_ext_coin *ext, int n)
{
    (void)coins_kv_ensure_schema(pdb);
    for (int i = 0; i < n; i++) {
        const struct caf_ext_coin *e = &ext[i];
        (void)coins_kv_add(pdb, e->txid.data, e->vout, e->value,
                           (int32_t)e->height, e->is_coinbase,
                           e->script_len ? e->script : NULL, e->script_len);
    }
}

/* The single invariant: coins_applied_height present AND == the durable
 * utxo_apply stage cursor. Returns true iff it holds. */
static bool frontier_eq_cursor(sqlite3 *db)
{
    int32_t frontier = -777;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &frontier, &found))
        return false;
    if (!found)
        return false;
    uint64_t cursor = stage_cursor_persisted(db, "utxo_apply", "caf_test");
    return (uint64_t)frontier == cursor;
}

int test_coins_applied_frontier(void);
int test_coins_applied_frontier(void)
{
    printf("\n=== coins_applied_height contiguous-frontier invariant test ===\n");
    int failures = 0;

    blocker_module_init();
    caf_mkdir_p("./test-tmp");

    struct caf_ext_coin ext[2];
    memset(ext, 0, sizeof(ext));
    ext[0].txid.data[0] = 0xE7; ext[0].txid.data[1] = 0x0A; /* EXT_L */
    ext[0].vout = 0; ext[0].value = 500000000LL; ext[0].height = 0;
    ext[0].script[0] = 0x76; ext[0].script[1] = 0xa9; ext[0].script[2] = 0xAA;
    ext[0].script_len = 3;
    ext[1].txid.data[0] = 0xE7; ext[1].txid.data[1] = 0x0B; /* EXT_W */
    ext[1].vout = 0; ext[1].value = 600000000LL; ext[1].height = 0;
    ext[1].script[0] = 0x76; ext[1].script[1] = 0xa9; ext[1].script[2] = 0xBC;
    ext[1].script_len = 3;

    /* ── PART A: virgin datadir → ABSENT; forward apply; reorg rewind —
     *           frontier == cursor on every path. ─────────────────────── */
    struct caf_branch L, W;
    bool built = branch_build(&L, 0x11, 4, 2, &ext[0]) &&
                 branch_build(&W, 0x22, 5, 2, &ext[1]);
    CAF_CHECK("branches build", built);

    if (built) {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "main");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        CAF_CHECK("progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);
        CAF_CHECK("event log opens", lg != NULL);

        if (lg) {
            sqlite3 *pdb = progress_store_db();

            /* (4a) VIRGIN: before any stage activity coins_applied_height is
             * ABSENT — a fresh datadir is NOT 0-as-applied. */
            int32_t f0 = -1; bool found0 = true;
            CAF_CHECK("virgin: get succeeds",
                      coins_kv_get_applied_height(pdb, &f0, &found0));
            CAF_CHECK("virgin: found == false (ABSENT, never 0-as-applied)",
                      found0 == false);

            seed_base_coins(pdb, ext, 2);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            active_chain_init(&ms.chain_active);
            active_chain_move_window_tip(&ms.chain_active, &L.blocks[L.n - 1]);

            struct caf_ctx ctx = { .active = &L, .ext = ext, .n_ext = 2 };
            CAF_CHECK("stage init (also runs boot backfill)",
                      utxo_apply_stage_init(&ms));
            utxo_apply_stage_set_reader(caf_reader, &ctx);
            utxo_apply_stage_set_lookup(caf_lookup, &ctx);

            /* (4b) BOOT BACKFILL on a virgin datadir: no cursor row exists yet,
             * so backfill leaves the key ABSENT (never seeds from MAX(coins)).
             * The first forward apply writes it in lockstep with the cursor. */
            int32_t fb = -1; bool foundb = true;
            CAF_CHECK("virgin backfill: still ABSENT (no cursor row to seed)",
                      coins_kv_get_applied_height(pdb, &fb, &foundb) &&
                      foundb == false);

            /* (1) FORWARD APPLY: drive L's genesis + 3 blocks. The losing
             * branch L spends EXT_L at h2. frontier must == cursor == L.n. */
            CAF_CHECK("L seed proof_validate (all ok)",
                      seed_proof_validate(pdb, &L, L.n - 1, -1));
            int adv_l = utxo_apply_stage_drain(100);
            CAF_CHECK("L drains all", adv_l == L.n);
            CAF_CHECK("forward apply: frontier == cursor", frontier_eq_cursor(pdb));
            {
                int32_t fr = -1; bool fnd = false;
                (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                CAF_CHECK("forward apply: frontier present && == L tip+1",
                          fnd && fr == L.n);
            }

            /* OPERATOR DISCONNECT / SHORTER-WINDOW REORG.  invalidateblock
             * first retracts the raw active window to the target's parent, so
             * there is deliberately no active slot at the old applied height
             * C-1.  That absence must drive the same inverse-delta path as a
             * same-height competing winner; treating it as an unknown/no-op
             * leaves both coins and the durable cursor above the invalidated
             * block.  Pin the decrease before reconnecting L's tip. */
            CAF_CHECK("short disconnect: old tip is hash-addressable",
                      block_map_insert(&ms.map_block_index,
                                       L.blocks[L.n - 1].phashBlock,
                                       &L.blocks[L.n - 1]));
            L.blocks[L.n - 1].nStatus |= BLOCK_FAILED_VALID;
            CAF_CHECK("short disconnect: failed verdict is exact old tip",
                      block_has_any_failure(&L.blocks[L.n - 1]));
            CAF_CHECK("short disconnect: retract active window one block",
                      active_chain_move_window_tip(
                          &ms.chain_active, &L.blocks[L.n - 2]));
            {
                stage_t *probe = stage_create("utxo_apply", caf_noop_step, NULL);
                CAF_CHECK("short disconnect: probe stage_create", probe != NULL);
                _Atomic uint64_t unwound_n = 0;
                _Atomic int64_t blocked_t = 0;
                progress_store_tx_lock();
                bool unwound = utxo_apply_reorg_unwind_if_needed(
                    pdb, probe, &ms, &unwound_n, &blocked_t);
                progress_store_tx_unlock();
                CAF_CHECK("short disconnect: unwind succeeds", unwound);
                CAF_CHECK("short disconnect: unwind counted once",
                          (uint64_t)unwound_n == 1);
                CAF_CHECK("short disconnect: frontier == cursor at parent+1",
                          frontier_eq_cursor(pdb));
                int32_t fr = -999; bool fnd = false;
                (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                CAF_CHECK("short disconnect: frontier retreats exactly one",
                          fnd && fr == L.n - 1);
                if (probe) stage_destroy(probe);
            }
            L.blocks[L.n - 1].nStatus &= ~(unsigned)BLOCK_FAILED_ANY_MASK;
            CAF_CHECK("short disconnect: reconsider old tip",
                      !block_has_any_failure(&L.blocks[L.n - 1]));
            CAF_CHECK("short disconnect: restore active L tip",
                      active_chain_move_window_tip(
                          &ms.chain_active, &L.blocks[L.n - 1]));
            CAF_CHECK("short disconnect: re-apply disconnected tip",
                      utxo_apply_stage_drain(100) >= 1);
            CAF_CHECK("short disconnect: reconnect restores frontier",
                      frontier_eq_cursor(pdb));
            {
                int32_t fr = -1; bool fnd = false;
                (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                CAF_CHECK("short disconnect: frontier returns to L tip+1",
                          fnd && fr == L.n);
            }

            /* (3) REORG REWIND: install heavier W on active_chain, extend
             * proof_validate. L and W share only genesis (h0, tag 0x00) and
             * diverge at h1, so the fork point is 0 and the unwind pulls the
             * cursor + frontier BACK to fork+1 == 1.
             *
             * LOAD-BEARING (SERIOUS FIX 2): fire the unwind ALONE (no forward
             * re-advance) and snapshot the frontier AT THE MOMENT OF THE
             * DECREASE, asserting it == fork+1 (1). If we only drained to the
             * final quiescent state, the forward re-advance over the heavier W
             * would immediately re-write the frontier up to W.n and every
             * assertion would still pass even with the reorg co-commit DELETED
             * (the forward apply heals it). Pinning the decrease HERE — in the
             * window between the unwind and the first re-apply — catches BOTH
             * regressions the reorg co-commit guards against:
             *   1. DELETING coins_kv_set_applied_height_in_tx(db, fork_plus1) in
             *      utxo_apply_delta_reorg.c → frontier stranded at the old high
             *      (4) while the cursor drops to 1 → frontier != cursor, frd != 1;
             *   2. re-introducing a MONOTONIC FLOOR in the setter → the floor
             *      blocks the plain-set decrease, leaving frontier at 4 while the
             *      cursor drops to 1 → frontier != cursor, frd != 1.
             * The strictly-shorter operator-disconnect case is pinned above;
             * this second snapshot retains coverage for a same-height branch
             * replacement whose fork is genesis.) */
            int32_t pre_reorg_frontier = -1; bool pre_found = false;
            (void)coins_kv_get_applied_height(pdb, &pre_reorg_frontier,
                                              &pre_found);
            CAF_CHECK("pre-reorg frontier present (== L.n)",
                      pre_found && pre_reorg_frontier == L.n);

            ctx.active = &W;
            active_chain_move_window_tip(&ms.chain_active, &W.blocks[W.n - 1]);
            CAF_CHECK("W seed proof_validate (all ok)",
                      seed_proof_validate(pdb, &W, W.n - 1, -1));

            /* Fire the reorg unwind directly, BYPASSING the forward re-advance
             * (utxo_apply_stage_step_once would unwind AND re-apply one height in
             * the same call, hiding the decrease). The unwind reads the cursor
             * from the DB and uses `stage` only as a non-NULL guard, so a
             * throwaway handle is sufficient; the progress_store tx lock is
             * recursive, so wrapping the call mirrors production's
             * step_once discipline exactly. */
            {
                stage_t *probe = stage_create("utxo_apply", caf_noop_step, NULL);
                CAF_CHECK("reorg probe stage_create", probe != NULL);
                _Atomic uint64_t unwound_n = 0;
                _Atomic int64_t  blocked_t = 0;
                progress_store_tx_lock();
                bool unwound = utxo_apply_reorg_unwind_if_needed(
                    pdb, probe, &ms, &unwound_n, &blocked_t);
                progress_store_tx_unlock();
                CAF_CHECK("reorg unwind fires alone (no re-advance)", unwound);
                CAF_CHECK("reorg unwind counted exactly once",
                          (uint64_t)unwound_n == 1);
                /* AT THE MOMENT OF THE DECREASE: cursor + frontier both pulled
                 * to fork+1 == 1, strictly BELOW the pre-reorg frontier (4). */
                CAF_CHECK("reorg decrease: frontier == cursor (== fork+1)",
                          frontier_eq_cursor(pdb));
                int32_t frd = -999; bool fndd = false;
                (void)coins_kv_get_applied_height(pdb, &frd, &fndd);
                CAF_CHECK("reorg decrease: frontier DECREASED to fork+1 (1), "
                          "strictly below pre-reorg frontier",
                          fndd && frd == 1 && frd < pre_reorg_frontier);
                if (probe) stage_destroy(probe);
            }

            /* Now re-advance forward over the heavier W to the quiescent tip. */
            int adv_w = utxo_apply_stage_drain(100);
            CAF_CHECK("re-advanced over W", adv_w >= W.n - 1);
            CAF_CHECK("after reorg rewind: frontier == cursor",
                      frontier_eq_cursor(pdb));
            {
                int32_t fr = -1; bool fnd = false;
                (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                CAF_CHECK("after reorg: frontier present && == W tip+1",
                          fnd && fr == W.n);
            }

            utxo_apply_stage_shutdown();
            active_chain_free(&ms.chain_active);
        }
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── PART B: upstream_failed blocked path (no coin mutation). ─────── */
    struct caf_branch F;
    bool fbuilt = branch_build(&F, 0x33, 4, -1, NULL);  /* no spends */
    CAF_CHECK("fail-branch builds", fbuilt);

    if (fbuilt) {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "upfail");
        char log_path[512];
        snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

        CAF_CHECK("upfail: progress_store opens", progress_store_open(dir));
        event_log_t *lg = event_log_open(log_path);

        if (lg) {
            sqlite3 *pdb = progress_store_db();

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            active_chain_init(&ms.chain_active);
            active_chain_move_window_tip(&ms.chain_active, &F.blocks[F.n - 1]);

            struct caf_ctx ctx = { .active = &F, .ext = ext, .n_ext = 0 };
            CAF_CHECK("upfail: stage init", utxo_apply_stage_init(&ms));
            utxo_apply_stage_set_reader(caf_reader, &ctx);
            utxo_apply_stage_set_lookup(caf_lookup, &ctx);

            blocker_clear("utxo_apply.apply_failed");
            /* Mark height 2 as upstream ok=0 → step_apply blocks at h2. The
             * prior successful h0/h1 applies leave cursor/frontier == 2, and
             * the failed h2 row is rolled back so no later height can apply over
             * the hole. */
            CAF_CHECK("upfail: seed proof_validate with ok=0 at h2",
                      seed_proof_validate(pdb, &F, F.n - 1, 2));
            int adv = utxo_apply_stage_drain(100);
            CAF_CHECK("upfail: drains until h2", adv == 2);
            CAF_CHECK("upfail: recorded an upstream_failed block",
                      utxo_apply_stage_upstream_failed_total() >= 1);
            CAF_CHECK("upstream_failed blocked: frontier == cursor",
                      frontier_eq_cursor(pdb));
            CAF_CHECK("upstream_failed blocked: typed blocker recorded",
                      blocker_exists("utxo_apply.apply_failed"));
            {
                int32_t fr = -1; bool fnd = false;
                (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                CAF_CHECK("upstream_failed: frontier present && == h2",
                          fnd && fr == 2);
            }
            blocker_clear("utxo_apply.apply_failed");

            utxo_apply_stage_shutdown();
            active_chain_free(&ms.chain_active);
        }
        if (lg) event_log_close(lg);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── PART C: boot backfill SEEDS from an existing cursor (no key yet). ─
     * Simulate an existing datadir that has a durable utxo_apply cursor but no
     * coins_applied_height key (predates P2): the backfill must seed the
     * frontier == cursor, NOT from MAX(coins.height). ──────────────────── */
    {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "backfill");
        CAF_CHECK("backfill: progress_store opens", progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        (void)coins_kv_ensure_schema(pdb);

        /* NEGATIVE CONTROL (hardening #4): stamp a durable utxo_apply cursor at
         * 123 AND seed live coins whose MAX(height) is 200 (deliberately HIGHER
         * than the cursor and DIFFERENT from it). The backfill must seed the
         * frontier from the CURSOR (123), NEVER from MAX(coins.height) (200) —
         * the whole point of P2 (MAX(coins.height) is the most-recent surviving
         * coin's creation height, not a contiguous applied frontier). If the
         * backfill ever regressed to MAX(coins.height) this asserts 123 != 200
         * and FAILS. */
        {
            uint8_t ctxid[32] = {0};
            ctxid[0] = 0xC0; ctxid[1] = 0xDE;
            uint8_t pk[3] = { 0x76, 0xa9, 0xCC };
            CAF_CHECK("backfill: seed a live coin at height 200 (> cursor 123)",
                      coins_kv_add(pdb, ctxid, 0, 999000000LL,
                                   (int32_t)200, false, pk, sizeof(pk)));
        }
        CAF_CHECK("backfill: stamp utxo_apply cursor=123",
                  caf_exec(pdb,
                    "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
                    "VALUES('utxo_apply', 123, 1)"));

        int32_t before = -1; bool found_before = true;
        CAF_CHECK("backfill: key ABSENT before backfill",
                  coins_kv_get_applied_height(pdb, &before, &found_before) &&
                  found_before == false);

        CAF_CHECK("backfill: runs", coins_kv_backfill_applied_height_if_absent(
                      pdb, coins_kv_set_applied_height_in_tx));

        int32_t after = -999; bool found_after = false;
        CAF_CHECK("backfill: key present after backfill",
                  coins_kv_get_applied_height(pdb, &after, &found_after) &&
                  found_after == true);
        CAF_CHECK("backfill: seeded value == cursor (123), NOT MAX(coins.height) (200)",
                  after == 123);
        CAF_CHECK("backfill: frontier == cursor after seed", frontier_eq_cursor(pdb));

        /* Idempotent: a second call is a no-op and never re-seeds (would block
         * a later legitimate rewind). Lower the cursor and confirm the key is
         * unchanged. */
        CAF_CHECK("backfill: lower cursor to 50",
                  caf_exec(pdb,
                    "UPDATE stage_cursor SET cursor=50 WHERE name='utxo_apply'"));
        CAF_CHECK("backfill: second call no-ops",
                  coins_kv_backfill_applied_height_if_absent(
                      pdb, coins_kv_set_applied_height_in_tx));
        int32_t after2 = -1; bool found2 = false;
        (void)coins_kv_get_applied_height(pdb, &after2, &found2);
        CAF_CHECK("backfill: idempotent — frontier unchanged (still 123)",
                  found2 && after2 == 123);

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── PART D: poison_rewind co-writes the frontier (SERIOUS FIX 1). ────
     * The poison_rewind is the THIRD production writer of the utxo_apply stage
     * cursor: it forces the cursor DOWN to the frontier height and deletes the
     * downstream logs. Before SERIOUS FIX 1 it left coins_applied_height at its
     * old (higher) value → a DURABLE stale-HIGH frontier the if-absent backfill
     * could never correct. After the fix it co-writes frontier = height inside
     * the SAME BEGIN IMMEDIATE, so coins_applied_height == the rewound utxo_apply
     * cursor. This pins that. */
    {
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "poison");
        CAF_CHECK("poison: progress_store opens", progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        (void)coins_kv_ensure_schema(pdb);

        /* Schema the rewind touches (mirrors the reducer's *_log tables). */
        bool sch =
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS validate_headers_log("
                "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
                "fail_reason TEXT, validated_at INTEGER NOT NULL)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS body_fetch_log("
                "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, source TEXT NOT NULL,"
                "bytes INTEGER NOT NULL DEFAULT 0, fetched_at INTEGER NOT NULL,"
                "ok INTEGER NOT NULL, fail_reason TEXT)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS body_persist_log("
                "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER, persisted_at INTEGER)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS script_validate_log("
                "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS proof_validate_log("
                "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS utxo_apply_log("
                "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS utxo_apply_delta("
                "height INTEGER PRIMARY KEY)") &&
            caf_exec(pdb, "CREATE TABLE IF NOT EXISTS tip_finalize_log("
                "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER)");
        CAF_CHECK("poison: reducer log schema created", sch);
        CAF_CHECK("poison: stage_cursor table ensured", stage_table_ensure(pdb));

        /* Simulate a pipeline applied forward through height 9 (frontier = 10):
         * ok=1 utxo_apply rows at [0..9], the utxo_apply cursor at 10, and the
         * applied frontier stamped at 10 (== cursor, the P2 steady state). */
        const int FRONTIER = 10;
        bool seeded = true;
        for (int h = 0; h < FRONTIER && seeded; h++) {
            char sql[160];
            snprintf(sql, sizeof(sql),
                "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
                "VALUES(%d,'verified',1)", h);
            seeded = caf_exec(pdb, sql);
        }
        CAF_CHECK("poison: seed ok=1 utxo_apply rows [0..9]", seeded);
        CAF_CHECK("poison: stamp utxo_apply cursor=10", caf_exec(pdb,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('utxo_apply',10,1)"));
        CAF_CHECK("poison: stamp applied frontier=10 (== cursor)",
                  coins_kv_backfill_applied_height_if_absent(
                      pdb, coins_kv_set_applied_height_in_tx));
        CAF_CHECK("poison: precondition frontier == cursor (10)",
                  frontier_eq_cursor(pdb));

        /* Seed the DOWNSTREAM_STALE poison shape AT the frontier (height 10):
         * validate_headers ok=1, body_fetch skipped_invalid/header_validation_failed,
         * and ok=0 downstream rows — the exact shape poison_mode classifies as
         * STAGE_REPAIR_POISON_DOWNSTREAM_STALE. No ok=1 row sits at/above 10 in
         * any success_checked_log, so the rewind proceeds. */
        char ps[2048];
        snprintf(ps, sizeof(ps),
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,fail_reason,validated_at) VALUES(10,zeroblob(32),1,NULL,1);"
            "INSERT OR REPLACE INTO body_fetch_log"
            "(height,hash,source,bytes,fetched_at,ok,fail_reason) "
            "VALUES(10,zeroblob(32),'skipped_invalid',0,1,0,'header_validation_failed');"
            "INSERT OR REPLACE INTO body_persist_log(height,source,ok,persisted_at) "
            "VALUES(10,'upstream_failed',0,1);"
            "INSERT OR REPLACE INTO script_validate_log(height,status,ok) "
            "VALUES(10,'upstream_failed',0);"
            "INSERT OR REPLACE INTO proof_validate_log(height,status,ok) "
            "VALUES(10,'upstream_failed',0);"
            "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
            "VALUES(10,'upstream_failed',0);");
        CAF_CHECK("poison: seed DOWNSTREAM_STALE poison shape at frontier", caf_exec(pdb, ps));

        /* Invoke the rewind AT the frontier (active_tip = 9). It forces the
         * utxo_apply cursor DOWN to 10 (== the frontier height) and — with
         * SERIOUS FIX 1 — co-writes coins_applied_height = 10 in the same txn. */
        struct stage_repair_header_solution_result res;
        bool rv = stage_repair_header_solution_poison_rewind(pdb, FRONTIER,
                                                             FRONTIER - 1, &res);
        CAF_CHECK("poison: rewind succeeds", rv && res.repaired);
        /* utxo_apply cursor forced to the frontier height (10). */
        CAF_CHECK("poison: utxo_apply cursor rewound to frontier height",
                  stage_cursor_persisted(pdb, "utxo_apply", "caf_test") ==
                  (uint64_t)FRONTIER);
        /* THE FIX: frontier co-moved with the cursor — equal, not stale-high. */
        CAF_CHECK("poison: coins_applied_height == utxo_apply cursor (co-written)",
                  frontier_eq_cursor(pdb));
        {
            int32_t fr = -1; bool fnd = false;
            (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
            CAF_CHECK("poison: frontier present && == frontier height (10)",
                      fnd && fr == FRONTIER);
        }

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── PART E: non-fatal reject (spend_unknown_utxo) blocks. ────────────
     * A summary.ok==false spend_unknown_utxo leaves the coins UNMUTATED and
     * holds the cursor/frontier at the unresolved height. This pins the
     * fail-closed policy that prevents later heights applying above a hole. */
    {
        /* A branch that spends a coin NOT present in coins_kv and NOT resolvable
         * by the lookup (n_ext = 0 below) → spend_unknown_utxo at h2. */
        struct caf_ext_coin phantom;
        memset(&phantom, 0, sizeof(phantom));
        phantom.txid.data[0] = 0xDE; phantom.txid.data[1] = 0xAD;
        phantom.vout = 0; phantom.value = 400000000LL; phantom.height = 0;
        phantom.script[0] = 0x76; phantom.script_len = 1;

        struct caf_branch R;
        bool rbuilt = branch_build(&R, 0x44, 4, 2, &phantom);
        CAF_CHECK("reject-branch builds", rbuilt);

        if (rbuilt) {
            char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "reject");
            char log_path[512];
            snprintf(log_path, sizeof(log_path), "%s/events.log", dir);

            CAF_CHECK("reject: progress_store opens", progress_store_open(dir));
            event_log_t *lg = event_log_open(log_path);

            if (lg) {
                sqlite3 *pdb = progress_store_db();

                struct main_state ms;
                memset(&ms, 0, sizeof(ms));
                active_chain_init(&ms.chain_active);
                active_chain_move_window_tip(&ms.chain_active, &R.blocks[R.n - 1]);

                /* n_ext = 0 → caf_lookup never resolves the phantom spend. */
                struct caf_ctx ctx = { .active = &R, .ext = ext, .n_ext = 0 };
                CAF_CHECK("reject: stage init", utxo_apply_stage_init(&ms));
                utxo_apply_stage_set_reader(caf_reader, &ctx);
                utxo_apply_stage_set_lookup(caf_lookup, &ctx);
                blocker_clear("utxo_apply.apply_failed");

                CAF_CHECK("reject: seed proof_validate (all ok)",
                          seed_proof_validate(pdb, &R, R.n - 1, -1));
                int adv = utxo_apply_stage_drain(100);
                CAF_CHECK("reject: drains until h2", adv == 2);
                CAF_CHECK("reject: recorded a spend_unknown_utxo (coins not mutated)",
                          utxo_apply_stage_spend_unknown_total() >= 1);
                CAF_CHECK("non-fatal reject blocked: frontier == cursor",
                          frontier_eq_cursor(pdb));
                CAF_CHECK("reject: typed blocker recorded",
                          blocker_exists("utxo_apply.apply_failed"));
                {
                    int32_t fr = -1; bool fnd = false;
                    (void)coins_kv_get_applied_height(pdb, &fr, &fnd);
                    CAF_CHECK("reject: frontier present && == h2",
                              fnd && fr == 2);
                }
                blocker_clear("utxo_apply.apply_failed");

                utxo_apply_stage_shutdown();
                active_chain_free(&ms.chain_active);
            }
            if (lg) event_log_close(lg);
            progress_store_close();
            test_cleanup_tmpdir(dir);
        }
        branch_free(&R);
    }

    /* ── PART F: coins_kv_seed_genesis_applied_height (regtest genesis mint
     * bootstrap). A pristine from-genesis store gets coins_applied_height=1;
     * every non-pristine shape (already-present / borrowed-proven / coins
     * present / cursor present) is a fail-closed no-op. ─────────────────── */
    {
        /* (1) Pristine store: no key, no coins, no cursor, not proven → seed 1. */
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "gseed");
        CAF_CHECK("gseed: progress_store opens", progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        (void)coins_kv_ensure_schema(pdb);
        int32_t v = -1; bool found = true;
        CAF_CHECK("gseed: key ABSENT before seed",
                  coins_kv_get_applied_height(pdb, &v, &found) && !found);
        CAF_CHECK("gseed: seed runs on a pristine from-genesis store",
                  coins_kv_seed_genesis_applied_height(
                      pdb, coins_kv_set_applied_height_in_tx));
        CAF_CHECK("gseed: coins_applied_height == 1 (genesis applied)",
                  coins_kv_get_applied_height(pdb, &v, &found) && found && v == 1);
        /* (2) Idempotent: a second call never re-seeds. */
        CAF_CHECK("gseed: second call no-ops",
                  coins_kv_seed_genesis_applied_height(
                      pdb, coins_kv_set_applied_height_in_tx));
        v = -1; found = false;
        CAF_CHECK("gseed: idempotent — still 1",
                  coins_kv_get_applied_height(pdb, &v, &found) && found && v == 1);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }
    {
        /* (3) Coins already present → not pristine → no-op (key stays ABSENT). */
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "gseedcoins");
        CAF_CHECK("gseed-coins: progress_store opens", progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        (void)coins_kv_ensure_schema(pdb);
        uint8_t ctxid[32] = {0}; ctxid[0] = 0xAB; uint8_t pk[3] = { 0x76, 0xa9, 0xCC };
        CAF_CHECK("gseed-coins: seed a live coin at height 5",
                  coins_kv_add(pdb, ctxid, 0, 100000000LL, (int32_t)5, false, pk, sizeof(pk)));
        CAF_CHECK("gseed-coins: seed no-ops with coins present",
                  coins_kv_seed_genesis_applied_height(
                      pdb, coins_kv_set_applied_height_in_tx));
        int32_t v = -1; bool found = true;
        CAF_CHECK("gseed-coins: key still ABSENT (not a pristine genesis store)",
                  coins_kv_get_applied_height(pdb, &v, &found) && !found);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }
    {
        /* (4) utxo_apply cursor already stamped → not pristine → no-op. */
        char dir[256]; test_make_tmpdir(dir, sizeof(dir), "coins_applied_frontier", "gseedcur");
        CAF_CHECK("gseed-cursor: progress_store opens", progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        (void)coins_kv_ensure_schema(pdb);
        CAF_CHECK("gseed-cursor: stamp utxo_apply cursor=7",
                  caf_exec(pdb, "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
                                "VALUES('utxo_apply',7,1)"));
        CAF_CHECK("gseed-cursor: seed no-ops with a stamped cursor",
                  coins_kv_seed_genesis_applied_height(
                      pdb, coins_kv_set_applied_height_in_tx));
        int32_t v = -1; bool found = true;
        CAF_CHECK("gseed-cursor: key still ABSENT (fold already started)",
                  coins_kv_get_applied_height(pdb, &v, &found) && !found);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    branch_free(&L);
    branch_free(&W);
    branch_free(&F);

    printf("=== coins_applied_height frontier invariant: %d failures ===\n", failures);
    return failures;
}
