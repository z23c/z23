/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Explorer projection writers — the full per-block indexer.
 *
 * One model TU grouping every read-derived explorer-projection writer so
 * the per-block hook in node_db_catchup_service.c stays a single call and
 * the service file stays under the E1 file-size ceiling. Each save uses the
 * cached-statement AR lifecycle (AR_BEGIN_SAVE → reset → bind → AR_STEP_DONE
 * → AR_FINISH_SAVE), modeled on db_tx_save (tx_index.c).
 *
 * node.db ONLY — see explorer_index.h. */

#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "script/standard.h"
#include "crypto/sha3.h"
#include "overlay/overlay_projection.h"
#include "zslp/slp.h"
#include "sapling/constants.h"
#include "util/log_macros.h"
#include <string.h>

/* ── Validation records ────────────────────────────────────────────
 * The projection rows have no persistent struct of their own (they are
 * derived per-tx and written immediately), so each save builds a tiny
 * validation record and runs validates_* over it. This satisfies the E11
 * model-validation gate while keeping every save a single bind+step. */

struct explorer_row_v {
    uint8_t txid[32];
    int block_height;
    int index_pos;
};

static bool explorer_row_validate(const struct explorer_row_v *r,
                                  struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, r, txid);
    validates_non_negative(errors, r, block_height);
    validates_non_negative(errors, r, index_pos);
    return !ar_errors_any(errors);
}

DEFINE_MODEL_CALLBACKS(explorer)

/* ── Transparent outputs ───────────────────────────────────────────── */

bool db_tx_output_save(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t vout, int64_t value, int script_type,
                       const uint8_t *address_hash, int block_height)
{
    if (!ndb || !ndb->open || !txid)
        LOG_FAIL("explorer", "db_tx_output_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = (int)vout;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "tx_output", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_txo_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vout);
    AR_BIND_INT(s, 3, value);
    AR_BIND_INT(s, 4, script_type);
    if (address_hash)
        AR_BIND_BLOB(s, 5, address_hash, 20);
    else
        AR_BIND_NULL(s, 5);
    AR_BIND_INT(s, 6, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── Transparent inputs ────────────────────────────────────────────── */

bool db_tx_input_save(struct node_db *ndb, const uint8_t txid[32],
                      uint32_t vin_index, const uint8_t prev_txid[32],
                      uint32_t prev_vout, int block_height)
{
    if (!ndb || !ndb->open || !txid || !prev_txid)
        LOG_FAIL("explorer", "db_tx_input_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = (int)vin_index;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "tx_input", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_txi_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)vin_index);
    AR_BIND_BLOB(s, 3, prev_txid, 32);
    AR_BIND_INT(s, 4, (int)prev_vout);
    AR_BIND_INT(s, 5, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── OP_RETURN ──────────────────────────────────────────────────────── */

bool db_op_return_save(struct node_db *ndb, const uint8_t txid[32],
                       int block_height, const uint8_t *script,
                       size_t script_len, bool is_slp)
{
    if (!ndb || !ndb->open || !txid || !script)
        LOG_FAIL("explorer", "db_op_return_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = 0;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "op_return", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_opret_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, block_height);
    AR_BIND_BLOB(s, 3, script, script_len);
    AR_BIND_INT(s, 4, is_slp ? 1 : 0);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── Sapling spends ────────────────────────────────────────────────── */

bool db_sapling_spend_save(struct node_db *ndb, const uint8_t txid[32],
                           uint32_t spend_index,
                           const struct spend_description *sd,
                           int block_height)
{
    if (!ndb || !ndb->open || !txid || !sd)
        LOG_FAIL("explorer", "db_sapling_spend_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = (int)spend_index;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "sapling_spend", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_sspend_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)spend_index);
    AR_BIND_BLOB(s, 3, sd->cv.data, 32);
    AR_BIND_BLOB(s, 4, sd->anchor.data, 32);
    AR_BIND_BLOB(s, 5, sd->nullifier.data, 32);
    AR_BIND_BLOB(s, 6, sd->rk.data, 32);
    AR_BIND_INT(s, 7, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── Sapling outputs ───────────────────────────────────────────────── */

bool db_sapling_output_save(struct node_db *ndb, const uint8_t txid[32],
                            uint32_t output_index,
                            const struct output_description *od,
                            int block_height)
{
    if (!ndb || !ndb->open || !txid || !od)
        LOG_FAIL("explorer", "db_sapling_output_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = (int)output_index;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "sapling_output", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_soutput_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)output_index);
    AR_BIND_BLOB(s, 3, od->cv.data, 32);
    AR_BIND_BLOB(s, 4, od->cm.data, 32);
    AR_BIND_BLOB(s, 5, od->ephemeral_key.data, 32);
    AR_BIND_INT(s, 6, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── Sprout JoinSplits ─────────────────────────────────────────────── */

bool db_joinsplit_save(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t js_index, const struct js_description *jsd,
                       int block_height)
{
    if (!ndb || !ndb->open || !txid || !jsd)
        LOG_FAIL("explorer", "db_joinsplit_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = (int)js_index;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "joinsplit", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_js_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, txid, 32);
    AR_BIND_INT(s, 2, (int)js_index);
    AR_BIND_INT(s, 3, jsd->vpub_old);
    AR_BIND_INT(s, 4, jsd->vpub_new);
    AR_BIND_BLOB(s, 5, jsd->anchor.data, 32);
    AR_BIND_INT(s, 6, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── Sprout nullifiers ─────────────────────────────────────────────── */

bool db_sprout_nullifier_save(struct node_db *ndb, const uint8_t nullifier[32],
                              const uint8_t txid[32], int block_height)
{
    if (!ndb || !ndb->open || !nullifier || !txid)
        LOG_FAIL("explorer", "db_sprout_nullifier_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memcpy(rec.txid, txid, 32);
    rec.block_height = block_height;
    rec.index_pos = 0;

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "sprout_nullifier", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_spnf_insert;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, nullifier, 32);
    AR_BIND_BLOB(s, 2, txid, 32);
    AR_BIND_INT(s, 3, block_height);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

/* ── view_integrity receipt ────────────────────────────────────────── */

bool db_view_integrity_save(struct node_db *ndb, int64_t height,
                            const uint8_t sha3[32])
{
    if (!ndb || !ndb->open || !sha3)
        LOG_FAIL("explorer", "db_view_integrity_save: invalid args (ndb=%p)",
                 (void *)ndb);

    struct explorer_row_v rec;
    memset(rec.txid, 0xFF, 32);    /* txid presence unused for this table */
    rec.block_height = (int)(height < 0 ? -1 : height & 0x7fffffff);
    rec.index_pos = 0;
    if (height < 0)
        LOG_FAIL("explorer", "db_view_integrity_save: negative height %lld",
                 (long long)height);

    struct ar_callbacks *cbs = db_explorer_callbacks();
    AR_BEGIN_SAVE(cbs, "view_integrity", &rec, explorer_row_validate);

    sqlite3_stmt *s = ndb->stmt_vint_insert;
    AR_RESET(s);
    AR_BIND_INT(s, 1, height);
    AR_BIND_BLOB(s, 2, sha3, 32);

    bool ok = AR_STEP_DONE(s);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_view_integrity_get(struct node_db *ndb, int64_t height,
                           uint8_t sha3_out[32])
{
    if (!ndb || !ndb->open || height < 0 || !sha3_out)
        return false;

    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
                    "SELECT sha3_hash FROM view_integrity WHERE height=?");
    AR_BIND_INT(s, 1, height);

    bool found = false;
    if (AR_STEP_ROW(s)) {
        const void *blob = sqlite3_column_blob(s, 0);
        int blob_len = sqlite3_column_bytes(s, 0);
        if (blob && blob_len == 32) {
            memcpy(sha3_out, blob, 32);
            found = true;
        }
    }
    AR_FINALIZE(s);
    return found;
}

int64_t db_view_integrity_max_height(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return -1;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s, "SELECT MAX(height) FROM view_integrity", -1);
    int64_t h = -1;
    if (AR_STEP_ROW(s))
        h = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return h;
}

/* ── Owner-derivation helper ───────────────────────────────────────── */

bool db_tx_output_addr(struct node_db *ndb, const uint8_t txid[32],
                       uint32_t vout, uint8_t addr20[20])
{
    if (!ndb || !ndb->open || !txid || !addr20)
        return false;
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT address_hash FROM tx_outputs WHERE txid=? AND vout=?"
        " AND address_hash IS NOT NULL",
        (AR_BIND_BLOB(s, 1, txid, 32), AR_BIND_INT(s, 2, (int)vout)),
        AR_READ_BLOB(s, 0, addr20, 20));
}

/* ── Reindex truncate ──────────────────────────────────────────────── */

bool db_explorer_index_truncate(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("explorer", "db_explorer_index_truncate: db not open");

    static const char *const tables[] = {
        "tx_outputs", "tx_inputs", "op_returns",
        "sapling_spends", "sapling_outputs", "joinsplits",
        "sprout_nullifiers", "view_integrity",
        "znam_names", "znam_text_records", "znam_addr_records",
        "zslp_tokens", "zslp_transfers", "zslp_balances",
        /* Both ZID feeds are stateful the same way ZNAM FCFS is (a ROTATE
         * reads the row its ANCHOR wrote), so a partial replay over surviving
         * rows is not equivalent to the genesis..tip walk. Clear it. */
        "zid_identities",
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[64];
        snprintf(sql, sizeof(sql), "DELETE FROM %s", tables[i]);
        if (!node_db_exec(ndb, sql))
            LOG_FAIL("explorer",
                     "db_explorer_index_truncate: DELETE FROM %s failed",
                     tables[i]);
    }
    /* The per-outpoint ledger is DOWNSTREAM of these source projections
     * (zslp_transfers / tx_outputs / tx_inputs), so a reindex must reset it
     * — rows AND cursor/digest — so the backfill re-derives it once the
     * source tables are repopulated. */
    if (!zslp_ledger_truncate(ndb))
        LOG_FAIL("explorer",
                 "db_explorer_index_truncate: zslp_ledger reset failed");
    return true;
}

/* ── op_return dispatch ────────────────────────────────────────────── */

/* Persist the generic op_returns row (one per tx), then hand the script to
 * the ONE overlay dispatcher. Called only for the FIRST OP_RETURN output of
 * the tx (op_returns PK is txid). */
static void index_op_return(struct node_db *ndb, const struct transaction *tx,
                            const struct tx_out *out, int height)
{
    const uint8_t *script = out->script_pub_key.data;
    size_t len = out->script_pub_key.size;

    /* The op_returns row carries an is_slp flag, so the SLP lokad is still
     * probed here — the flag is needed BEFORE any overlay dispatch. The
     * PROJECTION is the registry's job (its ZSLP apply re-parses, which is
     * the registry's decoupling contract). */
    struct slp_message slpmsg;
    bool is_slp = slp_parse(script, len, &slpmsg);

    if (!db_op_return_save(ndb, tx->hash.data, height, script, len, is_slp))
        LOG_WARN("explorer", "index_op_return: op_returns save failed at h=%d",
                 height);

    /* Peek the lokad, find its overlay, apply it — ZSLP / ZNAM / ZANC / ZID
     * and everything added later. Adding an overlay is a registration in
     * explorer_index_overlays.c, not an edit here. A non-overlay OP_RETURN
     * matches nothing and is a clean no-op; a projection failure is logged
     * inside the apply and never gates the block. */
    (void)overlay_ingest(explorer_index_overlays(), ndb, tx, script, len,
                         height);
}

/* ── Per-tx projection writer ──────────────────────────────────────── */

static void index_tx_projections(struct node_db *ndb,
                                 const struct transaction *tx, int height,
                                 uint32_t *acc_njs, uint32_t *acc_nss,
                                 uint32_t *acc_nso, int64_t *acc_sprout,
                                 int64_t *acc_sapling)
{
    /* Transparent outputs (+ op_return dispatch on the first OP_RETURN). */
    bool wrote_opret = false;
    for (size_t vo = 0; vo < tx->num_vout; vo++) {
        const struct tx_out *o = &tx->vout[vo];
        uint8_t a20[20];
        bool has = false;
        enum script_type st = utxo_classify_script(o->script_pub_key.data,
                                                   o->script_pub_key.size,
                                                   a20, &has);
        if (!db_tx_output_save(ndb, tx->hash.data, (uint32_t)vo, o->value,
                               (int)st, has ? a20 : NULL, height))
            LOG_WARN("explorer", "tx_output save failed h=%d vout=%zu",
                     height, vo);
        if (st == SCRIPT_OP_RETURN && !wrote_opret) {
            index_op_return(ndb, tx, o, height);
            wrote_opret = true;
        }
    }

    /* Transparent inputs (skip coinbase null prevout). */
    for (size_t vi = 0; vi < tx->num_vin; vi++) {
        if (outpoint_is_null(&tx->vin[vi].prevout))
            continue;
        if (!db_tx_input_save(ndb, tx->hash.data, (uint32_t)vi,
                              tx->vin[vi].prevout.hash.data,
                              tx->vin[vi].prevout.n, height))
            LOG_WARN("explorer", "tx_input save failed h=%d vin=%zu",
                     height, vi);
    }
    zslp_validity_mark_live_spends(ndb, tx, height);

    /* Sapling spends. */
    for (size_t s = 0; s < tx->num_shielded_spend; s++)
        if (!db_sapling_spend_save(ndb, tx->hash.data, (uint32_t)s,
                                   &tx->v_shielded_spend[s], height))
            LOG_WARN("explorer", "sapling_spend save failed h=%d", height);
    *acc_nss += (uint32_t)tx->num_shielded_spend;

    /* Sapling outputs. */
    for (size_t o = 0; o < tx->num_shielded_output; o++)
        if (!db_sapling_output_save(ndb, tx->hash.data, (uint32_t)o,
                                    &tx->v_shielded_output[o], height))
            LOG_WARN("explorer", "sapling_output save failed h=%d", height);
    *acc_nso += (uint32_t)tx->num_shielded_output;

    /* JoinSplits + sprout nullifiers + sprout value. */
    for (size_t j = 0; j < tx->num_joinsplit; j++) {
        const struct js_description *js = &tx->v_joinsplit[j];
        if (!db_joinsplit_save(ndb, tx->hash.data, (uint32_t)j, js, height))
            LOG_WARN("explorer", "joinsplit save failed h=%d", height);
        for (size_t k = 0; k < ZC_NUM_JS_INPUTS; k++)
            if (!db_sprout_nullifier_save(ndb, js->nullifiers[k].data,
                                          tx->hash.data, height))
                LOG_WARN("explorer", "sprout_nullifier save failed h=%d",
                         height);
        *acc_sprout += js->vpub_old - js->vpub_new;
    }
    *acc_njs += (uint32_t)tx->num_joinsplit;
    *acc_sapling += tx->value_balance;
}

/* ── Per-height integrity receipt ──────────────────────────────────── */

/* SHA3-256(prev_receipt || height || block_hash || sprout_value ||
 *          sapling_value || num_tx || num_joinsplits ||
 *          num_sapling_spends || num_sapling_outputs), all multi-byte
 * integers little-endian. Mirrors explorer_stats_sections.c:440-443. */
static void compute_view_receipt(const uint8_t prev_receipt[32],
                                 int64_t height, const uint8_t block_hash[32],
                                 int64_t sprout_value, int64_t sapling_value,
                                 uint32_t num_tx, uint32_t num_js,
                                 uint32_t num_ss, uint32_t num_so,
                                 uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t le8[8];
    uint8_t le4[4];
    #define PACK_LE64(v) do { \
        uint64_t _u = (uint64_t)(v); \
        for (int _i = 0; _i < 8; _i++) le8[_i] = (uint8_t)(_u >> (8 * _i)); \
        sha3_256_write(&ctx, le8, 8); \
    } while (0)
    #define PACK_LE32(v) do { \
        uint32_t _u = (uint32_t)(v); \
        for (int _i = 0; _i < 4; _i++) le4[_i] = (uint8_t)(_u >> (8 * _i)); \
        sha3_256_write(&ctx, le4, 4); \
    } while (0)

    sha3_256_write(&ctx, prev_receipt, 32);
    PACK_LE64(height);
    sha3_256_write(&ctx, block_hash, 32);
    PACK_LE64(sprout_value);
    PACK_LE64(sapling_value);
    PACK_LE32(num_tx);
    PACK_LE32(num_js);
    PACK_LE32(num_ss);
    PACK_LE32(num_so);
    #undef PACK_LE64
    #undef PACK_LE32
    sha3_256_finalize(&ctx, out);
}

/* ── Single per-block hook ─────────────────────────────────────────── */

bool explorer_index_block(struct node_db *ndb, const struct block *blk,
                          const struct block_index *pindex,
                          const uint8_t prev_receipt[32],
                          uint8_t out_receipt[32],
                          int64_t *out_sprout, int64_t *out_sapling)
{
    if (!ndb || !ndb->open || !blk || !pindex || !pindex->phashBlock)
        LOG_FAIL("explorer", "explorer_index_block: invalid args (ndb=%p)",
                 (void *)ndb);

    uint32_t njs = 0, nss = 0, nso = 0;
    int64_t sprout_val = 0, sapling_val = 0;

    for (size_t i = 0; i < blk->num_vtx; i++)
        index_tx_projections(ndb, &blk->vtx[i], pindex->nHeight,
                             &njs, &nss, &nso, &sprout_val, &sapling_val);

    /* OP_RETURN catalog (models/op_return_index.h) — independent projection
     * of EVERY OP_RETURN output (unlike op_returns above, which keeps only
     * the tx's first). Row-only here: the digest/cursor advance is owned
     * exclusively by the supervised backfill service
     * (engine/services/src/op_return_backfill_service.c) so the running
     * catalog digest stays single-writer across threads. A save failure is
     * logged inside apply_block_rows and never fails this hook. */
    (void)op_return_index_apply_block_rows(ndb, blk, pindex->nHeight,
                                           NULL, 0, NULL);

    uint8_t zero_prev[32] = {0};
    const uint8_t *prev = (pindex->nHeight == 0 || !prev_receipt)
                          ? zero_prev : prev_receipt;
    uint8_t receipt[32];
    compute_view_receipt(prev, pindex->nHeight, pindex->phashBlock->data,
                         sprout_val, sapling_val, (uint32_t)blk->num_vtx,
                         njs, nss, nso, receipt);

    if (!db_view_integrity_save(ndb, pindex->nHeight, receipt))
        LOG_WARN("explorer", "explorer_index_block: view_integrity save "
                 "failed at h=%d", pindex->nHeight);

    if (out_receipt)
        memcpy(out_receipt, receipt, 32);
    if (out_sprout)
        *out_sprout = sprout_val;
    if (out_sapling)
        *out_sapling = sapling_val;
    return true;
}
