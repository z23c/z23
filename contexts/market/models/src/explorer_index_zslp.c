/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* ZSLP (SLP Type-1) apply + fast backfill — split out of explorer_index.c to
 * keep that TU under the E1 ceiling. Decodes parsed SLP messages into the
 * node.db zslp_tokens / zslp_transfers projection. node.db ONLY.
 *
 * ar-validate-skip:zslp-apply — every write goes through db_zslp_token_save /
 * db_zslp_transfer_save (contexts/market/models/src/zslp.c), which run the validates_*
 * lifecycle; this TU only decodes + dispatches and owns no model record. */

#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/zslp.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "zslp/slp.h"
#include "util/log_macros.h"
#include <stdint.h>
#include <string.h>

/* SLP quantities are unsigned 64-bit; node.db INTEGER is signed 64-bit. Clamp
 * the handful of on-chain amounts above INT64_MAX to INT64_MAX so the token /
 * transfer still appears (the column cannot represent the true magnitude
 * anyway) instead of casting negative and being dropped by the >= 0 validator. */
static int64_t zslp_i64(uint64_t v)
{
    return v > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)v;
}

/* SLP carries token_id in wire (display / big-endian) order — the byte-reverse
 * of the node's internal txid order. A GENESIS stores its token_id as that
 * tx's own txid (internal order); MINT/SEND must reverse the wire token_id to
 * the SAME internal order so a token's GENESIS row and its SEND/MINT transfers
 * collate under the single byte-order the explorer readers bind. Verified
 * on-chain: every SEND/MINT token_id == reverse(its GENESIS txid). */
static void zslp_token_id_internal(const uint8_t wire[32], uint8_t out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = wire[31 - i];
}

/* Emit one zslp_transfers row from a live block (full tx in hand). Skips
 * 0-amount slots and vouts the tx lacks; resolves to_addr from vout[vout]'s
 * scriptPubKey (NULL when non-standard). */
static void zslp_emit_transfer(struct node_db *ndb,
                               const struct transaction *tx, int height,
                               const uint8_t token_id32[32], int tx_type,
                               uint64_t amount, uint32_t vout)
{
    if (amount == 0 || vout >= tx->num_vout)
        return;
    const struct tx_out *o = &tx->vout[vout];
    uint8_t a20[20];
    bool has = false;
    utxo_classify_script(o->script_pub_key.data, o->script_pub_key.size,
                         a20, &has);
    if (!db_zslp_transfer_save(ndb, tx->hash.data, height, token_id32,
                               tx_type, zslp_i64(amount), (int)vout,
                               has ? a20 : NULL))
        LOG_WARN("explorer", "zslp apply: transfer save failed h=%d vout=%u "
                 "type=%d", height, vout, tx_type);
}

/* Apply a parsed SLP Type-1 message to the zslp_* tables (forward/reindex
 * path). GENESIS -> token row + a transfer of initial_quantity to vout[1];
 * MINT -> a transfer of additional_quantity to vout[1]; SEND -> one transfer
 * per output_quantities[i] to vout[i+1] (vout[0] is the OP_RETURN). The mint
 * baton (authority marker) gets no row. zslp_balances is intentionally NOT
 * written — a credit-only ledger cannot debit SEND inputs and would over-count
 * holders; deferred to a future per-(token,outpoint) ledger. */
void explorer_index_apply_slp(struct node_db *ndb, const struct transaction *tx,
                              const struct slp_message *m, int height)
{
    uint8_t tid[32];
    switch (m->type) {
    case SLP_TX_GENESIS:
        if (!db_zslp_token_save(ndb, tx->hash.data, m->ticker, m->name,
                                (int)m->decimals, m->document_url, height,
                                zslp_i64(m->initial_quantity)))
            LOG_WARN("explorer", "zslp apply: GENESIS token save skipped h=%d",
                     height);
        zslp_emit_transfer(ndb, tx, height, tx->hash.data, SLP_TX_GENESIS,
                           m->initial_quantity, 1);
        break;
    case SLP_TX_MINT:
        zslp_token_id_internal(m->token_id.data, tid);
        zslp_emit_transfer(ndb, tx, height, tid, SLP_TX_MINT,
                           m->additional_quantity, 1);
        break;
    case SLP_TX_SEND:
        zslp_token_id_internal(m->token_id.data, tid);
        for (int i = 0; i < m->num_outputs; i++)
            zslp_emit_transfer(ndb, tx, height, tid, SLP_TX_SEND,
                               m->output_quantities[i], (uint32_t)(i + 1));
        break;
    default:
        break;
    }
}

/* Emit one zslp_transfers row from a backfill (no live tx): resolve to_addr
 * from the already-indexed tx_outputs table (txid,vout -> address_hash).
 * Skips 0-amount slots. */
static void zslp_backfill_emit(struct node_db *ndb, const uint8_t txid[32],
                               int height, const uint8_t token_id32[32],
                               int tx_type, uint64_t amount, uint32_t vout)
{
    if (amount == 0)
        return;
    uint8_t a20[20];
    bool has = db_tx_output_addr(ndb, txid, vout, a20);
    if (!db_zslp_transfer_save(ndb, txid, height, token_id32, tx_type,
                               zslp_i64(amount), (int)vout, has ? a20 : NULL))
        LOG_WARN("explorer", "zslp backfill: transfer save failed h=%d "
                 "vout=%u type=%d", height, vout, tx_type);
}

/* Fast one-shot: re-derive zslp_tokens + zslp_transfers from the existing
 * op_returns rows (is_slp=1), WITHOUT a full genesis..tip block re-walk. Each
 * SLP script is re-parsed; transfers resolve their recipient from tx_outputs.
 * tokens+transfers carry no cross-tx ordering dependency, so a plain ascending
 * scan is correct. Idempotent (clears stale rows first). zslp_balances left
 * empty (see explorer_index_apply_slp). node.db only. Returns the number of
 * SLP op_returns processed, or -1 on a fatal arg/prepare error. */
int64_t db_zslp_backfill(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_ERR("explorer", "db_zslp_backfill: db not open");

    db_zslp_clear_all(ndb);
    node_db_exec(ndb, "DELETE FROM zslp_balances");

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT txid, block_height, script FROM op_returns "
            "WHERE is_slp=1 ORDER BY block_height ASC",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_ERR("explorer", "db_zslp_backfill: prepare failed: %s",
                sqlite3_errmsg(ndb->db));

    int64_t processed = 0, tokens = 0;
    while (AR_STEP_ROW(s)) {
        uint8_t txid[32], tid[32];
        if (AR_COL_BYTES(s, 0) != 32)
            continue;
        AR_READ_BLOB(s, 0, txid, 32);
        int height = (int)AR_COL_INT(s, 1);
        const uint8_t *script = (const uint8_t *)sqlite3_column_blob(s, 2);
        size_t slen = (size_t)AR_COL_BYTES(s, 2);

        struct slp_message m;
        if (!script || !slp_parse(script, slen, &m))
            continue;
        processed++;

        switch (m.type) {
        case SLP_TX_GENESIS:
            if (db_zslp_token_save(ndb, txid, m.ticker, m.name,
                                   (int)m.decimals, m.document_url, height,
                                   zslp_i64(m.initial_quantity)))
                tokens++;
            zslp_backfill_emit(ndb, txid, height, txid, SLP_TX_GENESIS,
                               m.initial_quantity, 1);
            break;
        case SLP_TX_MINT:
            zslp_token_id_internal(m.token_id.data, tid);
            zslp_backfill_emit(ndb, txid, height, tid, SLP_TX_MINT,
                               m.additional_quantity, 1);
            break;
        case SLP_TX_SEND:
            zslp_token_id_internal(m.token_id.data, tid);
            for (int i = 0; i < m.num_outputs; i++)
                zslp_backfill_emit(ndb, txid, height, tid, SLP_TX_SEND,
                                   m.output_quantities[i], (uint32_t)(i + 1));
            break;
        default:
            break;
        }
    }
    AR_FINALIZE(s);

    LOG_INFO("explorer", "backfill-zslp: %lld SLP op_returns processed, "
             "%lld tokens", (long long)processed, (long long)tokens);
    return processed;
}
