/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Explorer block CONTROLLER: /explorer/block/{hash|height}. Thin
 * parse-delegate glue — it parses the request, fetches the block (via
 * the native block_index/disk path or the RPC proxy), packs the fields
 * into the view structs, and hands them to contexts/explorer/views/src/explorer_block_view.c.
 * See explorer_controller_internal.h for shared declarations and
 * controllers/explorer_internal.h for the helper inlines. */

#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "explorer_controller_internal.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "models/database.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "util/template.h"
#include "validation/main_state.h"
#include "views/explorer_block_view.h"
#include "views/format_helpers.h"
#include "views/wallet_templates_gen.h"
#include "zslp/slp.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t serve_block_rpc(const char *param, uint8_t *r, size_t max)
{
    /* Empty param: render the not-found view so callers get a real error
     * body instead of an empty response. */
    if (!param || !param[0])
        return explorer_view_block_not_found_rpc(r, max);
    char buf[262144]; /* 256KB for block JSON */

    /* Get block hash */
    char hash[65] = "";
    if (zcl_is_all_digits(param)) {
        char params[64];
        snprintf(params, sizeof(params), "[%s]", param);
        if (rpc_call("getblockhash", params, buf, sizeof(buf)) <= 0)
            return explorer_view_block_not_found_rpc(r, max);
        zcl_json_extract_str(buf, "result", hash, sizeof(hash));
    } else if (zcl_is_hex_string(param, 64)) {
        snprintf(hash, sizeof(hash), "%s", param);
    }

    if (!hash[0])
        return explorer_view_block_not_found_rpc(r, max);

    /* Get full block */
    char params2[128];
    snprintf(params2, sizeof(params2), "[\"%s\", true]", hash);
    if (rpc_call("getblock", params2, buf, sizeof(buf)) <= 0)
        return explorer_view_block_not_found_rpc(r, max);

    struct explorer_block_rpc_view_data d;
    memset(&d, 0, sizeof(d));
    d.height = (int)zcl_json_int(buf, "height");
    int64_t blk_time = zcl_json_int(buf, "time");
    d.difficulty = zcl_json_real(buf, "difficulty");
    (void)zcl_json_int(buf, "size");

    zcl_json_extract_str(buf, "merkleroot", d.merkle, sizeof(d.merkle));
    zcl_json_extract_str(buf, "previousblockhash", d.prev, sizeof(d.prev));
    zcl_json_extract_str(buf, "nextblockhash", d.next_hash, sizeof(d.next_hash));
    snprintf(d.hash, sizeof(d.hash), "%s", hash);

    format_time(d.ts, sizeof(d.ts), (uint32_t)blk_time);

    /* Count txs */
    int tx_count = explorer_count_json_tx_array(buf);
    const char *txarr = strstr(buf, "\"tx\":[");
    d.tx_count = tx_count;
    d.has_tx_array = (txarr != NULL);

    /* Parse up to 100 txids into the row array; the view applies the
     * same buffer-bound guard when emitting rows. */
    struct explorer_block_rpc_tx_row rows[100];
    size_t nrows = 0;
    if (txarr) {
        const char *p = txarr + 6; /* skip "tx":[ */
        int idx = 0;
        while (p && idx < 100) {
            if (*p == '"') {
                p++;
                const char *end = strchr(p, '"');
                if (!end) break;
                char txid[65];
                size_t tlen = (size_t)(end - p);
                if (tlen > 64) tlen = 64;
                memcpy(txid, p, tlen);
                txid[tlen] = '\0';

                char short_txid[18];
                if (tlen >= 64)
                    snprintf(short_txid, sizeof(short_txid), "%.8s...%.4s", txid, txid + 60);
                else
                    /* bounded to fit short_txid[18]; a malformed sub-64 txid
                     * is displayed truncated rather than tripping fortify */
                    snprintf(short_txid, sizeof(short_txid), "%.17s", txid);

                rows[nrows].index = idx;
                snprintf(rows[nrows].txid, sizeof(rows[nrows].txid), "%s", txid);
                snprintf(rows[nrows].short_txid, sizeof(rows[nrows].short_txid), "%s", short_txid);
                nrows++;
                idx++;
                p = end + 1;
            } else if (*p == ']') {
                break;
            } else {
                p++;
            }
        }
    }
    d.rows = rows;
    d.num_rows = nrows;

    return explorer_view_block_rpc(&d, r, max);
}

/* ── Block Detail (native) ────────────────────────────────── */

size_t serve_block(const char *param, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    if (use_rpc_proxy())
        return serve_block_rpc(param, r, max);
    if (!ctx->main_state || !param || !param[0]) return 0;

    const struct block_index *bi = NULL;

    if (zcl_is_all_digits(param)) {
        int h = atoi(param);
        int tip = active_chain_height(&ctx->main_state->chain_active);
        if (h >= 0 && h <= tip)
            bi = active_chain_at(&ctx->main_state->chain_active, h);
    } else if (zcl_is_hex_string(param, 64)) {
        struct uint256 hash;
        uint256_set_hex(&hash, param);
        bi = (const struct block_index *)block_map_find(
            &ctx->main_state->map_block_index, &hash);
    }

    if (!bi) {
        char safe_param[256];
        html_escape(safe_param, sizeof(safe_param), param ? param : "");
        return explorer_view_block_not_found(safe_param, r, max);
    }

    struct explorer_block_view_data d;
    memset(&d, 0, sizeof(d));
    d.height = bi->nHeight;
    d.tip = active_chain_height(&ctx->main_state->chain_active);

    if (bi->phashBlock) uint256_get_hex(bi->phashBlock, d.hash);
    /* Read block from disk early to get header fields (merkle root, etc.)
     * The block_index mmap doesn't store these — only the full block has them. */
    struct block blk;
    block_init(&blk);
    bool loaded = ctx->datadir && read_block_from_disk_index(&blk, bi, ctx->datadir);
    d.loaded = loaded;

    if (loaded) {
        uint256_get_hex(&blk.header.hashMerkleRoot, d.merkle);
        uint256_get_hex(&blk.header.hashFinalSaplingRoot, d.sapling_root);
        uint256_get_hex(&blk.header.nNonce, d.nonce);
    } else {
        uint256_get_hex(&bi->hashMerkleRoot, d.merkle);
        uint256_get_hex(&bi->hashFinalSaplingRoot, d.sapling_root);
        uint256_get_hex(&bi->nNonce, d.nonce);
    }

    format_time(d.ts, sizeof(d.ts), bi->nTime);
    zcl_format_zcl(d.sapling_val, sizeof(d.sapling_val), bi->nSaplingValue);
    zcl_format_zcl(d.sprout_val, sizeof(d.sprout_val), bi->nSproutValue);
    d.n_tx = bi->nTx;
    d.difficulty = difficulty_from_index(bi);
    d.n_bits = bi->nBits;

    /* Pack the transaction rows the view will render. */
    struct explorer_block_tx_row rows[100];
    size_t nrows = 0;
    if (loaded && blk.num_vtx > 0) {
        d.num_vtx = blk.num_vtx;
        size_t show_max = blk.num_vtx > 100 ? 100 : blk.num_vtx;
        for (size_t i = 0; i < show_max; i++) {
            const struct transaction *tx = &blk.vtx[i];
            struct explorer_block_tx_row *row = &rows[nrows];

            /* Format the abbreviation from a local copy: row->txid and
             * row->short_txid live in the same rows[] object, so passing
             * row->txid as the snprintf source trips -Wrestrict even though
             * the two fields never overlap. */
            char txid_hex[65];
            uint256_get_hex(&tx->hash, txid_hex);
            memcpy(row->txid, txid_hex, sizeof(row->txid));
            snprintf(row->short_txid, sizeof(row->short_txid),
                     "%.8s...%.4s", txid_hex, txid_hex + 60);

            zcl_format_zcl(row->value, sizeof(row->value),
                           transaction_get_value_out(tx));

            bool is_cb = transaction_is_coinbase(tx);
            bool has_shielded = (tx->num_shielded_spend > 0 || tx->num_shielded_output > 0 ||
                                 tx->num_joinsplit > 0);

            /* Check for ZSLP */
            bool is_slp = false;
            struct slp_message slp;
            if (tx->num_vout > 0 && tx->vout[0].script_pub_key.size > 0)
                is_slp = slp_parse(tx->vout[0].script_pub_key.data,
                                   tx->vout[0].script_pub_key.size, &slp);

            row->type_tags[0] = '\0';
            if (is_cb) snprintf(row->type_tags, sizeof(row->type_tags),
                                "<span class='tag tag-cb'>Coinbase</span> ");
            if (has_shielded) {
                size_t tl = strlen(row->type_tags);
                snprintf(row->type_tags + tl, sizeof(row->type_tags) - tl,
                    "<span class='tag tag-shielded'>Shielded</span> ");
            }
            if (is_slp) {
                size_t tl = strlen(row->type_tags);
                /* The ticker is attacker-controlled OP_RETURN bytes (not
                 * charset-restricted); escape before embedding to prevent
                 * stored XSS, mirroring the tx view (explorer_controller_tx.c). */
                char esc_ticker[256];
                html_escape(esc_ticker, sizeof(esc_ticker), slp.ticker);
                snprintf(row->type_tags + tl, sizeof(row->type_tags) - tl,
                    "<span class='tag tag-slp'>ZSLP: %s</span> ", esc_ticker);
            }

            /* Combined transparent + shielded counts */
            row->inputs = tx->num_vin + tx->num_shielded_spend +
                          tx->num_joinsplit;
            row->outputs = tx->num_vout + tx->num_shielded_output +
                           tx->num_joinsplit;
            nrows++;
        }
    }
    d.rows = rows;
    d.num_rows = nrows;

    size_t off = explorer_view_block(&d, r, max);

    block_free(&blk);
    return off;
}
