/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Explorer transaction CONTROLLER: /explorer/tx/{txid}. Thin parse-delegate
 * glue — it parses the request, fetches the transaction (mempool / tx index /
 * on-disk block, or via the RPC proxy), packs the already-computed fields
 * into the view structs, and hands them to the view shape
 * (contexts/explorer/views/src/explorer_tx_view.c). Controllers must not build views.
 * See explorer_controller_internal.h for shared declarations. */

#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "explorer_controller_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/subsidy.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"
#include "util/template.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "views/explorer_tx_view.h"
#include "views/format_helpers.h"
#include "views/wallet_templates_gen.h"
#include "zslp/slp.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Map a row to its display kind: OP_RETURN wins over an address. */
static int tx_io_classify(bool is_op_return, const char *addr)
{
    if (is_op_return)
        return EXPLORER_TX_IO_OP_RETURN;
    if (addr[0])
        return EXPLORER_TX_IO_ADDRESS;
    return EXPLORER_TX_IO_UNKNOWN;
}

/* Count objects ("{") in a JSON array section, stopping at its "]". */
static size_t tx_rpc_count_objects(const char *arr)
{
    size_t count = 0;
    if (!arr) return 0;
    for (const char *q = arr; *q && *q != ']'; q++)
        if (*q == '{') count++;
    return count;
}

/* Scan for the "]" that closes the array whose "[" sits at arr+7. */
static const char *tx_rpc_array_end(const char *arr, const char *fallback)
{
    const char *end = NULL;
    int brace_depth = 0;
    for (const char *q = arr + 7; *q; q++) {
        if (*q == '[') brace_depth++;
        if (*q == ']') { brace_depth--; if (brace_depth <= 0) { end = q; break; } }
    }
    if (!end) end = fallback;
    return end;
}

/* Walk the "value": entries in [start, end). */
static size_t tx_rpc_count_values(const char *start, const char *end)
{
    size_t cap = 0;
    for (const char *p = start; p < end; ) {
        const char *val_str = strstr(p, "\"value\":");
        if (!val_str || val_str >= end) break;
        cap++;
        p = val_str + 8;
    }
    return cap;
}

static void tx_rpc_parse_summary(struct explorer_tx_rpc_view_data *d, const char *result)
{
    d->confirmations = zcl_json_int(result, "confirmations");
    d->block_height = zcl_json_int(result, "height");
    d->size = zcl_json_int(result, "size");
    d->version = zcl_json_int(result, "version");
    d->locktime = zcl_json_int(result, "locktime");

    int64_t expiry = zcl_json_int(result, "expiryheight");
    d->has_expiry = expiry > 0;
    d->expiry = expiry;

    double value_balance = zcl_json_real(result, "valuebalance");
    if (value_balance != 0.0) {
        d->has_value_balance = true;
        zcl_format_zcl(d->value_balance, sizeof(d->value_balance),
                       (int64_t)(value_balance * (double)ZATOSHI_PER_ZCL));
    }

    zcl_json_extract_str(result, "blockhash", d->blockhash, sizeof(d->blockhash));
    d->has_block = d->blockhash[0] != '\0';
}

static void tx_rpc_parse_out_row(struct explorer_tx_rpc_out_row *row, int out_idx,
                                 const char *val_str, const char *vout_end)
{
    double val = strtod(val_str + 8, NULL);
    memset(row, 0, sizeof(*row));
    row->index = out_idx;
    zcl_format_zcl(row->value, sizeof(row->value),
                   (int64_t)(val * (double)ZATOSHI_PER_ZCL));

    /* Try to find address */
    char addr[64] = "";
    const char *addr_start = strstr(val_str, "\"addresses\":[\"");
    if (addr_start && addr_start < vout_end && addr_start - val_str < 500) {
        addr_start += 14;
        /* Bound the closing-quote search to the known JSON span so
         * it cannot read past the end of an unterminated buffer. */
        const char *addr_end =
            (addr_start <= vout_end)
                ? memchr(addr_start, '"', (size_t)(vout_end - addr_start))
                : NULL;
        if (addr_end && (size_t)(addr_end - addr_start) < sizeof(addr)) {
            memcpy(addr, addr_start, (size_t)(addr_end - addr_start));
            addr[(size_t)(addr_end - addr_start)] = '\0';
        }
    }

    /* Check for OP_RETURN */
    bool is_opreturn = (strstr(val_str, "\"type\":\"nulldata\"") != NULL &&
                        strstr(val_str, "\"type\":\"nulldata\"") < vout_end &&
                        strstr(val_str, "\"type\":\"nulldata\"") - val_str < 500);

    row->kind = tx_io_classify(is_opreturn, addr);
    if (row->kind == EXPLORER_TX_IO_ADDRESS)
        snprintf(row->addr, sizeof(row->addr), "%s", addr);
}

static size_t tx_rpc_parse_out_rows(struct explorer_tx_rpc_out_row *out_rows, size_t cap,
                                    const char *vout, const char *vout_end)
{
    const char *p = vout;
    int out_idx = 0;
    size_t num_out_rows = 0;
    while (p < vout_end && num_out_rows < cap) {
        const char *val_str = strstr(p, "\"value\":");
        if (!val_str || val_str >= vout_end) break;

        tx_rpc_parse_out_row(&out_rows[num_out_rows], out_idx, val_str, vout_end);

        num_out_rows++;
        out_idx++;
        p = val_str + 8;
    }
    return num_out_rows;
}

static size_t serve_tx_rpc(const char *param, uint8_t *r, size_t max)
{
    /* Bad txid: render the invalid-tx view so callers get a real error
     * body instead of an empty response (and never re-probe on 0). */
    if (!zcl_is_hex_string(param, 64))
        return explorer_view_tx_invalid(r, max);

    char buf[262144];

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\", 1]", param);
    int n = rpc_call("getrawtransaction", params, buf, sizeof(buf));
    if (n <= 0 || strstr(buf, "\"error\":null") == NULL)
        return explorer_view_tx_not_found_rpc(param, r, max);

    /* Extract the result object — find "result":{ */
    const char *result = strstr(buf, "\"result\":{");
    if (!result) result = buf;

    struct explorer_tx_rpc_view_data d;
    memset(&d, 0, sizeof(d));
    snprintf(d.txid, sizeof(d.txid), "%s", param);
    tx_rpc_parse_summary(&d, result);

    /* Parse vout array for outputs */
    struct explorer_tx_rpc_out_row *out_rows = NULL;
    size_t num_out_rows = 0;
    const char *vout = strstr(result, "\"vout\":[");
    if (vout) {
        d.has_outputs = true;

        /* Find the end of the vout array. */
        const char *vout_end = tx_rpc_array_end(vout, buf + n);

        /* Count "value": entries to size the row array. */
        size_t cap = tx_rpc_count_values(vout, vout_end);

        if (cap > 0) {
            out_rows = zcl_malloc(cap * sizeof(*out_rows), "explorer.tx.rpc.out_rows");
            if (!out_rows)
                return explorer_view_tx_not_found_rpc(param, r, max);
            num_out_rows = tx_rpc_parse_out_rows(out_rows, cap, vout, vout_end);
        }
    }
    d.out_rows = out_rows;
    d.num_out_rows = num_out_rows;

    /* Shielded data */
    const char *ss = strstr(result, "\"vShieldedSpend\":[");
    d.shielded_spend = tx_rpc_count_objects(ss);
    const char *so = strstr(result, "\"vShieldedOutput\":[");
    d.shielded_output = tx_rpc_count_objects(so);
    const char *js = strstr(result, "\"vjoinsplit\":[");
    d.joinsplit = tx_rpc_count_objects(js);

    size_t off = explorer_view_tx_rpc(&d, r, max);
    free(out_rows);
    return off;
}

static bool tx_request_valid(struct explorer_context *ctx, const char *param)
{
    return ctx->main_state && zcl_is_hex_string(param, 64) &&
           explorer_param_is_printable_ascii(param);
}

/* Returns 1 when the tx was found in an on-disk block, else 0. */
static int tx_load_confirmed(struct explorer_context *ctx, struct uint256 *txhash,
                             struct transaction *tx, struct block *blk,
                             int *block_height, char *block_hash_hex)
{
    if (ctx->node_db) {
        struct db_tx_index txi;
        if (db_tx_find(ctx->node_db, txhash->data, &txi)) {
            *block_height = txi.block_height;

            /* Load block from disk */
            const struct block_index *bi =
                active_chain_at(&ctx->main_state->chain_active, *block_height);
            if (bi && ctx->datadir && read_block_from_disk_index(blk, bi, ctx->datadir)) {
                /* Find the tx in the block */
                for (size_t i = 0; i < blk->num_vtx; i++) {
                    if (uint256_eq(&blk->vtx[i].hash, txhash)) {
                        transaction_copy(tx, &blk->vtx[i]);
                        if (bi->phashBlock)
                            uint256_get_hex(bi->phashBlock, block_hash_hex);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

static size_t tx_render_rpc_fallback(const char *param, uint8_t *r, size_t max,
                                     struct block *blk)
{
    block_free(blk);
    /* SQLite didn't have it — fall back to RPC (covers txindex gaps) */
    size_t rpc_result = serve_tx_rpc(param, r, max);
    if (rpc_result > 0) return rpc_result;
    char safe_param[256];
    html_escape(safe_param, sizeof(safe_param), param ? param : "");
    return explorer_view_tx_not_found(safe_param, r, max);
}

static void tx_fill_header(struct explorer_tx_view_data *d, struct transaction *tx,
                           bool in_mempool, int block_height, int tip)
{
    /* Header info */
    uint256_get_hex(&tx->hash, d->txid);
    d->in_mempool = in_mempool;
    d->confirmations = in_mempool ? 0 : (block_height >= 0 ? tip - block_height + 1 : 0);

    if (block_height >= 0) {
        d->has_block = true;
        d->block_height = block_height;
        format_with_commas(d->block_height_fmt, sizeof(d->block_height_fmt), block_height);
    }

    d->version = tx->version;
    d->overwintered = tx->overwintered;

    /* Compute serialized size */
    struct byte_stream bs;
    stream_init(&bs, 512);
    transaction_serialize(tx, &bs);
    d->size = bs.size;
    stream_free(&bs);

    d->lock_time = tx->lock_time;

    if (tx->overwintered && tx->expiry_height > 0) {
        d->has_expiry = true;
        d->expiry_height = tx->expiry_height;
    }

    /* Value balance for Sapling */
    if (tx->overwintered && tx->version >= 4) {
        d->has_value_balance = true;
        zcl_format_zcl(d->value_balance, sizeof(d->value_balance), tx->value_balance);
    }
}

static void tx_fill_in_row(struct explorer_tx_in_row *in, size_t i,
                           struct transaction *tx, struct explorer_context *ctx,
                           int block_height)
{
    memset(in, 0, sizeof(*in));
    in->index = i;
    if (transaction_is_coinbase(tx) && i == 0) {
        in->is_coinbase = true;
        int64_t reward = block_height >= 0 ?
            get_block_subsidy(block_height, &chain_params_get()->consensus) : 0;
        zcl_format_zcl(in->subsidy, sizeof(in->subsidy), reward);
    } else {
        uint256_get_hex(&tx->vin[i].prevout.hash, in->prev_hash);
        snprintf(in->prev_short, sizeof(in->prev_short), "%.8s...%.4s",
                 in->prev_hash, in->prev_hash + 60);
        in->prev_n = tx->vin[i].prevout.n;

        /* Look up previous output value via the tx_index model (the
         * raw tx_outputs read lives in db_tx_output_value). */
        int64_t prev_val = 0;
        if (db_tx_output_value(ctx->node_db, tx->vin[i].prevout.hash.data,
                               tx->vin[i].prevout.n, &prev_val)) {
            in->have_value = true;
            zcl_format_zcl(in->value, sizeof(in->value), prev_val);
        }
    }
}

static struct explorer_tx_in_row *tx_build_in_rows(struct transaction *tx,
                                                   struct explorer_context *ctx,
                                                   int block_height)
{
    if (tx->num_vin == 0)
        return NULL;
    struct explorer_tx_in_row *in_rows =
        zcl_malloc(tx->num_vin * sizeof(*in_rows), "explorer.tx.in_rows");
    if (!in_rows)
        return NULL;
    for (size_t i = 0; i < tx->num_vin; i++)
        tx_fill_in_row(&in_rows[i], i, tx, ctx, block_height);
    return in_rows;
}

static int64_t tx_fill_out_row(struct explorer_tx_out_row *o, size_t i,
                               struct transaction *tx)
{
    memset(o, 0, sizeof(*o));
    o->index = i;
    zcl_format_zcl(o->value, sizeof(o->value), tx->vout[i].value);
    o->script_size = tx->vout[i].script_pub_key.size;

    /* Try to extract destination address */
    char addr_str[64] = "";
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    if (script_extract_destination(&tx->vout[i].script_pub_key, &dest))
        addr_encode(addr_str, sizeof(addr_str), &dest);

    /* Check for OP_RETURN */
    bool is_op_return = (tx->vout[i].script_pub_key.size > 0 &&
                         tx->vout[i].script_pub_key.data[0] == 0x6a); /* OP_RETURN */

    o->kind = tx_io_classify(is_op_return, addr_str);
    if (o->kind == EXPLORER_TX_IO_ADDRESS)
        snprintf(o->addr, sizeof(o->addr), "%s", addr_str);
    return tx->vout[i].value;
}

static struct explorer_tx_out_row *tx_build_out_rows(struct transaction *tx,
                                                     int64_t *total_out)
{
    struct explorer_tx_out_row *out_rows = NULL;
    if (tx->num_vout > 0)
        out_rows = zcl_malloc(tx->num_vout * sizeof(*out_rows), "explorer.tx.out_rows");
    if (tx->num_vout > 0 && !out_rows)
        return NULL;
    for (size_t i = 0; i < tx->num_vout; i++)
        *total_out += tx_fill_out_row(&out_rows[i], i, tx);
    return out_rows;
}

static void tx_fill_joinsplit_data(struct transaction *tx, struct explorer_tx_view_data *d)
{
    /* Shielded data */
    d->num_shielded_spend = tx->num_shielded_spend;
    d->num_shielded_output = tx->num_shielded_output;
    d->num_joinsplit = tx->num_joinsplit;
    if (tx->num_joinsplit > 0) {
        int64_t js_in = 0, js_out = 0;
        for (size_t j = 0; j < tx->num_joinsplit; j++) {
            js_in += tx->v_joinsplit[j].vpub_old;
            js_out += tx->v_joinsplit[j].vpub_new;
        }
        zcl_format_zcl(d->joinsplit_in, sizeof(d->joinsplit_in), js_in);
        zcl_format_zcl(d->joinsplit_out, sizeof(d->joinsplit_out), js_out);
    }
}

static void tx_fill_slp_data(struct transaction *tx, struct explorer_tx_view_data *d)
{
    /* ZSLP token data */
    if (tx->num_vout > 0) {
        struct slp_message slp;
        if (slp_parse(tx->vout[0].script_pub_key.data,
                      tx->vout[0].script_pub_key.size, &slp)) {
            if (slp.type == SLP_TX_GENESIS) {
                d->slp.kind = EXPLORER_TX_SLP_GENESIS;
                html_escape(d->slp.ticker, sizeof(d->slp.ticker), slp.ticker);
                html_escape(d->slp.name, sizeof(d->slp.name), slp.name);
                d->slp.decimals = slp.decimals;
                snprintf(d->slp.initial_supply, sizeof(d->slp.initial_supply),
                         "%" PRIu64, slp.initial_quantity);
                if (slp.document_url[0]) {
                    d->slp.has_doc_url = true;
                    html_escape(d->slp.doc_url, sizeof(d->slp.doc_url), slp.document_url);
                }
            } else if (slp.type == SLP_TX_SEND) {
                d->slp.kind = EXPLORER_TX_SLP_SEND;
                uint256_get_hex(&slp.token_id, d->slp.token_id);
                d->slp.num_outputs = slp.num_outputs;
                for (int q = 0; q < slp.num_outputs &&
                         q < (int)(sizeof(d->slp.output_quantities) /
                                   sizeof(d->slp.output_quantities[0])); q++)
                    d->slp.output_quantities[q] = slp.output_quantities[q];
            } else if (slp.type == SLP_TX_MINT) {
                d->slp.kind = EXPLORER_TX_SLP_MINT;
                uint256_get_hex(&slp.token_id, d->slp.token_id);
                snprintf(d->slp.mint_quantity, sizeof(d->slp.mint_quantity),
                         "%" PRIu64, slp.additional_quantity);
            }
        }
    }
}

/* ── Transaction Detail (native) ──────────────────────────── */

size_t serve_tx(const char *param, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    if (use_rpc_proxy())
        return serve_tx_rpc(param, r, max);
    if (!tx_request_valid(ctx, param))
        return explorer_view_tx_invalid(r, max);

    struct uint256 txhash;
    uint256_set_hex(&txhash, param);

    /* Try mempool */
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    bool in_mempool = ctx->mempool &&
                      tx_mempool_lookup(ctx->mempool, &txhash, &tx);

    /* Try tx index */
    int block_height = -1;
    char block_hash_hex[65] = "";
    struct block blk;
    block_init(&blk);
    bool from_block = false;

    if (!in_mempool)
        from_block = tx_load_confirmed(ctx, &txhash, &tx, &blk, &block_height,
                                       block_hash_hex) != 0;

    if (!in_mempool && !from_block)
        return tx_render_rpc_fallback(param, r, max, &blk);

    int tip = active_chain_height(&ctx->main_state->chain_active);

    struct explorer_tx_view_data d;
    memset(&d, 0, sizeof(d));

    tx_fill_header(&d, &tx, in_mempool, block_height, tip);

    /* Inputs */
    d.num_vin = tx.num_vin;
    struct explorer_tx_in_row *in_rows = tx_build_in_rows(&tx, ctx, block_height);
    if (tx.num_vin > 0 && !in_rows) {
        transaction_free(&tx);
        block_free(&blk);
        return explorer_view_tx_invalid(r, max);
    }
    d.in_rows = in_rows;
    d.num_in_rows = tx.num_vin;

    /* Outputs */
    int64_t total_out = 0;
    d.num_vout = tx.num_vout;
    struct explorer_tx_out_row *out_rows = tx_build_out_rows(&tx, &total_out);
    if (tx.num_vout > 0 && !out_rows) {
        free(in_rows);
        transaction_free(&tx);
        block_free(&blk);
        return explorer_view_tx_invalid(r, max);
    }
    d.out_rows = out_rows;
    d.num_out_rows = tx.num_vout;
    zcl_format_zcl(d.total_out, sizeof(d.total_out), total_out);

    tx_fill_joinsplit_data(&tx, &d);

    tx_fill_slp_data(&tx, &d);

    size_t off = explorer_view_tx(&d, r, max);

    free(in_rows);
    free(out_rows);
    transaction_free(&tx);
    block_free(&blk);
    return off;
}
