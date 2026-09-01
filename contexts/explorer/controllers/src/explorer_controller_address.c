/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Explorer address + search CONTROLLER. Thin parse-delegate glue: it
 * decodes the address, fetches the balance + UTXO list via its existing
 * projection calls, packs the results into the view structs, and hands
 * them to contexts/explorer/views/src/explorer_address_view.c. The search handler keeps the
 * routing/dispatch logic and delegates only error/not-found page assembly to
 * the view. See explorer_controller_internal.h for shared declarations. */

#include "controllers/explorer_controller.h"
#include "controllers/explorer_internal.h"
#include "explorer_controller_internal.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "util/ar_step_readonly.h"
#include "util/template.h"
#include "validation/main_state.h"
#include "views/explorer_address_view.h"
#include "views/format_helpers.h"
#include "views/wallet_templates_gen.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t serve_address(const char *param, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    size_t param_len = param ? strlen(param) : 0;
    if (!ctx->main_state || !param || !param[0] || param_len >= 128 ||
        !explorer_param_is_printable_ascii(param))
        return 0;

    char safe_addr[128];
    html_escape(safe_addr, sizeof(safe_addr), param);

    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    if (!addr_decode(param, &dest))
        return explorer_view_address_invalid(safe_addr, r, max);

    /* Get the 20-byte hash */
    const uint8_t *addr_hash = NULL;
    if (dest.type == DEST_KEY_ID)
        addr_hash = dest.id.key.id.data;
    else if (dest.type == DEST_SCRIPT_ID)
        addr_hash = dest.id.script.hash.data;

    struct explorer_address_view_data d;
    memset(&d, 0, sizeof(d));
    d.safe_addr = safe_addr;
    d.is_p2pkh = (dest.type == DEST_KEY_ID);

    if (ctx->node_db && addr_hash) {
        int64_t balance = db_utxo_balance_for_address(ctx->node_db, addr_hash);
        zcl_format_zcl(d.balance, sizeof(d.balance), balance);
        d.have_balance = true;
    }

    /* UTXO list */
    struct explorer_address_utxo_row rows[100];
    size_t nrows = 0;
    if (ctx->node_db && addr_hash) {
        d.have_utxos = true;
        struct db_utxo utxos[100];
        int count = db_utxo_list_for_address(ctx->node_db, addr_hash, utxos, 100);
        d.utxo_count = count;

        for (int i = 0; i < count; i++) {
            struct explorer_address_utxo_row *row = &rows[nrows];
            struct uint256 utxo_txid;
            char txid_hex[65];
            memcpy(utxo_txid.data, utxos[i].txid, 32);
            uint256_get_hex(&utxo_txid, txid_hex);
            memcpy(row->txid_hex, txid_hex, sizeof(txid_hex));
            snprintf(row->short_txid, sizeof(row->short_txid), "%.8s...%.4s",
                     txid_hex, txid_hex + 60);

            zcl_format_zcl(row->value, sizeof(row->value), utxos[i].value);
            row->vout = utxos[i].vout;
            row->height = utxos[i].height;
            row->is_coinbase = utxos[i].is_coinbase;
            nrows++;

            db_utxo_free(&utxos[i]);
        }
    }
    d.rows = rows;
    d.num_rows = nrows;

    return explorer_view_address(&d, r, max);
}

/* ── Search ───────────────────────────────────────────────── */

size_t serve_search(const char *query, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    if (!query) return 0;

    /* URL-decode the query ('+' → space, %XX → byte) */
    char decoded[256];
    {
        size_t di = 0;
        for (size_t si = 0; query[si] && di < sizeof(decoded) - 1; si++) {
            if (query[si] == '%' && query[si+1] && query[si+2]) {
                char hex[3] = { query[si+1], query[si+2], '\0' };
                char *endp = NULL;
                long v = strtol(hex, &endp, 16);
                if (!endp || *endp != '\0' || v < 0 || v > 255)
                    return explorer_view_search_invalid(
                        "Malformed percent-encoding in query.", r, max);
                decoded[di++] = (char)v;
                si += 2;
            } else if (query[si] == '+') {
                decoded[di++] = ' ';
            } else {
                decoded[di++] = query[si];
            }
        }
        decoded[di] = '\0';
    }

    /* Strip leading/trailing whitespace */
    const char *dq = decoded;
    while (*dq == ' ') dq++;
    size_t qlen = strlen(dq);
    char q[256];
    if (qlen >= sizeof(q)) qlen = sizeof(q) - 1;
    memcpy(q, dq, qlen);
    q[qlen] = '\0';
    while (qlen > 0 && q[qlen - 1] == ' ') q[--qlen] = '\0';

    if (!qlen) return explorer_serve_dashboard(r, max);
    if (!explorer_param_is_printable_ascii(q))
        return explorer_view_search_invalid(
            "Search input contains unsupported characters.", r, max);

    /* Block height? Always try — serve_block handles RPC fallback */
    if (zcl_is_all_digits(q)) {
        int h = atoi(q);
        if (h >= 0 && h < 100000000)
            return serve_block(q, r, max);
    }

    /* 64-hex: try as block hash first, then txid */
    if (qlen == 64 && zcl_is_all_hex(q, 64)) {
        /* Try block hash via native index */
        if (ctx->main_state) {
            struct uint256 hash;
            uint256_set_hex(&hash, q);
            const struct block_index *bi = block_map_find(
                &ctx->main_state->map_block_index, &hash);
            if (bi)
                return serve_block(q, r, max);
        }

        /* Try txid via SQLite index */
        if (ctx->node_db) {
            struct uint256 hash;
            uint256_set_hex(&hash, q);
            struct db_tx_index txi;
            if (db_tx_find(ctx->node_db, hash.data, &txi))
                return serve_tx(q, r, max);
        }

        /* Try mempool */
        if (ctx->mempool) {
            struct uint256 hash;
            uint256_set_hex(&hash, q);
            if (tx_mempool_exists(ctx->mempool, &hash))
                return serve_tx(q, r, max);
        }

        /* Fallback: try as tx via RPC, then block hash via RPC */
        {
            char rpc_buf[1024];
            char rpc_params[128];
            int written = snprintf(rpc_params, sizeof(rpc_params),
                                   "[\"%s\", 1]", q);
            if (written >= 0 && (size_t)written < sizeof(rpc_params)) {
                int rn = rpc_call("getrawtransaction", rpc_params,
                                  rpc_buf, sizeof(rpc_buf));
                if (rn > 0 && strstr(rpc_buf, "\"error\":null"))
                    return serve_tx(q, r, max);
            }
        }
        return serve_block(q, r, max);
    }

    /* Address? (starts with t1, t3, etc.) */
    if (qlen > 20 && (q[0] == 't' || q[0] == 'T')) {
        struct tx_destination dest;
        if (addr_decode(q, &dest))
            return serve_address(q, r, max);
    }

    /* Not found */
    char safe[512];
    html_escape(safe, sizeof(safe), q);
    return explorer_view_search_not_found(safe, r, max);
}

/* ── Stats Page with SVG Charts ────────────────────────────── */

/* format_y_label and svg_line_chart moved to explorer_internal.h */
