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
#include "services/utxo_mirror_sync_service.h"
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

struct explorer_mirror_stamp {
    struct utxo_mirror_sync_service *service;
    uint64_t generation;
    int64_t next_height;
};

/* Health and counters are observations, not a lock on future chain changes. */
static bool explorer_mirror_stamp(struct node_db *ndb, struct explorer_mirror_stamp *stamp)
{
    struct utxo_mirror_sync_service *svc = g_utxo_mirror_sync;
    uint64_t before, after;
    if (!svc || svc->ndb != ndb || !atomic_load(&svc->thread_started) ||
        atomic_load(&svc->state) != UTXO_MIRROR_SYNC_RUNNING ||
        atomic_load(&svc->mirror_health) != UTXO_MIRROR_HEALTHY ||
        !utxo_mirror_sync_audit_snapshot(&before)) return false;
    int64_t next = atomic_load(&svc->last_mirror_height);
    int64_t frontier = atomic_load(&svc->last_frontier);
    int64_t pass = atomic_load(&svc->last_pass_unix);
    if (next <= 0 || next != frontier || pass <= 0 ||
        !utxo_mirror_sync_audit_snapshot(&after) || before != after ||
        g_utxo_mirror_sync != svc || atomic_load(&svc->state) != UTXO_MIRROR_SYNC_RUNNING ||
        atomic_load(&svc->mirror_health) != UTXO_MIRROR_HEALTHY) return false;
    *stamp = (struct explorer_mirror_stamp){.service = svc, .generation = after, .next_height = next};
    return true;
}

static void explorer_mirror_read(struct node_db *ndb, const uint8_t *addr_hash,
    struct explorer_address_view_data *d, struct explorer_address_utxo_row rows[100])
{
    struct explorer_mirror_stamp before, after;
    bool available = ndb && addr_hash && explorer_mirror_stamp(ndb, &before);
    if (available) {
        int64_t balance = db_utxo_balance_for_address(ndb, addr_hash);
        zcl_format_zcl(d->balance, sizeof(d->balance), balance);
        d->have_balance = true;
    }

    /* UTXO list */
    size_t nrows = 0;
    if (available) {
        d->have_utxos = true;
        struct db_utxo utxos[100];
        int count = db_utxo_list_for_address(ndb, addr_hash, utxos, 100);
        d->utxo_count = count;

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
    d->rows = rows;
    d->num_rows = nrows;
    if (available && explorer_mirror_stamp(ndb, &after) &&
        before.service == after.service && before.generation == after.generation &&
        before.next_height == after.next_height) {
        d->mirror_next_height = after.next_height;
    } else {
        d->have_balance = false; d->have_utxos = false; d->num_rows = 0;
    }
}

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

    const uint8_t *addr_hash = NULL;
    if (dest.type == DEST_KEY_ID)
        addr_hash = dest.id.key.id.data;
    else if (dest.type == DEST_SCRIPT_ID)
        addr_hash = dest.id.script.hash.data;

    struct explorer_address_view_data d = {0};
    d.safe_addr = safe_addr;
    d.is_p2pkh = (dest.type == DEST_KEY_ID);
    struct explorer_address_utxo_row rows[100];
    explorer_mirror_read(ctx->node_db, addr_hash, &d, rows);

    return explorer_view_address(&d, r, max);
}

/* ── Search ───────────────────────────────────────────────── */

/* URL-decode the query ('+' → space, %XX → byte) */
static bool search_url_decode_query(const char *query, char *decoded,
                                    size_t decoded_size)
{
    size_t di = 0;
    for (size_t si = 0; query[si] && di < decoded_size - 1; si++) {
        if (query[si] == '%' && query[si+1] && query[si+2]) {
            char hex[3] = { query[si+1], query[si+2], '\0' };
            char *endp = NULL;
            long v = strtol(hex, &endp, 16);
            if (!endp || *endp != '\0' || v < 0 || v > 255)
                return false;
            decoded[di++] = (char)v;
            si += 2;
        } else if (query[si] == '+') {
            decoded[di++] = ' ';
        } else {
            decoded[di++] = query[si];
        }
    }
    decoded[di] = '\0';
    return true;
}

/* Strip leading/trailing whitespace */
static size_t search_trim_query_spaces(const char *decoded, char *q,
                                       size_t q_size)
{
    const char *dq = decoded;
    while (*dq == ' ') dq++;
    size_t qlen = strlen(dq);
    if (qlen >= q_size) qlen = q_size - 1;
    memcpy(q, dq, qlen);
    q[qlen] = '\0';
    while (qlen > 0 && q[qlen - 1] == ' ') q[--qlen] = '\0';
    return qlen;
}

/* Block height? Always try — serve_block handles RPC fallback */
static bool search_query_is_block_height(const char *q)
{
    if (zcl_is_all_digits(q)) {
        int h = atoi(q);
        return h >= 0 && h < 100000000;
    }
    return false;
}

/* Address? (starts with t1, t3, etc.) */
static bool search_query_is_address(const char *q, size_t qlen)
{
    if (qlen > 20 && (q[0] == 't' || q[0] == 'T')) {
        struct tx_destination dest;
        return addr_decode(q, &dest);
    }
    return false;
}

/* 64-hex: try as block hash first, then txid */
static size_t search_serve_hex256(struct explorer_context *ctx, const char *q,
                                  uint8_t *r, size_t max)
{
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

size_t serve_search(const char *query, uint8_t *r, size_t max)
{
    struct explorer_context *ctx = explorer_ctx();
    if (!query) return 0;

    char decoded[256];
    if (!search_url_decode_query(query, decoded, sizeof(decoded)))
        return explorer_view_search_invalid(
            "Malformed percent-encoding in query.", r, max);

    char q[256];
    size_t qlen = search_trim_query_spaces(decoded, q, sizeof(q));

    if (!qlen) return explorer_serve_dashboard(r, max);
    if (!explorer_param_is_printable_ascii(q))
        return explorer_view_search_invalid(
            "Search input contains unsupported characters.", r, max);

    if (search_query_is_block_height(q))
        return serve_block(q, r, max);

    if (qlen == 64 && zcl_is_all_hex(q, 64))
        return search_serve_hex256(ctx, q, r, max);

    if (search_query_is_address(q, qlen))
        return serve_address(q, r, max);

    /* Not found */
    char safe[512];
    html_escape(safe, sizeof(safe), q);
    return explorer_view_search_not_found(safe, r, max);
}

/* ── Stats Page with SVG Charts ────────────────────────────── */

/* format_y_label and svg_line_chart moved to explorer_internal.h */

