/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer transaction view: the /explorer/tx/{txid} page (native +
 * RPC-proxy variants) and the bad-request / not-found error pages. The
 * controller parses and fetches; this file owns HTML assembly. */

#include "views/explorer_tx_view.h"
#include "views/explorer_pages_view.h"
#include "controllers/explorer_internal.h"
#include "chain/subsidy.h"      /* ZATOSHI_PER_ZCL */
#include "util/template.h"
#include "views/format_helpers.h"
#include "views/wallet_templates_gen.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── RPC-proxy: Transaction Not Found ──────────────────────── */

size_t explorer_view_tx_not_found_rpc(const char *param,
                                      uint8_t *r, size_t max)
{
    char msg[256];
    snprintf(msg, sizeof(msg), "TxID: <code>%s</code>", param ? param : "");
    return explorer_emit_error_page(r, max, 404, "Transaction Not Found", msg);
}

/* ── RPC-proxy: Transaction Detail ─────────────────────────── */

size_t explorer_view_tx_rpc(const struct explorer_tx_rpc_view_data *d,
                            uint8_t *r, size_t max)
{
    if (!d) return 0;
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Transaction"));
    off += explorer_emit_nav((char *)r + off, max - off, NULL);

    APPEND(off, r, max,
        "<h2>Transaction</h2>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>TxID</div><div class='val hash'>%s</div>"
        "<div class='label'>Confirmations</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Size</div><div class='val'>%" PRId64 " bytes</div>"
        "<div class='label'>Version</div><div class='val'>%" PRId64 "</div>"
        "<div class='label'>Lock Time</div><div class='val'>%" PRId64 "</div>",
        d->txid, d->confirmations, d->size, d->version, d->locktime);

    if (d->has_block)
        APPEND(off, r, max,
            "<div class='label'>Block</div><div class='val hash'>"
            "<a href='/explorer/block/%s'>%.16s...</a> (height %" PRId64 ")</div>",
            d->blockhash, d->blockhash, d->block_height);
    if (d->has_expiry)
        APPEND(off, r, max,
            "<div class='label'>Expiry Height</div><div class='val'>%" PRId64 "</div>", d->expiry);
    if (d->has_value_balance)
        APPEND(off, r, max,
            "<div class='label'>Value Balance</div><div class='val amount'>%s ZCL</div>", d->value_balance);

    APPEND(off, r, max, "</div></div>");

    if (d->has_outputs) {
        APPEND(off, r, max, "<h2>Outputs</h2><div class='io-box'>");

        for (size_t i = 0; i < d->num_out_rows && off + 512 < max; i++) {
            const struct explorer_tx_rpc_out_row *o = &d->out_rows[i];
            if (o->kind == EXPLORER_TX_IO_OP_RETURN) {
                APPEND(off, r, max,
                    "<div class='io-row'><div class='io-idx'>%d</div>"
                    "<div class='io-addr' style='color:#888'>OP_RETURN</div>"
                    "<div class='io-val'>%s ZCL</div></div>",
                    o->index, o->value);
            } else if (o->kind == EXPLORER_TX_IO_ADDRESS) {
                APPEND(off, r, max,
                    "<div class='io-row'><div class='io-idx'>%d</div>"
                    "<div class='io-addr'><a href='/explorer/address/%s'>%s</a></div>"
                    "<div class='io-val'>%s ZCL</div></div>",
                    o->index, o->addr, o->addr, o->value);
            } else {
                APPEND(off, r, max,
                    "<div class='io-row'><div class='io-idx'>%d</div>"
                    "<div class='io-addr' style='color:#666'>Unknown</div>"
                    "<div class='io-val'>%s ZCL</div></div>",
                    o->index, o->value);
            }
        }
        APPEND(off, r, max, "</div>");
    }

    if (d->shielded_spend > 0 || d->shielded_output > 0 || d->joinsplit > 0) {
        APPEND(off, r, max, "<h2>Shielded Data</h2><div class='card'><div class='grid'>");
        if (d->shielded_spend > 0)
            APPEND(off, r, max,
                "<div class='label'>Sapling Spends</div><div class='val'>%" PRId64 "</div>",
                d->shielded_spend);
        if (d->shielded_output > 0)
            APPEND(off, r, max,
                "<div class='label'>Sapling Outputs</div><div class='val'>%" PRId64 "</div>",
                d->shielded_output);
        if (d->joinsplit > 0)
            APPEND(off, r, max,
                "<div class='label'>JoinSplits</div><div class='val'>%" PRId64 "</div>",
                d->joinsplit);
        APPEND(off, r, max, "</div></div>");
    }

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}

/* ── Native: error pages ───────────────────────────────────── */

size_t explorer_view_tx_invalid(uint8_t *r, size_t max)
{
    return (size_t)snprintf((char *)r, max,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'></head><body>"
        EXPLORER_NAV "<h2>Invalid Transaction ID</h2>"
        "<p>Expected 64 hex characters.</p>" EXPLORER_FOOTER);
}

size_t explorer_view_tx_not_found(const char *safe_param,
                                  uint8_t *r, size_t max)
{
    return (size_t)snprintf((char *)r, max,
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'></head><body>"
        EXPLORER_NAV "<h2>Transaction Not Found</h2>"
        "<p>TxID: <code>%s</code></p>"
        "<p style='color:#666'>Not in mempool or tx index.</p>" EXPLORER_FOOTER,
        safe_param ? safe_param : "");
}

/* ── Native: Transaction Detail ────────────────────────────── */

size_t explorer_view_tx(const struct explorer_tx_view_data *d,
                        uint8_t *r, size_t max)
{
    if (!d) return 0;
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Transaction"));
    off += explorer_emit_nav((char *)r + off, max - off, NULL);

    APPEND(off, r, max,
        "<h2>Transaction</h2>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>TxID</div><div class='val hash'>%s</div>"
        "<div class='label'>Status</div><div class='val'>%s</div>"
        "<div class='label'>Confirmations</div><div class='val'>%d</div>",
        d->txid,
        d->in_mempool ? "<span class='tag tag-mempool'>Mempool</span>" : "Confirmed",
        d->confirmations);

    if (d->has_block)
        APPEND(off, r, max,
            "<div class='label'>Block</div><div class='val'>"
            "<a href='/explorer/block/%d'>%s</a></div>",
            d->block_height, d->block_height_fmt);

    APPEND(off, r, max,
        "<div class='label'>Version</div><div class='val'>%d%s</div>"
        "<div class='label'>Size</div><div class='val'>%zu bytes</div>"
        "<div class='label'>Lock Time</div><div class='val'>%u</div>",
        d->version, d->overwintered ? " (Overwinter)" : "",
        d->size, d->lock_time);

    if (d->has_expiry)
        APPEND(off, r, max,
            "<div class='label'>Expiry Height</div><div class='val'>%u</div>",
            d->expiry_height);

    if (d->has_value_balance)
        APPEND(off, r, max,
            "<div class='label'>Value Balance</div><div class='val amount'>%s ZCL</div>",
            d->value_balance);

    APPEND(off, r, max, "</div></div>");

    /* Inputs */
    APPEND(off, r, max, "<h2>Inputs (%zu)</h2><div class='io-box'>", d->num_vin);
    for (size_t i = 0; i < d->num_in_rows && off + 512 < max; i++) {
        const struct explorer_tx_in_row *in = &d->in_rows[i];
        if (in->is_coinbase) {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr'><span class='tag tag-cb'>Coinbase</span> "
                "Block reward</div>"
                "<div class='io-val'>%s ZCL</div></div>",
                in->index, in->subsidy);
        } else if (in->have_value) {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr'><a href='/explorer/tx/%s'>%s</a>:%u</div>"
                "<div class='io-val'>%s ZCL</div></div>",
                in->index, in->prev_hash, in->prev_short, in->prev_n, in->value);
        } else {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr'><a href='/explorer/tx/%s'>%s</a>:%u</div>"
                "<div class='io-val' style='color:#666'>?</div></div>",
                in->index, in->prev_hash, in->prev_short, in->prev_n);
        }
    }
    APPEND(off, r, max, "</div>");

    /* Outputs */
    APPEND(off, r, max, "<h2>Outputs (%zu)</h2><div class='io-box'>", d->num_vout);
    for (size_t i = 0; i < d->num_out_rows && off + 512 < max; i++) {
        const struct explorer_tx_out_row *o = &d->out_rows[i];
        if (o->kind == EXPLORER_TX_IO_OP_RETURN) {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr' style='color:#888'>OP_RETURN (%zu bytes)</div>"
                "<div class='io-val'>%s ZCL</div></div>",
                o->index, o->script_size, o->value);
        } else if (o->kind == EXPLORER_TX_IO_ADDRESS) {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr'><a href='/explorer/address/%s'>%s</a></div>"
                "<div class='io-val'>%s ZCL</div></div>",
                o->index, o->addr, o->addr, o->value);
        } else {
            APPEND(off, r, max,
                "<div class='io-row'>"
                "<div class='io-idx'>%zu</div>"
                "<div class='io-addr' style='color:#666'>Non-standard script (%zu bytes)</div>"
                "<div class='io-val'>%s ZCL</div></div>",
                o->index, o->script_size, o->value);
        }
    }
    APPEND(off, r, max,
        "<div class='io-row' style='font-weight:bold;border-top:1px solid #333'>"
        "<div class='io-idx'></div><div class='io-addr'>Total</div>"
        "<div class='io-val'>%s ZCL</div></div>", d->total_out);
    APPEND(off, r, max, "</div>");

    /* Shielded data */
    if (d->num_shielded_spend > 0 || d->num_shielded_output > 0 || d->num_joinsplit > 0) {
        APPEND(off, r, max, "<h2>Shielded Data</h2><div class='card'><div class='grid'>");
        if (d->num_shielded_spend > 0)
            APPEND(off, r, max,
                "<div class='label'>Sapling Spends</div><div class='val'>%zu</div>",
                d->num_shielded_spend);
        if (d->num_shielded_output > 0)
            APPEND(off, r, max,
                "<div class='label'>Sapling Outputs</div><div class='val'>%zu</div>",
                d->num_shielded_output);
        if (d->num_joinsplit > 0)
            APPEND(off, r, max,
                "<div class='label'>JoinSplits</div><div class='val'>%zu</div>"
                "<div class='label'>vpub_old (t&rarr;z)</div><div class='val amount'>%s ZCL</div>"
                "<div class='label'>vpub_new (z&rarr;t)</div><div class='val amount'>%s ZCL</div>",
                d->num_joinsplit, d->joinsplit_in, d->joinsplit_out);
        APPEND(off, r, max, "</div></div>");
    }

    /* ZSLP token data */
    if (d->slp.kind != EXPLORER_TX_SLP_NONE) {
        APPEND(off, r, max,
            "<h2><span class='tag tag-slp'>ZSLP Token</span></h2>"
            "<div class='card'><div class='grid'>");

        if (d->slp.kind == EXPLORER_TX_SLP_GENESIS) {
            APPEND(off, r, max,
                "<div class='label'>Type</div><div class='val'>GENESIS</div>"
                "<div class='label'>Ticker</div><div class='val' style='color:#ff88ff'>%s</div>"
                "<div class='label'>Name</div><div class='val'>%s</div>"
                "<div class='label'>Decimals</div><div class='val'>%u</div>"
                "<div class='label'>Initial Supply</div><div class='val'>%s</div>",
                d->slp.ticker, d->slp.name, d->slp.decimals, d->slp.initial_supply);
            if (d->slp.has_doc_url)
                APPEND(off, r, max,
                    "<div class='label'>Document URL</div><div class='val'>%s</div>",
                    d->slp.doc_url);
        } else if (d->slp.kind == EXPLORER_TX_SLP_SEND) {
            APPEND(off, r, max,
                "<div class='label'>Type</div><div class='val'>SEND</div>"
                "<div class='label'>Token ID</div><div class='val hash'>"
                "<a href='/explorer/tx/%s'>%s</a></div>",
                d->slp.token_id, d->slp.token_id);
            for (int q = 0; q < d->slp.num_outputs; q++) {
                char qlbl[32];
                snprintf(qlbl, sizeof(qlbl), "Output %d", q + 1);
                APPEND(off, r, max,
                    "<div class='label'>%s</div><div class='val'>%" PRIu64 "</div>",
                    qlbl, d->slp.output_quantities[q]);
            }
        } else if (d->slp.kind == EXPLORER_TX_SLP_MINT) {
            APPEND(off, r, max,
                "<div class='label'>Type</div><div class='val'>MINT</div>"
                "<div class='label'>Token ID</div><div class='val hash'>"
                "<a href='/explorer/tx/%s'>%s</a></div>"
                "<div class='label'>Quantity</div><div class='val'>%s</div>",
                d->slp.token_id, d->slp.token_id, d->slp.mint_quantity);
        }

        APPEND(off, r, max, "</div></div>");
    }

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}
