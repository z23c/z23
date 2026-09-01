/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer block VIEW: block detail page (native + RPC-proxy variants) and
 * the "block not found" error page. The controller parses and fetches; this
 * file assembles the HTML. */

#include "views/explorer_block_view.h"
#include "views/explorer_pages_view.h"
#include "controllers/explorer_internal.h"
#include "util/template.h"
#include "views/format_helpers.h"
#include "views/wallet_templates_gen.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Block Not Found (RPC proxy path) ─────────────────────── */

size_t explorer_view_block_not_found_rpc(uint8_t *r, size_t max)
{
    return explorer_emit_error_page(r, max, 404, "Block Not Found", "The requested block was not found");
}

/* ── Block Not Found (native path) ────────────────────────── */

size_t explorer_view_block_not_found(const char *safe_param,
                                     uint8_t *r, size_t max)
{
    char msg[256];
    snprintf(msg, sizeof(msg), "No block found for: <code>%s</code>", safe_param ? safe_param : "");
    return explorer_emit_error_page(r, max, 404, "Block Not Found", msg);
}

/* ── Block Detail (RPC proxy) ─────────────────────────────── */

size_t explorer_view_block_rpc(const struct explorer_block_rpc_view_data *d,
                               uint8_t *r, size_t max)
{
    if (!d) return 0;
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Block"));
    off += explorer_emit_nav((char *)r + off, max - off, "blocks");

    /* Pager */
    APPEND(off, r, max, "<div class='pager'>");
    if (d->height > 0)
        APPEND(off, r, max, "<a href='/explorer/block/%d'>&laquo; Block %d</a>", d->height - 1, d->height - 1);
    if (d->next_hash[0])
        APPEND(off, r, max, "<a href='/explorer/block/%d'>Block %d &raquo;</a>", d->height + 1, d->height + 1);
    APPEND(off, r, max, "</div>");

    APPEND(off, r, max,
        "<h2>Block %d</h2>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>Hash</div><div class='val hash'>%s</div>"
        "<div class='label'>Height</div><div class='val'>%d</div>"
        "<div class='label'>Time</div><div class='val'>%s</div>"
        "<div class='label'>Transactions</div><div class='val'>%d</div>"
        "<div class='label'>Difficulty</div><div class='val'>%.6f</div>"
        "<div class='label'>Merkle Root</div><div class='val mono'>%s</div>",
        d->height, d->hash, d->height, d->ts, d->tx_count, d->difficulty, d->merkle);
    if (d->prev[0])
        APPEND(off, r, max,
            "<div class='label'>Prev Block</div><div class='val hash'>"
            "<a href='/explorer/block/%s'>%s</a></div>", d->prev, d->prev);
    APPEND(off, r, max, "</div></div>");

    /* Transaction list */
    if (d->has_tx_array) {
        APPEND(off, r, max,
            "<h2>Transactions (%d)</h2>"
            "<table><tr><th>#</th><th>TxID</th></tr>", d->tx_count);

        for (size_t i = 0; i < d->num_rows && off + 256 < max; i++) {
            const struct explorer_block_rpc_tx_row *row = &d->rows[i];
            APPEND(off, r, max,
                "<tr><td>%d</td><td class='hash'><a href='/explorer/tx/%s'>%s</a></td></tr>",
                row->index, row->txid, row->short_txid);
        }
        if (d->tx_count > 100)
            APPEND(off, r, max,
                "<tr><td colspan='2' style='color:#666;text-align:center'>"
                "...and %d more transactions</td></tr>", d->tx_count - 100);
        APPEND(off, r, max, "</table>");
    }

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}

/* ── Block Detail (native) ────────────────────────────────── */

size_t explorer_view_block(const struct explorer_block_view_data *d,
                           uint8_t *r, size_t max)
{
    if (!d) return 0;
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Block"));
    off += explorer_emit_nav((char *)r + off, max - off, "blocks");

    /* Navigation */
    {
        char prev_fmt[32], next_fmt[32], h_fmt[32], conf_fmt[32];
        format_with_commas(prev_fmt, sizeof(prev_fmt), d->height - 1);
        format_with_commas(next_fmt, sizeof(next_fmt), d->height + 1);
        format_with_commas(h_fmt, sizeof(h_fmt), d->height);
        format_with_commas(conf_fmt, sizeof(conf_fmt), d->tip - d->height + 1);

        APPEND(off, r, max, "<div class='pager'>");
        if (d->height > 0)
            APPEND(off, r, max, "<a href='/explorer/block/%d'>&laquo; Block %s</a>", d->height - 1, prev_fmt);
        if (d->height < d->tip)
            APPEND(off, r, max, "<a href='/explorer/block/%d'>Block %s &raquo;</a>", d->height + 1, next_fmt);
        APPEND(off, r, max, "</div>");

        APPEND(off, r, max,
            "<h2>Block %s</h2>"
            "<div class='card'><div class='grid'>"
            "<div class='label'>Hash</div><div class='val hash'>%s</div>"
            "<div class='label'>Height</div><div class='val'>%s</div>"
            "<div class='label'>Confirmations</div><div class='val'>%s</div>"
            "<div class='label'>Time</div><div class='val'>%s</div>"
            "<div class='label'>Transactions</div><div class='val'>%u</div>"
            "<div class='label'>Difficulty</div><div class='val'>%.6f</div>"
            "<div class='label'>Merkle Root</div><div class='val mono'>%s</div>"
            "<div class='label'>Sapling Root</div><div class='val mono'>%s</div>"
            "<div class='label'>Nonce</div><div class='val mono'>%s</div>"
            "<div class='label'>Bits</div><div class='val'>0x%08x</div>"
            "<div class='label'>Sapling &Delta;</div><div class='val amount'>%s ZCL</div>"
            "<div class='label'>Sprout &Delta;</div><div class='val amount'>%s ZCL</div>"
            "</div></div>",
            h_fmt, d->hash, h_fmt, conf_fmt, d->ts, d->n_tx,
            d->difficulty, d->merkle, d->sapling_root, d->nonce,
            d->n_bits, d->sapling_val, d->sprout_val);
    }

    if (d->loaded && d->num_vtx > 0) {
        APPEND(off, r, max,
            "<h2>Transactions (%zu)</h2>"
            "<table><tr><th>#</th><th>TxID</th><th>Type</th>"
            "<th>Inputs</th><th>Outputs</th><th>Value Out</th></tr>",
            d->num_vtx);

        for (size_t i = 0; i < d->num_rows && off + 512 < max; i++) {
            const struct explorer_block_tx_row *row = &d->rows[i];

            char idx_s[21], in_s[21], out_s[21];
            snprintf(idx_s, sizeof(idx_s), "%zu", i);
            snprintf(in_s, sizeof(in_s), "%zu", row->inputs);
            snprintf(out_s, sizeof(out_s), "%zu", row->outputs);

            struct template_var vars[] = {
                { "index",      idx_s },
                { "txid",       row->txid },
                { "short_txid", row->short_txid },
                { "type_tags",  row->type_tags },
                { "inputs",     in_s },
                { "outputs",    out_s },
                { "value",      row->value },
            };
            off += template_render(TMPL_EXPLORER_TX_ROW,
                                   vars, sizeof(vars)/sizeof(vars[0]),
                                   (char *)r + off, max - off);
        }

        if (d->num_vtx > 100)
            APPEND(off, r, max,
                "<tr><td colspan='6' style='color:#666;text-align:center'>"
                "...and %zu more transactions</td></tr>",
                d->num_vtx - 100);

        APPEND(off, r, max, "</table>");
    } else if (!d->loaded) {
        APPEND(off, r, max,
            "<div class='card' style='border-left-color:#ff4444'>"
            "Block data not available on disk.</div>");
    }

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}
