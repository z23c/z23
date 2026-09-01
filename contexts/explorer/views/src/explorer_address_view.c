/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer address + search VIEWS. The controller parses and fetches; this
 * file assembles the HTML. */

#include "views/explorer_address_view.h"
#include "controllers/explorer_internal.h"
#include "views/format_helpers.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Invalid Address (400) ────────────────────────────────── */

size_t explorer_view_address_invalid(const char *safe_addr,
                                     uint8_t *r, size_t max)
{
    return (size_t)snprintf((char *)r, max,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'></head><body>"
        EXPLORER_NAV "<h2>Invalid Address</h2>"
        "<p><code>%s</code> is not a valid ZClassic address.</p>"
        EXPLORER_FOOTER, safe_addr ? safe_addr : "");
}

/* ── Address Detail ───────────────────────────────────────── */

size_t explorer_view_address(const struct explorer_address_view_data *d,
                             uint8_t *r, size_t max)
{
    if (!d) return 0;
    size_t off = 0;

    APPEND(off, r, max, EXPLORER_HEADER("Address"));
    off += explorer_emit_nav((char *)r + off, max - off, NULL);

    APPEND(off, r, max,
        "<h2>Address</h2>"
        "<div class='card'><div class='grid'>"
        "<div class='label'>Address</div><div class='val hash'>%s</div>"
        "<div class='label'>Type</div><div class='val'>%s</div>",
        d->safe_addr ? d->safe_addr : "",
        d->is_p2pkh ? "P2PKH (Pay-to-PubKey-Hash)" : "P2SH (Pay-to-Script-Hash)");

    if (d->have_balance) {
        APPEND(off, r, max,
            "<div class='label'>Balance</div><div class='val amount'>%s ZCL</div>",
            d->balance);
    }
    APPEND(off, r, max, "</div></div>");

    /* UTXO list */
    if (d->have_utxos) {
        APPEND(off, r, max,
            "<h2>Unspent Outputs (%d)</h2>"
            "<table><tr><th>TxID</th><th>Vout</th><th>Value</th>"
            "<th>Height</th><th>Type</th></tr>", d->utxo_count);

        for (size_t i = 0; i < d->num_rows && off + 512 < max; i++) {
            const struct explorer_address_utxo_row *row = &d->rows[i];
            APPEND(off, r, max,
                "<tr><td class='hash'><a href='/explorer/tx/%s'>%s</a></td>"
                "<td>%u</td><td class='amount'>%s ZCL</td>"
                "<td>%d</td><td>%s</td></tr>",
                row->txid_hex, row->short_txid, row->vout, row->value,
                row->height,
                row->is_coinbase ? "<span class='tag tag-cb'>CB</span>" : "");
        }

        APPEND(off, r, max, "</table>");
        if (d->utxo_count == 0) {
            APPEND(off, r, max,
                "<p style='color:#666'>No unspent outputs found for this address.</p>");
        }
    } else {
        APPEND(off, r, max,
            "<p style='color:#666'>UTXO index not available.</p>");
    }

    APPEND(off, r, max, EXPLORER_FOOTER);
    return off;
}

/* ── Search: invalid query (400) ──────────────────────────── */

size_t explorer_view_search_invalid(const char *detail, uint8_t *r, size_t max)
{
    return (size_t)snprintf((char *)r, max,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'></head><body>"
        EXPLORER_NAV "<h2>Invalid Search Query</h2>"
        "<p>%s</p>" EXPLORER_FOOTER, detail ? detail : "");
}

/* ── Search: no results ───────────────────────────────────── */

size_t explorer_view_search_not_found(const char *safe_query,
                                      uint8_t *r, size_t max)
{
    size_t off = 0;
    APPEND(off, r, max, EXPLORER_HEADER("Search"));
    off += explorer_emit_nav((char *)r + off, max - off, NULL);
    APPEND(off, r, max,
        "<h2>Search Results</h2>"
        "<div class='card'>"
        "<p>No results for: <code>%s</code></p>"
        "<p style='color:#666'>Try a block height, block hash, transaction ID, or address.</p>"
        "</div>" EXPLORER_FOOTER, safe_query ? safe_query : "");
    return off;
}
