/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Renders the /wallet/receive page with transparent and shielded addresses and QR codes.
 */

#include "controllers/wallet_view_internal.h"
#include "controllers/wallet_controller.h"
#include "util/log_macros.h"

/* ── Receive (/wallet/receive) ──────────────────────────────── */

size_t serve_receive(uint8_t *r, size_t max) {
    sqlite3 *db = wv_open_db();
    size_t off = wv_emit_header(r, max, "Receive — Z23", "/wallet/receive");

    off += template_render(TMPL_RECEIVE_TABS, NULL, 0,
        (char *)r + off, max - off);
    off += template_render(TMPL_RECEIVE_ZPANE_OPEN, NULL, 0,
        (char *)r + off, max - off);

    struct wv_receive_address z_addrs[16];
    int z_count = 0;
    if (db) {
        z_count = wv_list_receive_addresses(db, z_addrs,
            sizeof(z_addrs) / sizeof(z_addrs[0]));
        sqlite3_close(db);
        db = NULL;
    }

    for (int i = 0; i < z_count && off + 512 < max; i++) {
        char escaped[1024];
        html_escape(escaped, sizeof(escaped), z_addrs[i].address);
        if (i == 0) {
            off = wv_emit_qr_svg(r, max, off, z_addrs[i].address, 3);
            APPEND(off, r, max,
                "<div class='addr-display-sm' style='font-size:13px;"
                "margin-top:12px'>%s</div>", escaped);
        } else if (i == 1) {
            APPEND(off, r, max,
                "<details style='margin-top:8px'>"
                "<summary style='color:#888;font-size:14px;"
                "cursor:pointer'>Show all addresses</summary>"
                "<div class='addr-display-sm' style='font-size:13px'>"
                "%s</div>", escaped);
        } else {
            APPEND(off, r, max,
                "<div class='addr-display-sm' style='font-size:13px'>"
                "%s</div>", escaped);
        }
    }
    if (z_count > 1)
        APPEND(off, r, max, "</details>");

    if (z_count == 0) {
        off += template_render(TMPL_RECEIVE_NO_ZADDR, NULL, 0,
            (char *)r + off, max - off);
    }

    off += template_render(TMPL_RECEIVE_ZPANE_CLOSE, NULL, 0,
        (char *)r + off, max - off);

    /* Do not present a fixed placeholder as a wallet-owned deposit address. */
    APPEND(off, r, max,
        "<div id='pane-t' style='display:none;text-align:center;padding:16px 0'>"
        "<div class='balance-sub'>Transparent receiving unavailable</div>"
        "<p>Public transactions are visible on-chain. This view cannot verify "
        "a wallet-owned transparent address; use a verified wallet address "
        "from the wallet command interface instead.</p></div>");

    off += template_render(TMPL_RECEIVE_JS, NULL, 0,
        (char *)r + off, max - off);
    off += template_render(TMPL_RECEIVE_COPY_JS, NULL, 0,
        (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── History (/wallet/history) ──────────────────────────────── */
