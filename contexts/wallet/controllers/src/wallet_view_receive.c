/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

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

    /* ── Public address pane ── */
    {
        /* Build QR SVG into temp buffer */
        char qr_buf[65536] = "";
        wv_emit_qr_svg((uint8_t *)qr_buf, sizeof(qr_buf), 0, PRIMARY_ADDR, 5);

        /* Build chunked address display */
        char chunk_buf[512];
        size_t ci = 0;
        const char *a = PRIMARY_ADDR;
        size_t alen = strlen(a);
        ci += (size_t)snprintf(chunk_buf + ci, sizeof(chunk_buf) - ci,
            "<div class='addr-display addr-chunked' "
            "style='margin-top:16px' id='t-addr'>"
            "<span class='hi'>%.4s</span>", a);
        for (size_t i = 4; i < alen && ci < sizeof(chunk_buf) - 80; i += 4) {
            size_t left = alen - i;
            if (left > 4) left = 4;
            ci += (size_t)snprintf(chunk_buf + ci, sizeof(chunk_buf) - ci,
                "<span class='sep'> </span>");
            if (i + left >= alen)
                ci += (size_t)snprintf(chunk_buf + ci, sizeof(chunk_buf) - ci,
                    "<span class='hi'>%.*s</span>", (int)left, a + i);
            else
                ci += (size_t)snprintf(chunk_buf + ci, sizeof(chunk_buf) - ci,
                    "%.*s", (int)left, a + i);
        }
        snprintf(chunk_buf + ci, sizeof(chunk_buf) - ci, "</div>");

        struct template_var tv[] = {
            { "qr_svg", qr_buf },
            { "chunked_addr", chunk_buf },
        };
        off += template_render(TMPL_RECEIVE_TPANE, tv, 2,
            (char *)r + off, max - off);
    }

    off += template_render(TMPL_RECEIVE_JS, NULL, 0,
        (char *)r + off, max - off);
    off += template_render(TMPL_RECEIVE_COPY_JS, NULL, 0,
        (char *)r + off, max - off);

    wv_emit_footer(r, max, &off);
    return off;
}

/* ── History (/wallet/history) ──────────────────────────────── */
