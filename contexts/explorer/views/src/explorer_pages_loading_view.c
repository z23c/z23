/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer pages loading VIEW: the token-index status page served while its
 * background cache warms. */

#include "views/explorer_pages_loading_view.h"
#include "controllers/explorer_internal.h"

#include <stddef.h>
#include <stdint.h>

size_t explorer_view_tokens_loading(uint8_t *r, size_t max)
{
    size_t off = 0;
    APPEND(off, r, max,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='stylesheet' href='/explorer/style.css'>"
        "</head><body>" EXPLORER_NAV
        "<div style='max-width:900px;margin:50px auto;color:#ccc'>"
        "<h1 style='font-size:32px;color:#ff99ff'>Token Index Warming</h1>"
        "<p style='font-size:18px;color:#888'>The ZSLP projection is being "
        "built in the background. Blocks, stats, and node status remain "
        "available now.</p>"
        "<div style='display:flex;gap:12px;flex-wrap:wrap;margin-top:22px'>"
        "<a href='/explorer' style='display:inline-block;background:#33ff99;"
        "color:#07130d;padding:10px 14px;border-radius:6px;font-weight:700;"
        "text-decoration:none'>Open blocks</a>"
        "<a href='/api/v1/status' style='display:inline-block;border:1px solid #333;"
        "color:#ddd;padding:10px 14px;border-radius:6px;text-decoration:none'>"
        "Open node status JSON</a>"
        "</div>"
        "</div>" EXPLORER_FOOTER);
    return off;
}
