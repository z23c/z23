/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Site route registry — the generated tables. net/site_routes.def is the
 * one inventory; this file expands it into the test-visible descriptor
 * table and the two global navs + the onion landing app grid (chrome
 * entries at their historical fixed positions). The dispatch chains
 * (onion_service.c, https_server.c) and the ratelimit classifier
 * (onion_ratelimit.c) expand the same def for code; everything here is
 * data, so test_site_routes can pin order, classes, flags, and the
 * byte-exact nav/grid content without string-scraping a .c file. */

#include "net/site_routes.h"

#include <stdio.h>

/* ── Descriptor table (dispatch order == def row order) ─────────────── */

const struct zcl_site_route g_zcl_site_routes[] = {
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    { #id, prefix, #handler, #flavor, cost, rkey, \
      (ZCL_SITE_FLAGS_##flavor) | (methods), \
      ZCL_SITE_POSNUM_##nav_app, ZCL_SITE_POSNUM_##nav_onion, \
      ZCL_SITE_POSNUM_##grid, nav_label, nav_href, nav_id, grid_desc, \
      fail_body, app_id },
#include "net/site_routes.def"
#undef SITE_ROUTE
};

const size_t g_zcl_site_routes_count =
    sizeof(g_zcl_site_routes) / sizeof(g_zcl_site_routes[0]);

/* ── Global navs ────────────────────────────────────────────────────────
 *
 * Chrome rows ([0] Explorer, [7] Directory) stay hand-written; the app
 * rows land at their fixed slots via the ZCL_SITE_POS_* selectors, so
 * emitted HTML stays byte-stable while the link data has one home. Both
 * transports carry the same app set — a nav slot token means both navs. */

const struct zcl_site_nav_link g_zcl_site_nav_app[] = {
    [0] = { "/explorer", "Explorer", "explorer" },
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_POS_##nav_app(nav_href, nav_label, nav_id)
#include "net/site_routes.def"
#undef SITE_ROUTE
    [7] = { "/directory", "Directory", "directory" },
};

const size_t g_zcl_site_nav_app_count =
    sizeof(g_zcl_site_nav_app) / sizeof(g_zcl_site_nav_app[0]);

const struct zcl_site_nav_link g_zcl_site_nav_onion[] = {
    [0] = { "/explorer", "Explorer", "explorer" },
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_POS_##nav_onion(nav_href, nav_label, nav_id)
#include "net/site_routes.def"
#undef SITE_ROUTE
    [7] = { "/directory", "Directory", "directory" },
};

const size_t g_zcl_site_nav_onion_count =
    sizeof(g_zcl_site_nav_onion) / sizeof(g_zcl_site_nav_onion[0]);

/* ── Landing-page app grid ──────────────────────────────────────────────
 *
 * Same fixed-position scheme: [0] Explorer, [5] Directory, [6] Status API
 * are chrome; the def rows fill [1..4]. */

const struct zcl_site_grid_entry g_zcl_site_app_grid[] = {
    [0] = { "/explorer", "Explorer",
            "REST-style chain, block, transaction, address, and token "
            "reads." },
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_POS_##grid(nav_href, nav_label, grid_desc)
#include "net/site_routes.def"
#undef SITE_ROUTE
    [5] = { "/directory", "Directory",
            "On-chain discovered peer/app directory for the Tor-only "
            "network." },
    [6] = { "/status", "Status API",
            "Machine-readable node, sync, and onion reachability status." },
};

const size_t g_zcl_site_app_grid_count =
    sizeof(g_zcl_site_app_grid) / sizeof(g_zcl_site_app_grid[0]);

/* ── Onion front-door nav emitter ─────────────────────────────────────── */

size_t zcl_site_onion_nav_emit(char *buf, size_t max)
{
    size_t off = 0;
    int n = snprintf(buf, max,
        "<header class='site-top'>"
        "<a class='brand' href='/'>"
        "<span class='glyph' aria-hidden='true'>Z</span>"
        "<span>Z23</span></a>"
        "<nav aria-label='Site'>");
    if (n > 0)
        off = (size_t)n < max ? (size_t)n : max;
    for (size_t i = 0; i < g_zcl_site_nav_onion_count && off < max; i++) {
        n = snprintf(buf + off, max - off, "<a href='%s'>%s</a>",
                     g_zcl_site_nav_onion[i].href,
                     g_zcl_site_nav_onion[i].label);
        if (n > 0) {
            size_t wrote = (size_t)n < max - off ? (size_t)n : max - off;
            off += wrote;
        }
    }
    if (off < max) {
        n = snprintf(buf + off, max - off, "</nav></header>");
        if (n > 0) {
            size_t wrote = (size_t)n < max - off ? (size_t)n : max - off;
            off += wrote;
        }
    }
    return off;
}
