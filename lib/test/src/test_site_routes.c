/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_site_routes — the site route registry (net/site_routes.def) gate.
 *
 * The def is the single inventory of the app MVC web mounts; the onion
 * and HTTPS dispatch chains, the ratelimit classifier, and both site
 * navs all expand it. This group pins the contract without
 * string-scraping any .c file — every assertion reads the generated
 * tables (lib/net/src/site_routes.c) or calls the real classifier:
 *
 *   1. Dispatch order: the def rows, in order, are exactly the pinned
 *      (id, prefix) list — store, /n/, /names, zcode, metaverse, blog,
 *      yardsale, /market/chunk, /observation.json.
 *   2. Every row's cost class is a valid onion_route_class, and the
 *      per-row classes are pinned at their current values (names_gateway
 *      EXPENSIVE with the "name-gateway" puzzle key, everything else
 *      CHEAP with no key).
 *   3. Method flags: the POST surface is onion-only by construction — the
 *      pinned POST-flagged set is {store, names, yardsale}, store,
 *      market_chunk and observation are the mounts absent from the HTTPS
 *      expansion (observation is a peer-to-peer document served to
 *      nodes, never to a browser), and
 *      the HTTPS-served POST rows (names, yardsale) carry
 *      F_HTTPS|F_POST_ONION, i.e. GET only on that listener (it 405s
 *      non-GET/HEAD before dispatch).
 *   4. apps/<app>/app.def ZCL_APP_WEB_MOUNT correspondence, both
 *      directions:
 *      blog and yardsale each mount exactly the prefix of their def row;
 *      social's "/" mount is the documented manifest-only exception (the
 *      "/" front door is node chrome, serve_landing_page, not an app
 *      runtime route) and is asserted to have NO row. The app_id column
 *      (the /directory.json "apps" advertisement set) is pinned to
 *      exactly {blog, yardsale}, each cross-checked against its app.def's
 *      ZCL_APP_ONION(true).
 *   5. Byte-exact nav/grid pins: both generated nav tables, the landing
 *      app grid, the SITE_GLOBAL_NAV literal twin contract, and the
 *      zcl_site_onion_nav_emit() output (the former ONION_GLOBAL_NAV).
 *   6. Classifier agreement: onion_route_classify() on each row's prefix
 *      returns the row's cost class and key, and the hand-written
 *      EXPENSIVE specials above the def expansion still fire. */

#include "test/test_core.h"

#include "net/onion_ratelimit.h"
#include "net/site_routes.h"
#include "views/site_layout.h"

#include <stdio.h>
#include <string.h>

#define SR_CHECK(name, expr) do {                                   \
    printf("site_routes: %s... ", (name));                          \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* ── Pinned expectations ─────────────────────────────────────────────── */

static const struct { const char *id; const char *prefix; } k_rows[] = {
    { "store",         "/store"        },
    { "names_gateway", "/n/"           },
    { "names",         "/names"        },
    { "zcode",         "/zcode"        },
    { "metaverse",     "/metaverse"    },
    { "blog",          "/blog"         },
    { "yardsale",      "/yardsale"     },
    { "market_chunk",  "/market/chunk" },
    { "observation",   "/observation.json" },
};
#define K_ROW_COUNT (sizeof(k_rows) / sizeof(k_rows[0]))

/* Both navs carry the same app set — the wayfinding contract is that the
 * two transports never disagree about the map of the world. */
static const struct zcl_site_nav_link k_nav_app[] = {
    { "/explorer",  "Explorer",  "explorer"  },
    { "/names",     "Names",     "names"     },
    { "/store",     "Store",     "store"     },
    { "/blog",      "Blog",      "blog"      },
    { "/metaverse", "Metaverse", "metaverse" },
    { "/yardsale",  "Yardsale",  "yardsale"  },
    { "/zcode",     "Zcode",     "zcode"     },
    { "/directory", "Directory", "directory" },
};

static const struct zcl_site_nav_link k_nav_onion[] = {
    { "/explorer",  "Explorer",  "explorer"  },
    { "/names",     "Names",     "names"     },
    { "/store",     "Store",     "store"     },
    { "/blog",      "Blog",      "blog"      },
    { "/metaverse", "Metaverse", "metaverse" },
    { "/yardsale",  "Yardsale",  "yardsale"  },
    { "/zcode",     "Zcode",     "zcode"     },
    { "/directory", "Directory", "directory" },
};

static const struct zcl_site_grid_entry k_grid[] = {
    { "/explorer", "Explorer",
      "REST-style chain, block, transaction, address, and token reads." },
    { "/store", "Store",
      "Commerce and token purchase flows hosted directly on the node." },
    { "/blog", "Blog",
      "Static site hosting from your datadir over the onion service." },
    { "/yardsale", "Yardsale",
      "Signed for-sale-by-owner token signs; buyers settle directly with "
      "sellers." },
    { "/zcode", "Zcode",
      "Packages, publishers, rankings, and downloads from the on-node "
      "ZCODE library." },
    { "/directory", "Directory",
      "On-chain discovered peer/app directory for the Tor-only network." },
    { "/status", "Status API",
      "Machine-readable node, sync, and onion reachability status." },
};

/* The former ONION_GLOBAL_NAV literal, byte-exact. */
static const char k_onion_nav_html[] =
    "<header class='site-top'>"
    "<a class='brand' href='/'>"
    "<span class='glyph' aria-hidden='true'>Z</span>"
    "<span>Z23</span></a>"
    "<nav aria-label='Site'>"
    "<a href='/explorer'>Explorer</a>"
    "<a href='/names'>Names</a>"
    "<a href='/store'>Store</a>"
    "<a href='/blog'>Blog</a>"
    "<a href='/metaverse'>Metaverse</a>"
    "<a href='/yardsale'>Yardsale</a>"
    "<a href='/zcode'>Zcode</a>"
    "<a href='/directory'>Directory</a>"
    "</nav></header>";

/* ── Small helpers ───────────────────────────────────────────────────── */

static const struct zcl_site_route *sr_find(const char *id)
{
    for (size_t i = 0; i < g_zcl_site_routes_count; i++)
        if (strcmp(g_zcl_site_routes[i].id, id) == 0)
            return &g_zcl_site_routes[i];
    return NULL;
}

static size_t sr_count_prefix(const char *prefix)
{
    size_t n = 0;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++)
        if (strcmp(g_zcl_site_routes[i].prefix, prefix) == 0)
            n++;
    return n;
}

static bool sr_nav_eq(const struct zcl_site_nav_link *got, size_t got_n,
                      const struct zcl_site_nav_link *want, size_t want_n)
{
    if (got_n != want_n) return false;
    for (size_t i = 0; i < want_n; i++)
        if (strcmp(got[i].href, want[i].href) != 0 ||
            strcmp(got[i].label, want[i].label) != 0 ||
            strcmp(got[i].id, want[i].id) != 0)
            return false;
    return true;
}

/* Extract the ZCL_APP_WEB_MOUNT("...") value from an app.def, or return
 * false when absent/unreadable. Tests run from the repository root. */
static bool sr_app_mount(const char *def_path, char *out, size_t out_max)
{
    FILE *f = fopen(def_path, "r");
    if (!f) return false; // raw-return-ok:fixture-read-fails-closed
    char line[512];
    bool found = false;
    const char *key = "ZCL_APP_WEB_MOUNT(\"";
    const size_t key_len = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        const char *p = strstr(line, key);
        if (!p) continue;
        p += key_len;
        const char *end = strchr(p, '"');
        if (!end) break;
        size_t len = (size_t)(end - p);
        if (len >= out_max) break;
        memcpy(out, p, len);
        out[len] = '\0';
        found = true;
        break;
    }
    fclose(f);
    return found;
}

/* True when the app.def declares ZCL_APP_ONION(true). */
static bool sr_app_onion_enabled(const char *def_path)
{
    FILE *f = fopen(def_path, "r");
    if (!f) return false; // raw-return-ok:fixture-read-fails-closed
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "ZCL_APP_ONION(true)")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

/* ── The group ───────────────────────────────────────────────────────── */

int test_site_routes(void)
{
    printf("\n=== site route registry tests ===\n");
    int failures = 0;

    /* 1. Pinned dispatch order. */
    SR_CHECK("registry row count", g_zcl_site_routes_count == K_ROW_COUNT);
    bool order_ok = g_zcl_site_routes_count == K_ROW_COUNT;
    for (size_t i = 0; i < K_ROW_COUNT && order_ok; i++)
        order_ok = strcmp(g_zcl_site_routes[i].id, k_rows[i].id) == 0 &&
                   strcmp(g_zcl_site_routes[i].prefix, k_rows[i].prefix) == 0;
    SR_CHECK("dispatch order pinned (store,/n/,/names,zcode,metaverse,"
             "blog,yardsale,/market/chunk,/observation.json)", order_ok);

    /* 2. Cost classes valid + pinned; route keys pinned. */
    bool cost_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        enum onion_route_class c = g_zcl_site_routes[i].cost;
        if (c != ONION_ROUTE_STATIC && c != ONION_ROUTE_CHEAP &&
            c != ONION_ROUTE_EXPENSIVE)
            cost_ok = false;
    }
    SR_CHECK("every cost class valid", cost_ok);
    SR_CHECK("names_gateway EXPENSIVE + name-gateway key",
             sr_find("names_gateway") &&
             sr_find("names_gateway")->cost == ONION_ROUTE_EXPENSIVE &&
             strcmp(sr_find("names_gateway")->route_key,
                    "name-gateway") == 0);
    bool others_cheap = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++)
        if (strcmp(g_zcl_site_routes[i].id, "names_gateway") != 0 &&
            (g_zcl_site_routes[i].cost != ONION_ROUTE_CHEAP ||
             g_zcl_site_routes[i].route_key[0] != '\0'))
            others_cheap = false;
    SR_CHECK("all other rows CHEAP with no route key", others_cheap);

    /* 3. Method flags. */
    bool flags_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++)
        if (g_zcl_site_routes[i].flags & ~ZCL_SITE_F_ALL)
            flags_ok = false;
    SR_CHECK("flags within the known mask", flags_ok);

    bool post_set_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        const char *id = g_zcl_site_routes[i].id;
        bool want_post = strcmp(id, "store") == 0 ||
                         strcmp(id, "names") == 0 ||
                         strcmp(id, "yardsale") == 0;
        bool has_post =
            (g_zcl_site_routes[i].flags & ZCL_SITE_F_POST_ONION) != 0;
        if (want_post != has_post)
            post_set_ok = false;
    }
    SR_CHECK("POST-onion set is exactly {store, names, yardsale}",
             post_set_ok);

    /* The HTTPS expansion serves every row except the onion-only store
     * and market_chunk mounts; the POST-flagged rows it does serve
     * (names, yardsale) are GET/HEAD-only there by the listener-wide 405
     * gate — POST exists only in the onion dispatch. */
    bool https_set_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        const char *id = g_zcl_site_routes[i].id;
        bool want_https = strcmp(id, "store") != 0 &&
                          strcmp(id, "market_chunk") != 0 &&
                          strcmp(id, "observation") != 0;
        bool has_https =
            (g_zcl_site_routes[i].flags & ZCL_SITE_F_HTTPS) != 0;
        if (want_https != has_https)
            https_set_ok = false;
    }
    SR_CHECK("HTTPS set is every row except store, market_chunk and "
             "observation", https_set_ok);
    SR_CHECK("onion-only rows carry no HTTPS bit",
             sr_find("store") && sr_find("market_chunk") &&
             sr_find("observation") &&
             !(sr_find("store")->flags & ZCL_SITE_F_HTTPS) &&
             !(sr_find("market_chunk")->flags & ZCL_SITE_F_HTTPS) &&
             !(sr_find("observation")->flags & ZCL_SITE_F_HTTPS) &&
             (sr_find("market_chunk")->flags &
              (ZCL_SITE_F_PREFIX_GUARD | ZCL_SITE_F_FAIL_CLOSED)) ==
                 (ZCL_SITE_F_PREFIX_GUARD | ZCL_SITE_F_FAIL_CLOSED) &&
             (sr_find("observation")->flags &
              (ZCL_SITE_F_PREFIX_GUARD | ZCL_SITE_F_FAIL_CLOSED)) ==
                 (ZCL_SITE_F_PREFIX_GUARD | ZCL_SITE_F_FAIL_CLOSED));
    SR_CHECK("HTTPS-served POST rows are GET-only there (F_HTTPS|"
             "F_POST_ONION, no https-POST bit exists)",
             sr_find("names") && sr_find("yardsale") &&
             (sr_find("names")->flags &
              (ZCL_SITE_F_HTTPS | ZCL_SITE_F_POST_ONION)) ==
                 (ZCL_SITE_F_HTTPS | ZCL_SITE_F_POST_ONION) &&
             (sr_find("yardsale")->flags &
              (ZCL_SITE_F_HTTPS | ZCL_SITE_F_POST_ONION)) ==
                 (ZCL_SITE_F_HTTPS | ZCL_SITE_F_POST_ONION) &&
             sr_find("store") &&
             !(sr_find("store")->flags & ZCL_SITE_F_HTTPS));

    /* 4. apps/<app>/app.def mount correspondence, both directions. */
    static const struct { const char *app; const char *def_path; } k_apps[] = {
        { "blog",     "apps/blog/app.def"     },
        { "social",   "apps/social/app.def"   },
        { "yardsale", "apps/yardsale/app.def" },
    };
    bool mounts_ok = true;
    for (size_t i = 0; i < sizeof(k_apps) / sizeof(k_apps[0]); i++) {
        char mount[128];
        if (!sr_app_mount(k_apps[i].def_path, mount, sizeof(mount))) {
            mounts_ok = false;
            break;
        }
        size_t n_rows = sr_count_prefix(mount);
        if (strcmp(k_apps[i].app, "social") == 0) {
            /* Documented manifest-only exception: social declares a "/"
             * web mount, but "/" is the node's chrome landing page
             * (serve_landing_page) — no runtime route may claim it. */
            if (strcmp(mount, "/") != 0 || n_rows != 0)
                mounts_ok = false;
            continue;
        }
        /* 1:1: exactly one row, and it is the row named for the app. */
        const struct zcl_site_route *r = sr_find(k_apps[i].app);
        if (n_rows != 1 || !r || strcmp(r->prefix, mount) != 0)
            mounts_ok = false;
    }
    SR_CHECK("app.def mounts 1:1 with rows (social \"/\" = documented "
             "exception)", mounts_ok);
    /* Reverse: no row may sit on a mount some app.def declares under a
     * different app id, and no row claims "/". */
    bool reverse_ok = (sr_count_prefix("/") == 0);
    for (size_t i = 0; i < g_zcl_site_routes_count && reverse_ok; i++) {
        const char *id = g_zcl_site_routes[i].id;
        if (strcmp(id, "blog") == 0 || strcmp(id, "yardsale") == 0) {
            char mount[128];
            char path[128];
            snprintf(path, sizeof(path), "apps/%s/app.def", id);
            if (!sr_app_mount(path, mount, sizeof(mount)) ||
                strcmp(mount, g_zcl_site_routes[i].prefix) != 0)
                reverse_ok = false;
        }
    }
    SR_CHECK("rows named for apps mount their app.def prefix; no row "
             "claims \"/\"", reverse_ok);

    /* 4b. The app_id column: exactly the mounted app-catalog Apps carry
     * their id (blog, yardsale — the set served as "apps" on this node's
     * /directory.json self row), and every one of them declares
     * ZCL_APP_ONION(true) in its app.def, so the advertisement can never
     * drift from the catalog. social declares ONION(true) but has no row
     * (the documented "/" exception) and so advertises nothing. */
    bool appcol_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        const struct zcl_site_route *r = &g_zcl_site_routes[i];
        const char *want = NULL;
        if (strcmp(r->id, "blog") == 0) want = "blog";
        if (strcmp(r->id, "yardsale") == 0) want = "yardsale";
        if (!want) {
            if (r->app_id != NULL)
                appcol_ok = false;
            continue;
        }
        if (!r->app_id || strcmp(r->app_id, want) != 0) {
            appcol_ok = false;
            continue;
        }
        char path[128];
        snprintf(path, sizeof(path), "apps/%s/app.def", r->app_id);
        if (!sr_app_onion_enabled(path))
            appcol_ok = false;
    }
    SR_CHECK("app_id column is exactly {blog, yardsale}, each ZCL_APP_"
             "ONION(true) in its app.def", appcol_ok);

    /* 5. Byte-exact nav/grid pins. */
    SR_CHECK("app-side nav table",
             sr_nav_eq(g_zcl_site_nav_app, g_zcl_site_nav_app_count,
                       k_nav_app, sizeof(k_nav_app) / sizeof(k_nav_app[0])));
    SR_CHECK("onion nav table",
             sr_nav_eq(g_zcl_site_nav_onion, g_zcl_site_nav_onion_count,
                       k_nav_onion,
                       sizeof(k_nav_onion) / sizeof(k_nav_onion[0])));
    bool grid_ok = g_zcl_site_app_grid_count ==
                   sizeof(k_grid) / sizeof(k_grid[0]);
    for (size_t i = 0; i < sizeof(k_grid) / sizeof(k_grid[0]) && grid_ok;
         i++)
        grid_ok = strcmp(g_zcl_site_app_grid[i].href, k_grid[i].href) == 0 &&
                  strcmp(g_zcl_site_app_grid[i].label, k_grid[i].label) == 0 &&
                  strcmp(g_zcl_site_app_grid[i].desc, k_grid[i].desc) == 0;
    SR_CHECK("landing app grid", grid_ok);

    char nav_buf[1024];
    size_t nav_len = site_emit_global_nav(nav_buf, sizeof(nav_buf), NULL);
    SR_CHECK("SITE_GLOBAL_NAV literal twin",
             nav_len == strlen(SITE_GLOBAL_NAV) &&
             strcmp(nav_buf, SITE_GLOBAL_NAV) == 0);
    nav_len = zcl_site_onion_nav_emit(nav_buf, sizeof(nav_buf));
    SR_CHECK("onion nav emitter byte-identical to the former "
             "ONION_GLOBAL_NAV",
             nav_len == strlen(k_onion_nav_html) &&
             strcmp(nav_buf, k_onion_nav_html) == 0);
    /* The active-class path still marks exactly the matching link. */
    nav_len = site_emit_global_nav(nav_buf, sizeof(nav_buf), "blog");
    SR_CHECK("active class emission intact",
             strstr(nav_buf, "<a href='/blog' class='active'>Blog</a>") &&
             !strstr(nav_buf, "<a href='/store' class='active'>"));

    /* 6. Classifier agreement: each row's prefix classifies to the row's
     * own class and key, and the hand-written specials above the def
     * expansion still fire. */
    char key[32];
    bool classify_ok = true;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        char probe[64];
        snprintf(probe, sizeof(probe), "%s", g_zcl_site_routes[i].prefix);
        size_t plen = strlen(probe);
        if (plen > 1 && probe[plen - 1] == '/')
            snprintf(probe + plen, sizeof(probe) - plen, "x");
        key[0] = '\1'; /* sentinel: classify must reset it */
        enum onion_route_class got =
            onion_route_classify("GET", probe, key);
        if (got != g_zcl_site_routes[i].cost ||
            strcmp(key, g_zcl_site_routes[i].route_key) != 0)
            classify_ok = false;
    }
    SR_CHECK("classify(prefix) == row cost + key for every row",
             classify_ok);
    key[0] = '\0';
    SR_CHECK("store order POST special still EXPENSIVE",
             onion_route_classify("POST", "/store/orders", key) ==
                 ONION_ROUTE_EXPENSIVE &&
             strcmp(key, "store-order") == 0);
    key[0] = '\0';
    SR_CHECK("store order GET stays CHEAP (method-sensitive)",
             onion_route_classify("GET", "/store/orders", key) ==
                 ONION_ROUTE_CHEAP);
    key[0] = '\0';
    SR_CHECK("search specials still EXPENSIVE",
             onion_route_classify("GET", "/search", key) ==
                 ONION_ROUTE_EXPENSIVE &&
             strcmp(key, "search-hostname") == 0 &&
             onion_route_classify("GET", "/explorer/search", NULL) ==
                 ONION_ROUTE_EXPENSIVE);
    key[0] = '\0';
    SR_CHECK("chrome STATIC set unaffected",
             onion_route_classify("GET", "/", key) == ONION_ROUTE_STATIC &&
             onion_route_classify("GET", "/status", NULL) ==
                 ONION_ROUTE_STATIC &&
             onion_route_classify("GET", "/explorer/style.css", NULL) ==
                 ONION_ROUTE_STATIC);
    key[0] = '\0';
    SR_CHECK("names gateway vs registry split",
             onion_route_classify("GET", "/n/somename", key) ==
                 ONION_ROUTE_EXPENSIVE &&
             strcmp(key, "name-gateway") == 0 &&
             onion_route_classify("GET", "/names", key) ==
                 ONION_ROUTE_CHEAP &&
             key[0] == '\0');

    if (failures == 0)
        printf("site_routes: all checks passed\n");
    return failures;
}
