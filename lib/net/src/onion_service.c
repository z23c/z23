/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Onion service: bridges Tor dynhost to zclassic23 MVC controllers.
 * All .onion traffic flows through here. */

#include "platform/time_compat.h"
#include "net/onion_service.h"
#include "net/onion_peer_merge.h"
#include "net/onion_ratelimit.h"
#include "net/site_routes.h"
#include "net/tor_integration.h"
#include "net/rom_seed.h"
#include "net/peer_strategy.h"
#include "znam/znam.h"
#include "util/log_json.h"
#include "util/log_macros.h"
#include "util/path_check.h"
#include "util/supervisor.h"
#include "util/template.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <sqlite3.h>
#include "util/ar_step_readonly.h"

struct onion_context {
    char address[128];
    const char *datadir;
    time_t start_time;
    onion_blog_serve_fn blog_serve;
    onion_peer_discover_fn peer_discover;
    onion_signed_peer_source_fn signed_source;
    void *signed_ctx;
};

static struct onion_context g_onion_ctx = {0};

static struct onion_context *onion_ctx(void)
{
    return &g_onion_ctx;
}

void onion_service_set_app_handlers(onion_blog_serve_fn blog_serve,
                                    onion_peer_discover_fn peer_discover)
{
    struct onion_context *ctx = onion_ctx();
    ctx->blog_serve = blog_serve;
    ctx->peer_discover = peer_discover;
}

void onion_service_set_signed_peer_source(onion_signed_peer_source_fn source,
                                          void *ctx_arg)
{
    struct onion_context *ctx = onion_ctx();
    ctx->signed_source = source;
    ctx->signed_ctx = ctx_arg;
}

/* Signed descriptors first, then the unsigned wallet scrape; the rule
 * and the merge live in net/onion_peer_merge.h. */
static int onion_discover_peers(struct onion_peer *out, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    int rejected = 0;
    int kept = onion_peers_collect(out, max, ctx->signed_source,
                                   ctx->signed_ctx, ctx->peer_discover,
                                   ctx->datadir, &rejected);
    if (rejected > 0)
        log_jsonf(LOG_JSON_WARN, "onion_hostname_rejected",
                  "\"dropped\":%d", rejected);
    return kept;
}

/* ── Shared page chrome for the onion front door ──────────────
 *
 * Inline twin of the site design system's tokens (app/views/src/site.css).
 * These pages live in lib/net — below the app/views layer — and the front
 * door must render even when the explorer asset cache is not initialized,
 * so they carry their own compact copy of the palette/type instead of
 * linking /explorer/style.css or including an app/views header. Keep the
 * values in lockstep with site.css's :root tokens (dark variant; both
 * themes are declared via color-scheme so form controls follow the page).
 * Single % everywhere: always substituted via a "%s" argument, never
 * embedded in a printf format string. */
static const char ONION_PAGE_CSS[] =
    ":root{--bg:#0a0d12;--panel:#121722;--panel-2:#171d2a;--border:#232b3a;"
    "--border-strong:#313b4e;--ink:#e9eef6;--ink-dim:#c3ccd9;--muted:#97a3b6;"
    "--accent:#5ea8ff;--accent-ink:#b9d9ff;--ok:#3ddc97;--warn:#f0b44c;"
    "--bad:#f2708a;color-scheme:dark light}"
    "*{box-sizing:border-box}"
    "body{margin:0 auto;max-width:860px;padding:16px 24px 40px;"
    "background:var(--bg);color:var(--ink);font-family:-apple-system,"
    "BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
    "font-size:16px;line-height:1.6}"
    "h1{font-size:28px;font-weight:720;letter-spacing:-0.015em;margin:0 0 12px}"
    "h2{font-size:20px;font-weight:680;margin:28px 0 12px;padding-bottom:8px;"
    "border-bottom:1px solid var(--border)}"
    "a{color:var(--accent);text-decoration:none}"
    "a:hover{color:var(--accent-ink);text-decoration:underline}"
    "a:focus-visible,input:focus-visible,button:focus-visible{outline:3px "
    "solid var(--ok);outline-offset:2px;border-radius:6px}"
    ".site-top{display:flex;align-items:center;gap:4px 18px;flex-wrap:wrap;"
    "padding:10px 0 14px;margin-bottom:18px;border-bottom:1px solid var(--border)}"
    ".site-top .brand{display:flex;align-items:center;gap:10px;margin-right:auto;"
    "font-weight:760;color:var(--ink)}"
    ".site-top .brand:hover{text-decoration:none}"
    ".site-top .brand .glyph{display:grid;place-items:center;width:30px;height:30px;"
    "border-radius:9px;border:1px solid var(--border-strong);"
    "background:linear-gradient(145deg,rgba(94,168,255,.13),rgba(167,139,250,.14));"
    "color:var(--accent-ink);font-weight:800}"
    ".site-top nav{display:flex;gap:2px;flex-wrap:wrap}"
    ".site-top nav a{padding:6px 11px;border-radius:6px;border:1px solid transparent;"
    "color:var(--muted);font-size:14px;font-weight:620;white-space:nowrap}"
    ".site-top nav a:hover{color:var(--ink);background:var(--panel);"
    "border-color:var(--border);text-decoration:none}"
    ".card,.site{background:linear-gradient(180deg,var(--panel-2) 0,var(--panel) 100%);"
    "border:1px solid var(--border);border-left:3px solid var(--accent);"
    "border-radius:10px;padding:16px 20px;margin:12px 0}"
    ".site a{font-size:16px}"
    ".desc{color:var(--muted);font-size:13px;margin-top:5px;line-height:1.45}"
    ".dashboard{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin:18px 0}"
    ".stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;"
    "padding:16px;text-align:center}"
    ".stat .val{color:var(--ok);font-size:24px;font-weight:700;"
    "font-variant-numeric:tabular-nums}"
    ".stat .label{color:var(--muted);font-size:12px;margin-top:4px;"
    "text-transform:uppercase;letter-spacing:.05em}"
    ".addr,.onion-addr{background:var(--bg);border:1px solid var(--border);"
    "padding:10px 12px;border-radius:6px;word-break:break-all;"
    "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;"
    "color:var(--accent);margin:10px 0;text-align:center}"
    ".apps{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));"
    "gap:12px;margin:20px 0}"
    ".app{background:var(--panel);border:1px solid var(--border);border-radius:10px;"
    "padding:14px}"
    ".app a{font-size:16px;font-weight:640}"
    "input[type=text]{background:var(--bg);color:var(--ink);"
    "border:1px solid var(--border-strong);border-radius:6px;padding:10px 12px;"
    "width:100%;font-size:15px;box-sizing:border-box}"
    "table{width:100%;border-collapse:collapse;font-size:15px;background:var(--panel);"
    "border:1px solid var(--border);border-radius:10px;overflow:hidden;margin:16px 0}"
    "th{text-align:left;color:var(--muted);padding:10px 12px;"
    "border-bottom:1px solid var(--border-strong);font-size:12px;"
    "text-transform:uppercase;letter-spacing:.04em}"
    "td{padding:9px 12px;border-bottom:1px solid var(--border)}"
    ".self{border-left:3px solid var(--ok)}"
    ".table-wrap{overflow-x:auto;max-width:100%}"
    ".muted{color:var(--muted)}"
    ".veil{min-height:70vh;display:flex;flex-direction:column;align-items:center;"
    "justify-content:center;text-align:center}"
    ".veil p{color:var(--muted);max-width:560px}"
    "footer{text-align:center;color:var(--muted);font-size:13px;margin-top:40px;"
    "padding:16px;border-top:1px solid var(--border)}"
    "@media(max-width:640px){.dashboard{grid-template-columns:1fr}"
    ".site-top{gap:4px 10px}}";

/* The global nav these pages emit is generated: zcl_site_onion_nav_emit()
 * (lib/net/src/site_routes.c) walks the nav table expanded from
 * net/site_routes.def — the single inventory — so this file no longer
 * keeps a hand-written lockstep copy of the app-side site_layout.h nav. */

/* Request admission — cost-tiered budgets plus an adaptive client puzzle
 * on expensive routes under sustained pressure. See net/onion_ratelimit.h
 * for the route table, tier sizing, and escalation thresholds. Replaces a
 * single global 100 req/s counter, under which one flooding client on any
 * path starved every honest client on every path. */

/* ── Query node stats from SQLite ─────────────────────────── */

static void query_node_stats(int *out_height, int *out_peers)
{
    struct onion_context *ctx = onion_ctx();
    *out_height = 0;
    *out_peers = 0;
    if (!ctx->datadir) return;

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), ctx->datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        LOG_WARN("net", "node db open failed: %s", db_path);
        return;
    }
    /* 5s timeout — allows reads even during heavy block sync */
    sqlite3_busy_timeout(db, 5000);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT MAX(height) FROM blocks", -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            *out_height = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM peers WHERE last_seen > strftime('%s','now') - 3600",
            -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            *out_peers = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
}

/* ── Landing page: node dashboard + directory ─────────────── */

static size_t serve_landing_page(uint8_t *response, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    /* Gather node info */
    int height = 0, peer_count = 0;
    query_node_stats(&height, &peer_count);

    long uptime = 0;
    if (ctx->start_time > 0)
        uptime = (long)(platform_time_wall_time_t() - ctx->start_time);

    /* Discover registered .onion sites from chain */
    struct onion_peer peers[64];
    int num_peers = 0;
    num_peers = onion_discover_peers(peers, 64);

    const char *onion = ctx->address[0] ? ctx->address : NULL;

    /* Build body into a temp buffer, then wrap with Content-Length */
    char body[32768];
    size_t off = 0;
    int n = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Z23 Node</title>"
        "<style>%s</style></head><body>",
        ONION_PAGE_CSS);
    if (n > 0) off = (size_t)n;

    off += zcl_site_onion_nav_emit(body + off, sizeof(body) - off);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Z23 Node</h1>"
        "<p class='muted'>A new internet. Tor-only. No DNS. No cloud.</p>");
    if (n > 0) off += (size_t)n;

    /* Node .onion address */
    if (onion) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='onion-addr'>%s</div>", onion);
        if (n > 0) off += (size_t)n;
    }

    /* Dashboard stats — detect sync-in-progress */
    bool syncing = (height == 0 && uptime < 600) || (height > 0 && height < 100);
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='dashboard'>"
        "<div class='stat'><div class='val'>%s%d</div>"
        "<div class='label'>Block Height</div></div>"
        "<div class='stat'><div class='val'>%d</div>"
        "<div class='label'>Peers (1h)</div></div>"
        "<div class='stat'><div class='val'>%ldm</div>"
        "<div class='label'>Uptime</div></div>"
        "</div>",
        syncing ? "syncing... " : "", height, peer_count, uptime / 60);
    if (syncing) {
        n += snprintf(body + off + (n > 0 ? n : 0),
            sizeof(body) - off - (size_t)(n > 0 ? n : 0),
            "<p class='muted' style='color:var(--warn)'>"
            "Node is syncing the blockchain. Stats will update as blocks are indexed."
            "</p>");
    }
    if (n > 0) off += (size_t)n;

    /* Search bar */
    n = snprintf(body + off, sizeof(body) - off,
        "<form action='/search' method='get'>"
        "<label for='onion-q' class='muted' style='display:block;font-size:13px;"
        "font-weight:640;margin:12px 0 4px'>Search the network</label>"
        "<input type='text' id='onion-q' name='q' placeholder='Search .onion sites by hostname...'>"
        "</form>");
    if (n > 0) off += (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<h2>Power Node Apps</h2>"
        "<div class='apps'>");
    if (n > 0) off += (size_t)n;
    /* Grid entries come from net/site_routes.def via g_zcl_site_app_grid
     * (chrome rows included, at their historical positions). */
    for (size_t gi = 0; gi < g_zcl_site_app_grid_count; gi++) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='app'><a href='%s'>%s</a>"
            "<div class='desc'>%s</div></div>",
            g_zcl_site_app_grid[gi].href, g_zcl_site_app_grid[gi].label,
            g_zcl_site_app_grid[gi].desc);
        if (n > 0) off += (size_t)n;
    }
    n = snprintf(body + off, sizeof(body) - off, "</div>");
    if (n > 0) off += (size_t)n;

    /* Peer directory */
    n = snprintf(body + off, sizeof(body) - off,
        "<h2>Network Directory (%d peers)</h2>", num_peers);
    if (n > 0) off += (size_t)n;

    if (num_peers == 0 && onion) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='site'>"
            "<a href='http://%s/'>This node</a>"
            "<div class='desc'>Your local Z23 node</div></div>",
            onion);
        if (n > 0) off += (size_t)n;
    }

    for (int i = 0; i < num_peers && off + 512 < sizeof(body); i++) {
        char esc_host[384]; /* hostname[64] worst-case html-escaped */
        html_escape(esc_host, sizeof(esc_host), peers[i].hostname);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='site'>"
            "<a href='http://%s/'>%s</a>"
            "<div class='desc'>Discovered at height %d</div></div>",
            esc_host, esc_host, peers[i].height);
        if (n > 0) off += (size_t)n;
    }

    /* Seed node */
    n = snprintf(body + off, sizeof(body) - off,
        "<div class='site'>"
        "<a href='http://zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion/'>"
        "zc23kenf...jnad.onion</a>"
        "<div class='desc'>Z23 seed node</div></div>"
        "<h2>Host Your Site</h2>"
        "<div class='site'>"
        "<div class='desc'>Every z23 node is a .onion web server.<br>"
        "Put HTML in <code>{datadir}/blog/</code> and it's live.<br>"
        "Explorer, store, blog, and directory are first-class power-node apps.<br>"
        "Register on-chain via ZSLP for network discovery.</div></div>"
        "<footer>Z23 v0.1.0 &mdash; pure C23 full node + Tor</footer>"
        "</body></html>");
    if (n > 0) off += (size_t)n;

    /* Wrap with HTTP headers including Content-Length */
    return (size_t)snprintf((char *)response, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%s", off, body);
}

/* ── Search handler ───────────────────────────────────────── */

/* One searchable directory row: the raw endpoint plus the on-chain name
 * that resolves to it, if any. The name is a LABEL for the address, never
 * a replacement — both are rendered, so a visitor always sees what they
 * are actually connecting to. */
struct onion_search_hit {
    char host[64];
    char name[ZNAM_NAME_MAX + 1];
    int  height;
};

/* ASCII case-insensitive substring. ZNAM names are lowercase by
 * construction; visitors are not. */
static bool str_contains_ci(const char *hay, const char *needle)
{
    if (!hay || !needle) return false;
    if (!needle[0]) return true;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen) {
            unsigned char a = (unsigned char)p[i], b = (unsigned char)needle[i];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (!a || a != b) break;
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static bool search_hit_known(const struct onion_search_hit *hits, int n,
                             const char *host)
{
    for (int i = 0; i < n; i++)
        if (strcmp(hits[i].host, host) == 0) return true;
    return false;
}

/* Append one hit if the query matches its host OR its name. Returns the
 * new count. Bounded by cap; duplicates are dropped. */
static int search_hit_add(struct onion_search_hit *hits, int n, int cap,
                          const char *host, const char *name, int height,
                          const char *query)
{
    if (n >= cap) return n;
    if (!onion_hostname_valid(host)) return n;
    if (query && query[0] &&
        !str_contains_ci(host, query) &&
        !(name && name[0] && str_contains_ci(name, query)))
        return n;
    if (search_hit_known(hits, n, host)) return n;
    snprintf(hits[n].host, sizeof(hits[n].host), "%s", host);
    snprintf(hits[n].name, sizeof(hits[n].name), "%s", name ? name : "");
    hits[n].height = height;
    return n + 1;
}

static size_t serve_search(const char *query, uint8_t *response, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    struct onion_peer peers[64];
    int num_peers = onion_discover_peers(peers, 64);

    /* Read-only handle for the two projections searched below. Absent or
     * unopenable → the chain-scan source alone still answers, exactly as
     * before: a search never regresses because a projection is missing. */
    sqlite3 *db = NULL;
    if (ctx->datadir) {
        char db_path[1024];
        zcl_node_db_path(db_path, sizeof(db_path), ctx->datadir);
        if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            db = NULL;
        } else {
            sqlite3_busy_timeout(db, 5000);
        }
    }

    struct onion_search_hit hits[64];
    int nhits = 0;
    char name_buf[ZNAM_NAME_MAX + 1];

    /* Source 1 — on-chain .onion announcements (the pre-existing source;
     * kept first and never narrowed). */
    for (int i = 0; i < num_peers; i++) {
        name_buf[0] = '\0';
        if (db) (void)onion_directory_name_for_db(db, peers[i].hostname,
                                                  name_buf, sizeof(name_buf));
        nhits = search_hit_add(hits, nhits, 64, peers[i].hostname,
                               name_buf, peers[i].height, query);
    }

    /* Source 2 — the peer_directory itself, so a node learned from a peer's
     * directory (not from a chain scan) is searchable too. */
    if (db) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT onion_address, height FROM peer_directory "
            "ORDER BY self DESC, last_seen DESC LIMIT 256",
            -1, &s, NULL) == SQLITE_OK && s) {
            while (nhits < 64 && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *addr = (const char *)sqlite3_column_text(s, 0);
                if (!addr) continue;
                name_buf[0] = '\0';
                (void)onion_directory_name_for_db(db, addr,
                                                  name_buf, sizeof(name_buf));
                nhits = search_hit_add(hits, nhits, 64, addr, name_buf,
                                       sqlite3_column_int(s, 1), query);
            }
        }
        if (s) sqlite3_finalize(s);
    }

    /* Source 3 — the ZNAM projection directly: a registered name resolves
     * even when neither the chain scan nor the directory has met the host
     * yet. Filtered in C (not via LIKE) so a query containing % or _ is
     * matched literally rather than as a wildcard. */
    if (db) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT name, target_value FROM znam_names "
            "WHERE target_type=?1 ORDER BY reg_height DESC LIMIT 256",
            -1, &s, NULL) == SQLITE_OK && s) {
            sqlite3_bind_int(s, 1, ZNAM_TYPE_ONION);
            while (nhits < 64 && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                const char *nm = (const char *)sqlite3_column_text(s, 0);
                const char *tv = (const char *)sqlite3_column_text(s, 1);
                if (!nm || !tv || !onion_directory_label_is_renderable(nm)) continue;
                char host[64];
                if (strlen(tv) == 56)
                    snprintf(host, sizeof(host), "%s.onion", tv);
                else
                    snprintf(host, sizeof(host), "%s", tv);
                nhits = search_hit_add(hits, nhits, 64, host, nm, 0, query);
            }
        }
        if (s) sqlite3_finalize(s);
    }

    if (db) sqlite3_close(db);

    char safe_query[512];
    html_escape(safe_query, sizeof(safe_query), query ? query : "");

    char body[16384];
    size_t off = 0;
    int n = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Search: %s</title>"
        "<style>%s</style></head><body>",
        safe_query, ONION_PAGE_CSS);
    if (n > 0) off = (size_t)n;

    off += zcl_site_onion_nav_emit(body + off, sizeof(body) - off);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Search</h1>"
        "<p>Results for: <b>%s</b></p>",
        safe_query);
    if (n > 0) off += (size_t)n;

    int found = 0;
    for (int i = 0; i < nhits && off + 640 < sizeof(body); i++) {
        char esc_host[384]; /* hostname[64] worst-case html-escaped */
        char esc_name[256]; /* name[64] worst-case html-escaped */
        html_escape(esc_host, sizeof(esc_host), hits[i].host);
        html_escape(esc_name, sizeof(esc_name), hits[i].name);

        char hstr[48] = "";
        if (hits[i].height > 0)
            snprintf(hstr, sizeof(hstr), "height %d", hits[i].height);

        /* A registered name becomes the link text; the raw .onion always
         * follows it in the description. Nameless hosts link by address, as
         * before. */
        bool named = hits[i].name[0] != '\0';
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='site'><a href='http://%s/'>%s</a>"
            "<div class='desc'>%s%s%s</div></div>",
            esc_host, named ? esc_name : esc_host,
            named ? esc_host : "",
            (named && hstr[0]) ? " &middot; " : "",
            hstr);
        if (n > 0) off += (size_t)n;
        found++;
    }

    if (found == 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p class='muted'>No results.</p>");
        if (n > 0) off += (size_t)n;
    }

    n = snprintf(body + off, sizeof(body) - off,
        "<p class='muted'>Search matches .onion hostnames discovered on-chain "
        "or through the peer directory, and ZNAM names registered on-chain for "
        "those hosts. A name is a label for an address, not a substitute: the "
        "raw .onion you would connect to is always shown with it.</p>"
        "<footer>Z23 &mdash; one binary, one onion, one stack</footer>"
        "</body></html>");
    if (n > 0) off += (size_t)n;

    return (size_t)snprintf((char *)response, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%s", off, body);
}

/* ── Directory endpoints ─────────────────────────────────── */

static size_t serve_directory_json(uint8_t *response, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    if (!ctx->datadir) return 0;

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), ctx->datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return 0;
    }
    sqlite3_busy_timeout(db, 5000);

    char body[65536];
    size_t off = 0;
    int n = snprintf(body, sizeof(body), "{\"nodes\":[");
    if (n > 0) off = (size_t)n;

    /* Freshness is a served field, not a hidden filter: rows past
     * ONION_DIR_EXPIRE_SECS are withheld (the refresh round deletes them on
     * its own cadence; this makes the endpoint correct in between), and
     * every row that IS served carries its age, the policy constants, and
     * both the hearsay stamp (last_seen) and the contact record
     * (last_success + dial counts), so a consumer can judge it rather than
     * trusting the list. The self row is never age-filtered. */
    int64_t now = (int64_t)platform_time_wall_time_t();

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT onion_address, port, services, height, last_seen, "
        "version, self, clearnet_ip, clearnet_port, "
        "COALESCE(first_seen,0), COALESCE(last_probe,0), "
        "COALESCE(probe_ok,0), COALESCE(fail_count,0), COALESCE(source,''), "
        "COALESCE(last_success,0), COALESCE(dial_success_count,0), "
        "COALESCE(apps,'') "
        "FROM peer_directory "
        "ORDER BY self DESC, last_seen DESC LIMIT " ONION_DIR_STR(ONION_DIR_SERVE_MAX),
        -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        sqlite3_close(db);
        return 0;
    }

    int count = 0;
    int skipped_expired = 0;
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && off + 1300 < sizeof(body)) {
        const char *addr = (const char *)sqlite3_column_text(s, 0);
        int port = sqlite3_column_int(s, 1);
        int svc = sqlite3_column_int(s, 2);
        int h = sqlite3_column_int(s, 3);
        int64_t ls = sqlite3_column_int64(s, 4);
        const char *ver = (const char *)sqlite3_column_text(s, 5);
        int self = sqlite3_column_int(s, 6);
        const char *cip = (const char *)sqlite3_column_text(s, 7);
        int cport = sqlite3_column_int(s, 8);
        int64_t fs = sqlite3_column_int64(s, 9);
        int64_t lp = sqlite3_column_int64(s, 10);
        int probe_ok = sqlite3_column_int(s, 11);
        int fails = sqlite3_column_int(s, 12);
        const char *src = (const char *)sqlite3_column_text(s, 13);
        int64_t lsucc = sqlite3_column_int64(s, 14);
        int64_t ok_n = sqlite3_column_int64(s, 15);
        const char *apps_col = (const char *)sqlite3_column_text(s, 16);

        /* Rows stored by pre-validation binaries may be hostile. */
        if (!onion_hostname_valid(addr)) continue;

        /* Never hand out a row nothing has confirmed for a week. The
         * refresh round deletes these; skipping them here keeps the
         * served list honest even on a node whose refresh child never
         * registered. */
        enum onion_dir_freshness fresh =
            onion_directory_freshness(ls, now, self != 0);
        if (fresh == ONION_DIR_EXPIRED) {
            skipped_expired++;
            continue;
        }

        char addr_esc[160], ver_esc[96], cip_esc[96], src_esc[64];
        log_json_escape(addr_esc, sizeof(addr_esc), addr);
        log_json_escape(ver_esc, sizeof(ver_esc), ver);
        log_json_escape(cip_esc, sizeof(cip_esc), cip);
        log_json_escape(src_esc, sizeof(src_esc), src);

        /* The on-chain name for this endpoint, when one is registered. The
         * name never replaces the address in the record — it is an extra
         * field beside it, so a consumer that resolves by address keeps
         * working and one that displays a name has the raw target too. */
        char name[ZNAM_NAME_MAX + 1] = "";
        char name_esc[160];
        (void)onion_directory_name_for_db(db, addr, name, sizeof(name));
        log_json_escape(name_esc, sizeof(name_esc), name);

        /* The app-service advertisement (Track 2): which app-catalog Apps
         * this host serves on its onion. Emitted right after "name" —
         * NEVER between clearnet_ip and clearnet_port, whose adjacency the
         * connman seed-fetch string-scan relies on (lib/net/src/connman.c
         * try_onion_seed_fetch_depth reads clearnet_port within 50 chars
         * of clearnet_ip). Old consumers ignore the unknown key; every
         * token is re-validated on the way out, so a row stored by a
         * pre-validation binary cannot inject text into the array. */
        char apps_json[2 * ONION_DIR_APPS_CSV_MAX + 16];
        size_t aj = (size_t)snprintf(apps_json, sizeof(apps_json),
                                     "\"apps\":[");
        const char *ap = apps_col;
        bool first_app = true;
        while (ap && *ap && aj + 40 < sizeof(apps_json)) {
            const char *comma = strchr(ap, ',');
            size_t tl = comma ? (size_t)(comma - ap) : strlen(ap);
            char tok[ONION_DIR_APP_ID_MAX + 1];
            if (tl > 0 && tl <= ONION_DIR_APP_ID_MAX) {
                memcpy(tok, ap, tl);
                tok[tl] = '\0';
                if (onion_directory_app_id_valid(tok)) {
                    int wn = snprintf(apps_json + aj, sizeof(apps_json) - aj,
                                      "%s\"%s\"", first_app ? "" : ",", tok);
                    if (wn > 0) aj += (size_t)wn;
                    first_app = false;
                }
            }
            ap += tl + (comma ? 1 : 0);
        }
        (void)snprintf(apps_json + aj, sizeof(apps_json) - aj, "]");

        if (count > 0) off += (size_t)snprintf(body + off, sizeof(body) - off, ",");
        off += (size_t)snprintf(body + off, sizeof(body) - off,
            "{\"onion\":\"%s\",\"name\":\"%s\",%s,\"port\":%d,\"services\":%d,"
            "\"height\":%d,\"last_seen\":%lld,\"version\":\"%s\",\"self\":%s,"
            "\"clearnet_ip\":\"%s\",\"clearnet_port\":%d,"
            "\"age_secs\":%lld,\"stale\":%s,\"first_seen\":%lld,"
            "\"last_probe\":%lld,\"probe_ok\":%s,\"fail_count\":%d,"
            "\"last_success\":%lld,\"dial_success_count\":%lld,"
            "\"source\":\"%s\"}",
            addr_esc, name_esc, apps_json, port, svc, h,
            (long long)ls, ver_esc,
            self ? "true" : "false",
            cip_esc, cport,
            (long long)onion_directory_age_secs(ls, now),
            fresh == ONION_DIR_STALE ? "true" : "false",
            (long long)fs, (long long)lp,
            probe_ok ? "true" : "false", fails,
            (long long)lsucc, (long long)ok_n,
            src_esc);
        count++;
    }
    sqlite3_finalize(s);
    sqlite3_close(db);

    /* Advertise the free ROM/sync artifacts this node seeds (kind + digest +
     * size + chunking) so a fresh node can discover WHO seeds WHAT without
     * waiting for gossip warm-up. Only appended when there is room; the JSON
     * stays well-formed either way. */
    char arts[2560];
    size_t an = rom_seed_directory_json(arts, sizeof(arts));
    const char *arts_body = (an > 0 && off + an + 64 < sizeof(body))
                                ? arts : "[]";
    /* The freshness policy travels WITH the list. A consumer that
     * disagrees with our thresholds can re-judge every row from its own
     * age_secs instead of taking our word for it. */
    off += (size_t)snprintf(body + off, sizeof(body) - off,
        "],\"count\":%d,\"generated_at\":%lld,\"stale_after_secs\":%lld,"
        "\"expire_after_secs\":%lld,\"refresh_secs\":%d,"
        "\"skipped_expired\":%d,\"artifacts\":%s}",
        count, (long long)now, (long long)ONION_DIR_STALE_SECS,
        (long long)ONION_DIR_EXPIRE_SECS, ONION_DIR_REFRESH_SECS,
        skipped_expired, arts_body);

    return (size_t)snprintf((char *)response, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%s", off, body);
}

static size_t serve_directory_html(uint8_t *response, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    if (!ctx->datadir) return 0;

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), ctx->datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return 0;
    }
    sqlite3_busy_timeout(db, 5000);

    char body[65536];
    size_t off = 0;
    int n = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Z23 Node Directory</title>"
        "<style>%s</style></head><body>",
        ONION_PAGE_CSS);
    if (n > 0) off = (size_t)n;

    off += zcl_site_onion_nav_emit(body + off, sizeof(body) - off);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Node Directory</h1>"
        "<p class='muted'>Decentralized .onion network &mdash; every node is a server</p>");
    if (n > 0) off += (size_t)n;

    off += (size_t)snprintf(body + off, sizeof(body) - off,
        "<div class='table-wrap'><table><tr><th>Node</th><th>Port</th>"
        "<th>Height</th><th>Last Seen</th><th>Reached</th>"
        "<th>Version</th></tr>");

    int64_t now = (int64_t)platform_time_wall_time_t();

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT onion_address, port, height, last_seen, version, self, "
        "COALESCE(last_success,0), COALESCE(dial_success_count,0), "
        "COALESCE(fail_count,0) "
        "FROM peer_directory ORDER BY self DESC, last_seen DESC LIMIT "
        ONION_DIR_STR(ONION_DIR_SERVE_MAX),
        -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        sqlite3_close(db);
        return 0;
    }

    int count = 0;
    while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW && off + 900 < sizeof(body)) {
        const char *addr = (const char *)sqlite3_column_text(s, 0);
        int port = sqlite3_column_int(s, 1);
        int h = sqlite3_column_int(s, 2);
        int64_t ls = sqlite3_column_int64(s, 3);
        const char *ver = (const char *)sqlite3_column_text(s, 4);
        int self = sqlite3_column_int(s, 5);
        int64_t lsucc = sqlite3_column_int64(s, 6);
        int64_t ok_n = sqlite3_column_int64(s, 7);
        int64_t fail_n = sqlite3_column_int64(s, 8);

        /* Rows stored by pre-validation binaries may be hostile. */
        if (!onion_hostname_valid(addr)) continue;

        /* Same freshness rule the JSON endpoint applies — one page must
         * never show what the other refuses to serve. */
        enum onion_dir_freshness fresh =
            onion_directory_freshness(ls, now, self != 0);
        if (fresh == ONION_DIR_EXPIRED) continue;

        char addr_esc[160], ver_esc[96];
        html_escape(addr_esc, sizeof(addr_esc), addr);
        html_escape(ver_esc, sizeof(ver_esc), ver);

        /* On-chain name for this endpoint, shown as the heading WITH the
         * raw .onion beneath it — a visitor always sees the address they
         * would actually connect to. */
        char name[ZNAM_NAME_MAX + 1] = "";
        char name_esc[256];
        (void)onion_directory_name_for_db(db, addr, name, sizeof(name));
        html_escape(name_esc, sizeof(name_esc), name);

        /* Format last_seen as relative time */
        int64_t age = onion_directory_age_secs(ls, now);
        char age_str[48];
        if (age < 60) snprintf(age_str, sizeof(age_str), "%llds ago", (long long)age);
        else if (age < 3600) snprintf(age_str, sizeof(age_str), "%lldm ago", (long long)(age/60));
        else if (age < 86400) snprintf(age_str, sizeof(age_str), "%lldh ago", (long long)(age/3600));
        else snprintf(age_str, sizeof(age_str), "%lldd ago", (long long)(age/86400));

        /* "Reached" is OUR contact record, kept distinct from "last seen"
         * (which a mere advertisement refreshes). Never reached is stated,
         * not blanked. */
        char reach_str[64];
        if (lsucc <= 0)
            snprintf(reach_str, sizeof(reach_str), "never (%lld fail)",
                     (long long)fail_n);
        else {
            int64_t sage = now - lsucc;
            if (sage < 0) sage = 0;
            snprintf(reach_str, sizeof(reach_str), "%lldh ago (%lld ok)",
                     (long long)(sage / 3600), (long long)ok_n);
        }

        /* The name is a LABEL for the address, never a substitute: the raw
         * .onion a visitor would actually connect to is always printed
         * beneath it, and it is what the link resolves to. */
        off += (size_t)snprintf(body + off, sizeof(body) - off,
            "<tr%s><td><a href='http://%s/'>%s</a>%s"
            "<div class='desc'>%s</div></td>"
            "<td>%d</td><td>%d</td><td>%s%s</td><td>%s</td><td>%s</td></tr>",
            self ? " class='self'" : "",
            addr_esc,
            name[0] ? name_esc : addr_esc,
            self ? " (this node)" : "",
            addr_esc,
            port, h, age_str,
            fresh == ONION_DIR_STALE ? " (stale)" : "",
            reach_str, ver_esc);
        count++;
    }
    sqlite3_finalize(s);
    sqlite3_close(db);

    off += (size_t)snprintf(body + off, sizeof(body) - off,
        "</table></div>"
        "<p class='muted'>%d nodes in directory (rows unseen for more than "
        "%lld hours are expired)</p>",
        count, (long long)(ONION_DIR_EXPIRE_SECS / 3600));
    off += (size_t)snprintf(body + off, sizeof(body) - off,
        "<p class='muted'><a href='/directory.json'>JSON API</a> | "
        "<a href='/'>Home</a></p>"
        "<footer>Z23 &mdash; one binary, one onion, one stack</footer>"
        "</body></html>");

    return (size_t)snprintf((char *)response, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%s", off, body);
}

/* ── Status endpoint (JSON API) ───────────────────────────── */

static size_t serve_status(uint8_t *response, size_t max)
{
    struct onion_context *ctx = onion_ctx();
    int height = 0, peers = 0;
    query_node_stats(&height, &peers);

    long uptime = 0;
    if (ctx->start_time > 0)
        uptime = (long)(platform_time_wall_time_t() - ctx->start_time);

    /* Query extra stats from SQLite */
    int64_t last_block_time = 0, tx_count = 0;
    if (ctx->datadir) {
        char db_path[1024];
        zcl_node_db_path(db_path, sizeof(db_path), ctx->datadir);
        sqlite3 *db = NULL;
        if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            sqlite3_busy_timeout(db, 5000);
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(db,
                    "SELECT time FROM blocks ORDER BY height DESC LIMIT 1",
                    -1, &s, NULL) == SQLITE_OK && s) {
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                    last_block_time = sqlite3_column_int64(s, 0);
                sqlite3_finalize(s);
            }
            s = NULL;
            if (sqlite3_prepare_v2(db,
                    "SELECT count(*) FROM transactions",
                    -1, &s, NULL) == SQLITE_OK && s) {
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                    tx_count = sqlite3_column_int64(s, 0);
                sqlite3_finalize(s);
            }
            sqlite3_close(db);
        }
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t last_block_age = (last_block_time > 0) ? now - last_block_time : -1;
    bool is_syncing = (height == 0 && uptime < 600) ||
                      (last_block_age > 600 && uptime > 300);

    const char *onion = ctx->address[0] ? ctx->address : NULL;

    char body[1024];
    int blen = snprintf(body, sizeof(body),
        "{\"height\":%d"
        ",\"peers\":%d"
        ",\"version\":\"0.1.0\""
        ",\"uptime\":%ld"
        ",\"syncing\":%s"
        ",\"tor_ready\":%s"
        ",\"onion_service_ready\":%s"
        ",\"last_block_age\":%lld"
        ",\"transactions\":%lld"
        "%s%s%s"
        "}",
        height, peers, uptime,
        is_syncing ? "true" : "false",
        tor_integration_is_ready() ? "true" : "false",
        onion ? "true" : "false",
        (long long)last_block_age,
        (long long)tx_count,
        onion ? ",\"onion\":\"" : "",
        onion ? onion : "",
        onion ? "\"" : "");
    if (blen < 0) blen = 0;

    return (size_t)snprintf((char *)response, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
        "%s", blen, body);
}

/* ── Admission-control responses ──────────────────────────── */

/* Always serveable: a fixed page rendered from a stack buffer, no DB
 * access and no allocation. Every tier routes its over-budget case here,
 * so the node can always say why a request was refused. */
static size_t serve_rate_limited(uint8_t *response, size_t response_max)
{
    return (size_t)snprintf((char *)response, response_max,
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
        "Retry-After: 1\r\n\r\n"
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>429 Too Many Requests</title>"
        "<style>%s</style></head><body>"
        "<div class='veil'>"
        "<h1><span style='color:var(--warn)'>429</span> Too Many Requests</h1>"
        "<p>Too many requests. Please wait a moment and try again.</p>"
        "<p><a href='/'>Home</a> &middot; <a href='/explorer'>Explorer</a></p>"
        "</div></body></html>",
        ONION_PAGE_CSS);
}

/* 402 for an expensive route while the tier is escalated. The page is
 * readable by a human and carries the same challenge as a JSON block a
 * script can read, so the browser front-end and a CLI client solve from
 * one response. */
static size_t serve_puzzle_required(const struct onion_pow_challenge *ch,
                                    uint8_t *response, size_t response_max)
{
    return (size_t)snprintf((char *)response, response_max,
        "HTTP/1.1 402 Payment Required\r\n"
        "Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n"
        "Cache-Control: no-store\r\nRetry-After: 1\r\n\r\n"
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>402 Proof of Work Required</title>"
        "<script type='application/json' id='pow-challenge'>"
        "{\"seed\":\"%s\",\"token\":\"%s\",\"bits\":%d,\"server_time\":%lld}"
        "</script>"
        "<style>%s</style></head><body>"
        "<div class='veil'>"
        "<h1><span style='color:var(--warn)'>402</span> Proof of Work Required</h1>"
        "<p>This node is under sustained load on this class of request and "
        "is temporarily pricing it with a small puzzle. Find a nonce such "
        "that SHA3-256(seed || token || ts || nonce), each of seed and "
        "token 32 raw bytes and each of ts and nonce 8 bytes "
        "little-endian, has %d leading zero bits.</p>"
        "<p>seed <code>%s</code></p>"
        "<p>token <code>%s</code></p>"
        "<p>server time <code>%lld</code></p>"
        "<p>Resubmit with <code>pow_ts</code> (the unix-second timestamp "
        "you hashed) and <code>pow_nonce</code> (decimal) as query "
        "parameters on a GET or form fields on a POST. One solution admits "
        "one request. This clears automatically once load drops.</p>"
        "<p><a href='/'>Home</a></p>"
        "</div></body></html>",
        ch->seed_hex, ch->token_hex, ch->bits, (long long)ch->server_time,
        ONION_PAGE_CSS,
        ch->bits, ch->seed_hex, ch->token_hex, (long long)ch->server_time);
}

/* App-mount handler prototypes — expanded from net/site_routes.def, the
 * single registry. lib/net must not include app/ headers (layering), so
 * the externs are generated inline, exactly like the hand-written
 * declarations they replace. */
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_EXTERN_##flavor(handler)
#include "net/site_routes.def"
#undef SITE_ROUTE

/* ── Main request handler ─────────────────────────────────── */

size_t onion_service_handle_request(const char *method,
                                     const char *path,
                                     const uint8_t *body,
                                     size_t body_len,
                                     uint8_t *response,
                                     size_t response_max)
{
    if (!path) path = "/";

    /* Admission: per-tier budgets, plus a route-bound puzzle on expensive
     * routes while that tier is escalated. Static assets and the landing
     * page draw from a budget the other tiers cannot touch, so a flood on
     * search or order creation can never take the node's front page down. */
    struct onion_pow_challenge challenge = {0};
    enum onion_admit_result admit =
        onion_ratelimit_admit(method, path, body, body_len, &challenge);

    if (admit == ONION_ADMIT_RATE_LIMITED)
        return serve_rate_limited(response, response_max);
    if (admit == ONION_ADMIT_POW_REQUIRED)
        return serve_puzzle_required(&challenge, response, response_max);

    /* JSON status endpoint */
    if (strcmp(path, "/status") == 0)
        return serve_status(response, response_max);

    /* Node directory — JSON API */
    if (strcmp(path, "/directory.json") == 0)
        return serve_directory_json(response, response_max);

    /* Node directory — HTML page */
    if (strcmp(path, "/directory") == 0 || strcmp(path, "/directory/") == 0)
        return serve_directory_html(response, response_max);

    /* Landing page / directory */
    if (strcmp(path, "/") == 0)
        return serve_landing_page(response, response_max);

    /* Search */
    if (strncmp(path, "/search", 7) == 0) {
        const char *q = strstr(path, "q=");
        return serve_search(q ? q + 2 : "", response, response_max);
    }

    /* Explorer — block explorer */
    extern const char *explorer_canonical_shortcut(const char *path);
    if (strncmp(path, "/explorer", 9) == 0 ||
        explorer_canonical_shortcut(path) != NULL) {
        extern size_t explorer_handle_request(const char *, const char *,
            const uint8_t *, size_t, uint8_t *, size_t);
        size_t n = explorer_handle_request(method, path, body, body_len,
                                           response, response_max);
        if (n > 0) return n;
    }

    /* App MVC mounts — expanded from net/site_routes.def in dispatch
     * order (store → names → zcode → metaverse → blog → yardsale), after
     * the core chrome above and before the 404 below. The behavior
     * contracts that used to be comments beside each hand-written route
     * now live beside their registry rows in the def. Each flavor keeps
     * its historical guard shape exactly: STORE and PLAIN prefix-match
     * with no boundary guard; DATADIR and FAILCLOSED require
     * path[N] ∈ {NUL, '/', '?'}; STORE and DATADIR also require the node
     * datadir; FAILCLOSED turns a handler 0 into a 503 carrying the row's
     * fail_body rather than falling through; ONIONCLOSED is FAILCLOSED
     * restricted to this listener (the HTTPS expansion emits nothing). */
#define ZCL_SITE_DISPATCH_STORE(prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        onion_ctx()->datadir) \
        return handler(method, path, body, body_len, response, \
                       response_max, onion_ctx()->datadir);
#define ZCL_SITE_DISPATCH_PLAIN(prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0) \
        return handler(method, path, body, body_len, response, \
                       response_max);
#define ZCL_SITE_DISPATCH_DATADIR(prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?') && \
        onion_ctx()->datadir) \
        return handler(method, path, body, body_len, response, \
                       response_max, onion_ctx()->datadir);
#define ZCL_SITE_DISPATCH_FAILCLOSED(prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?')) { \
        size_t site_n_ = handler(method, path, body, body_len, response, \
                                 response_max); \
        if (site_n_ > 0) \
            return site_n_; \
        /* Fail closed: a signed MVC mount must never degrade into an \
         * unrelated legacy static fallback when proof storage is absent. */ \
        return (size_t)snprintf((char *)response, response_max, \
            "HTTP/1.1 503 Service Unavailable\r\n" \
            "Content-Type: text/plain; charset=utf-8\r\n" \
            "Cache-Control: no-store\r\n" \
            "Connection: close\r\n\r\n" fail_body); \
    }
#define ZCL_SITE_DISPATCH_ONIONCLOSED(prefix, handler, fail_body) \
    ZCL_SITE_DISPATCH_FAILCLOSED(prefix, handler, fail_body)
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_DISPATCH_##flavor(prefix, handler, fail_body)
#include "net/site_routes.def"
#undef SITE_ROUTE
#undef ZCL_SITE_DISPATCH_FAILCLOSED
#undef ZCL_SITE_DISPATCH_ONIONCLOSED
#undef ZCL_SITE_DISPATCH_DATADIR
#undef ZCL_SITE_DISPATCH_PLAIN
#undef ZCL_SITE_DISPATCH_STORE

    /* 404 */
    return (size_t)snprintf((char *)response, response_max,
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>404 Not Found</title>"
        "<style>%s</style></head><body>"
        "<div class='veil'>"
        "<h1><span style='color:var(--bad)'>404</span> Not Found</h1>"
        "<p>The page you requested does not exist.</p>"
        "<p><a href='/'>Home</a> &middot; <a href='/explorer'>Explorer</a> &middot; "
        "<a href='/store'>Store</a> &middot; <a href='/blog'>Blog</a></p>"
        "</div></body></html>",
        ONION_PAGE_CSS);
}

/* ── Lifecycle ────────────────────────────────────────────── */

const char *onion_service_start(const char *datadir)
{
    struct onion_context *ctx = onion_ctx();
    if (ctx->datadir && ctx->start_time != 0)
        return ctx->address[0] ? ctx->address : NULL;
    ctx->datadir = datadir;
    ctx->start_time = platform_time_wall_time_t();

    /* Seed the peer directory, then hand it to the supervisor. The boot
     * populate is now the FIRST round, not the only one: from here a
     * refresh runs every ONION_DIR_REFRESH_SECS so the list this node
     * serves keeps up with reality (onion_directory.c). */
    if (datadir) {
        /* The boot round seeds the table from the discovery sources,
         * registers self, and ages out rows nothing has seen since the
         * last run — before this, a row written once at boot lived
         * forever. From here the supervised refresh child keeps sweeping
         * on its own cadence. */
        onion_directory_boot_round();
        onion_service_directory_register_refresh();
    }

    return ctx->address[0] ? ctx->address : NULL;
}

void onion_service_stop(void)
{
    /* Retire the refresh child before dropping the datadir, so it can
     * never observe (and report) a directory that is unopenable purely
     * because we just closed the service. */
    onion_service_directory_unregister_refresh();
    onion_ctx()->datadir = NULL;
}

const char *onion_service_get_address(void)
{
    return onion_ctx()->address[0] ? onion_ctx()->address : NULL;
}

const char *onion_service_datadir(void)
{
    return onion_ctx()->datadir;
}

int onion_service_discover_peers(struct onion_peer *out, size_t max)
{
    return onion_discover_peers(out, max);
}

void onion_service_set_address(const char *address)
{
    struct onion_context *ctx = onion_ctx();
    if (address) {
        snprintf(ctx->address, sizeof(ctx->address), "%s", address);

        /* Register ourselves in the peer directory */
        if (ctx->datadir)
            onion_directory_register_self();
    } else {
        ctx->address[0] = '\0';
    }
}
