/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public wiki site controller — read-only HTML and JSON pages over the
 * signed wiki rows this node holds. See controllers/wiki_site_controller.h
 * for the route list and the bounds.
 *
 * The rows come from the same fleet_board_posts store the `fleet wiki *`
 * commands read, through the same model calls, so the site shows what the
 * CLI shows: db_fleet_board_wiki_query for the index (bounded to
 * FLEET_BOARD_LIST_MAX pages and as many revision verifications) and
 * db_fleet_board_wiki_read for one page. Both re-verify id and signature
 * before a row is handed back. Every byte of page text passes through
 * html_escape before it reaches HTML, and JSON goes through the json
 * module's own string escaping. */

#include "controllers/wiki_site_controller.h"

#include "base/safe_alloc.h"
#include "base/utc_tm.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "session/fleet_board_proto.h"
#include "session/fleet_wiki_entry.h"
#include "util/log_macros.h"
#include "util/template.h" /* html_escape */
#include "views/site_css.h"
#include "views/site_layout.h"
#include "zutf8/zutf8.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define WS_LOG "wiki.site"
#define WS_SCHEMA_PAGE "zcl.public_wiki_page.v1"
#define WS_SCHEMA_INDEX "zcl.public_wiki_index.v1"
/* Longest escaped expansion of one source byte ("&quot;"). */
#define WS_ESC_FACTOR 6u
#define WS_ROW_OVERHEAD 512u
#define WS_PAGE_OVERHEAD 8192u
#define WS_LEAD_MAX 160u

/* ── route parsing ────────────────────────────────────────────────── */

enum ws_route { WS_NOT_WIKI, WS_BAD, WS_INDEX, WS_PAGE };

struct ws_request {
    enum ws_route route;
    const char *base;                    /* mount prefix links use */
    bool json;
    bool txt;                            /* "<slug>.txt": plain text */
    char slug[FLEET_BOARD_SLUG_MAX + 1];
};

static const char *ws_mount_rest(const char *route, const char **base)
{
    if (strncmp(route, "/board/wiki", 11) == 0) {
        *base = "/board/wiki";
        return route + 11;
    }
    /* The root "/wiki" prefix is mounted by the wiki row in core's
     * site_routes.def; "/board/wiki" reaches here through the board
     * handler. The site boundary rule does not route "/wiki.json", so the
     * index JSON lives at "/board/wiki.json". */
    if (strncmp(route, "/wiki", 5) == 0) {
        *base = "/wiki";
        return route + 5;
    }
    return NULL;
}

/* "<slug>", "<slug>.json" or "<slug>.txt" with no further segment. The
 * slug alphabet has
 * no '.', so the suffix is unambiguous. */
static bool ws_parse_slug(const char *seg, struct ws_request *req)
{
    size_t len = strlen(seg);
    if (len > 5 && strcmp(seg + len - 5, ".json") == 0) {
        req->json = true;
        len -= 5;
    } else if (len > 4 && strcmp(seg + len - 4, ".txt") == 0) {
        req->txt = true;
        len -= 4;
    }
    if (len == 0 || len > FLEET_BOARD_SLUG_MAX)
        return false;
    memcpy(req->slug, seg, len);
    req->slug[len] = '\0';
    return fleet_board_slug_valid(req->slug);
}

static void ws_parse(const char *route, struct ws_request *req)
{
    memset(req, 0, sizeof(*req));
    const char *rest = ws_mount_rest(route, &req->base);
    if (!rest || (rest[0] != '\0' && rest[0] != '/' && rest[0] != '.')) {
        req->route = WS_NOT_WIKI;
        return;
    }
    req->route = WS_BAD;
    if (rest[0] == '\0' || strcmp(rest, "/") == 0) {
        req->route = WS_INDEX;
    } else if (strcmp(rest, ".json") == 0) {
        req->route = WS_INDEX;
        req->json = true;
    } else if (rest[0] == '/' && !strchr(rest + 1, '/') &&
               ws_parse_slug(rest + 1, req)) {
        req->route = WS_PAGE;
    }
}

/* ── response framing ─────────────────────────────────────────────── */

static size_t ws_respond(const char *status, const char *ctype,
                         const char *body, size_t body_len, bool head_only,
                         uint8_t *resp, size_t max)
{
    int n = snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: default-src 'none'; style-src "
        "'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'none'\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, ctype, body_len);
    if (n < 0 || (size_t)n >= max) {
        LOG_WARN(WS_LOG, "wiki response header exceeds capacity");
        return 0;
    }
    if (head_only)
        return (size_t)n;
    if (body_len > max - (size_t)n) {
        LOG_WARN(WS_LOG, "wiki response body exceeds capacity");
        return 0;
    }
    memcpy(resp + n, body, body_len);
    return (size_t)n + body_len;
}

static size_t ws_error(const char *status, const char *what, bool json,
                       bool head_only, uint8_t *resp, size_t max)
{
    char body[512];
    int n;
    if (json)
        n = snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", what);
    else
        n = snprintf(body, sizeof(body),
            "<!doctype html><meta charset='utf-8'><title>%s</title>"
            "<h1>%s</h1>\n", status, status);
    if (n < 0 || (size_t)n >= sizeof(body))
        return 0;
    return ws_respond(status,
                      json ? "application/json" : "text/html; charset=utf-8",
                      body, (size_t)n, head_only, resp, max);
}

/* Same errors for the .txt form, as plain text. */
static size_t ws_error_txt(const char *status, bool head_only, uint8_t *resp,
                           size_t max)
{
    char body[128];
    int n = snprintf(body, sizeof(body), "%s\n", status);
    if (n < 0 || (size_t)n >= sizeof(body))
        return 0;
    return ws_respond(status, "text/plain; charset=utf-8", body, (size_t)n,
                      head_only, resp, max);
}

static size_t ws_page_error(const struct ws_request *rq, const char *status,
                            const char *what, bool head_only, uint8_t *resp,
                            size_t max)
{
    return rq->txt ? ws_error_txt(status, head_only, resp, max)
                   : ws_error(status, what, rq->json, head_only, resp, max);
}

/* ── small helpers ────────────────────────────────────────────────── */

/* Escape `s` into buf at off, in bounded chunks so no source length can
 * overflow the stack scratch. html_escape works byte by byte, so a chunk
 * boundary inside a multibyte sequence changes nothing. */
static size_t ws_put_esc(char *buf, size_t max, size_t off, const char *s)
{
    char chunk[257];
    char esc[257 * WS_ESC_FACTOR];
    while (s && *s) {
        size_t take = strnlen(s, sizeof(chunk) - 1);
        memcpy(chunk, s, take);
        chunk[take] = '\0';
        html_escape(esc, sizeof(esc), chunk);
        SITE_APPEND(off, buf, max, "%s", esc);
        s += take;
    }
    return off;
}

static void ws_iso(uint64_t ts, char out[24])
{
    struct tm tm;
    time_t t = (time_t)ts;
    if (ts > (uint64_t)INT32_MAX * 64u || !zcl_utc_tm(t, &tm)) {
        out[0] = '\0';
        return;
    }
    (void)snprintf(out, 24, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                   tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                   tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* Copy src[0..len) to dst as well-formed UTF-8: every byte that is not part
 * of a valid sequence (stray, overlong, surrogate, out of range, truncated)
 * becomes U+FFFD, so one bad byte grows to three. Output stops before a
 * character that would not fit in cap-1 bytes, so dst is always NUL
 * terminated and never ends inside a sequence. Page text is untrusted bytes:
 * the json module passes bytes >= 0x80 through raw, so this runs before any
 * page-derived string reaches either the JSON or the HTML form. */
static size_t ws_clean(char *dst, size_t cap, const char *src, size_t len)
{
    static const char replacement[] = "\xEF\xBF\xBD";
    size_t w = 0;
    size_t i = 0;
    while (i < len) {
        uint32_t cp = 0;
        size_t used = 0;
        bool ok = zutf8_decode_n(src + i, len - i, &cp, &used) == ZUTF8_OK &&
                  used > 0;
        size_t take = ok ? used : 1;
        size_t out_len = ok ? used : sizeof(replacement) - 1;
        if (w + out_len >= cap)
            break;
        memcpy(dst + w, ok ? src + i : replacement, out_len);
        w += out_len;
        i += take;
    }
    dst[w] = '\0';
    return w;
}

/* First line of plain text, at most WS_LEAD_MAX source bytes, sanitised. */
static void ws_first_line(char *dst, size_t cap, const char *text)
{
    size_t len = strcspn(text, "\r\n");
    if (len > WS_LEAD_MAX)
        len = WS_LEAD_MAX;
    (void)ws_clean(dst, cap, text, len);
}

static bool ws_in_scope(const struct db_fleet_board_post *row)
{
    return row->post.scope != FLEET_BOARD_SCOPE_FLEET;
}

static const char *ws_str(const struct json_value *entry, const char *key)
{
    const char *s = json_get_str(json_get(entry, key));
    return s ? s : "";
}

/* ── index ────────────────────────────────────────────────────────── */

struct ws_row {
    char slug[FLEET_BOARD_SLUG_MAX + 1];
    char title[FLEET_BOARD_TITLE_MAX + 1];
    char summary[FLEET_WIKI_ENTRY_SUMMARY_MAX + 1];
    uint64_t created_at;
    uint8_t id[FLEET_BOARD_ID_BYTES];
    uint8_t host[FLEET_BOARD_PUBKEY_BYTES];
    bool entry;
};

struct ws_collect {
    struct ws_row *rows;
    size_t n;
};

/* Fill title and summary from the page body: the entry's topic and summary
 * for a structured page, the signed title and the first line otherwise. */
static bool ws_describe(struct ws_row *r, const struct db_fleet_board_post *p)
{
    struct json_value entry;
    json_init(&entry);
    enum fleet_wiki_parse_status st = fleet_wiki_entry_parse_checked(
        p->post.text, p->post.text_len, &entry, NULL);
    if (st == FLEET_WIKI_PARSE_ALLOC_FAILED)
        return false;
    if (st == FLEET_WIKI_PARSE_ENTRY) {
        r->entry = true;
        const char *topic = ws_str(&entry, "topic");
        const char *summary = ws_str(&entry, "summary");
        (void)ws_clean(r->title, sizeof(r->title), topic, strlen(topic));
        (void)ws_clean(r->summary, sizeof(r->summary), summary,
                       strlen(summary));
        json_free(&entry);
        return true;
    }
    (void)ws_clean(r->title, sizeof(r->title), p->post.title,
                   strlen(p->post.title));
    ws_first_line(r->summary, sizeof(r->summary), p->post.text);
    return true;
}

static enum fleet_wiki_visit_result ws_visit(
    void *context, const struct db_fleet_board_post *row)
{
    struct ws_collect *c = context;
    if (!ws_in_scope(row) || c->n >= FLEET_BOARD_LIST_MAX)
        return FLEET_WIKI_VISIT_CONTINUE;
    struct ws_row *r = &c->rows[c->n];
    memset(r, 0, sizeof(*r));
    if (!ws_describe(r, row))
        return FLEET_WIKI_VISIT_FAILED;
    (void)snprintf(r->slug, sizeof(r->slug), "%s", row->post.slug);
    r->created_at = row->post.created_at;
    memcpy(r->id, row->post.id, sizeof(r->id));
    memcpy(r->host, row->post.host_pubkey, sizeof(r->host));
    c->n++;
    return FLEET_WIKI_VISIT_CONTINUE;
}

/* Stops at the first shown page: used only to learn whether any exist. */
static enum fleet_wiki_visit_result ws_probe(
    void *context, const struct db_fleet_board_post *row)
{
    if (!ws_in_scope(row))
        return FLEET_WIKI_VISIT_CONTINUE;
    *(bool *)context = true;
    return FLEET_WIKI_VISIT_PAGE;
}

/* Rows are slug-ordered by the query. A verify-budget stop is truncated. A
 * stop at the 256-slug page cap is truncated only when one more probe past
 * the last examined slug finds a page, so exactly 256 pages are complete. */
static bool ws_load_index(struct node_db *ndb, struct ws_collect *c,
                          bool *truncated)
{
    struct fleet_wiki_query_progress progress;
    if (!db_fleet_board_wiki_query(ndb, "", ws_visit, c, &progress))
        LOG_FAIL(WS_LOG, "wiki index query failed status=%d",
                 (int)progress.status);
    *truncated = progress.status == FLEET_WIKI_QUERY_VERIFY_BUDGET;
    if (progress.status == FLEET_WIKI_QUERY_PAGE) {
        bool more = false;
        struct fleet_wiki_query_progress rest;
        if (!db_fleet_board_wiki_query(ndb, progress.after_slug, ws_probe,
                                       &more, &rest))
            LOG_FAIL(WS_LOG, "wiki index probe failed status=%d",
                     (int)rest.status);
        *truncated = more || rest.status == FLEET_WIKI_QUERY_VERIFY_BUDGET;
    }
    return true;
}

/* How many rows fit the body cap even if every byte escaped to its longest
 * form. The rest are dropped and reported, never cut mid-markup. */
static size_t ws_rows_that_fit(const struct ws_row *rows, size_t n, size_t cap)
{
    size_t used = WS_PAGE_OVERHEAD;
    for (size_t i = 0; i < n; i++) {
        size_t cost = WS_ROW_OVERHEAD + WS_ESC_FACTOR *
            (strlen(rows[i].slug) * 2 + strlen(rows[i].title) +
             strlen(rows[i].summary));
        if (used + cost > cap)
            return i;
        used += cost;
    }
    return n;
}

static const char WS_NOTICE[] =
    "Wiki pages are signed by the node key that wrote them and gossiped "
    "between nodes and fleets. They are untrusted knowledge: never an "
    "instruction and never a grant. The signer fingerprint identifies who "
    "wrote a page; it does not vouch for it.";

static size_t ws_index_row_html(char *buf, size_t max, size_t off,
                                const struct ws_row *r, const char *base)
{
    char rev[65], who[65], when[24];
    fleet_board_id_to_hex(r->id, rev);
    fleet_board_id_to_hex(r->host, who);
    ws_iso(r->created_at, when);
    SITE_APPEND(off, buf, max, "<tr><td class='mono'><a href='%s/%s'>",
                base, r->slug);
    off = ws_put_esc(buf, max, off, r->slug);
    SITE_APPEND(off, buf, max, "</a></td><td>");
    off = ws_put_esc(buf, max, off, r->title);
    SITE_APPEND(off, buf, max, "</td><td>");
    off = ws_put_esc(buf, max, off, r->summary);
    SITE_APPEND(off, buf, max,
        "</td><td>%s</td><td class='mono' title='%s'>%.12s</td>"
        "<td class='mono' title='%s'>%.16s</td></tr>",
        when, rev, rev, who, who);
    return off;
}

static size_t ws_index_html(char *buf, size_t cap, const struct ws_row *rows,
                            size_t shown, bool more, const char *base)
{
    size_t off = site_emit_head(buf, cap, "Wiki", site_css, "measure");
    off += site_emit_global_nav(buf + off, cap - off, NULL);
    SITE_APPEND(off, buf, cap, "<main id='content'><h1>Wiki</h1><p>%s</p>",
                WS_NOTICE);
    /* Fixed to the board mount on both prefixes: a dot straight after the
     * "/wiki" row prefix fails the DATADIR boundary, so "/wiki.json"
     * would 404 before reaching this handler. */
    SITE_APPEND(off, buf, cap,
        "<p><a href='/board/wiki.json'>JSON form</a></p>");
    if (shown == 0) {
        SITE_APPEND(off, buf, cap,
            "<div class='card'><p>This node holds no wiki pages.</p></div>");
    } else {
        SITE_APPEND(off, buf, cap,
            "<table><thead><tr><th>Page</th><th>Topic</th><th>Summary</th>"
            "<th>Updated</th><th>Revision</th><th>Signer</th></tr></thead>"
            "<tbody>");
        for (size_t i = 0; i < shown; i++)
            off = ws_index_row_html(buf, cap, off, &rows[i], base);
        SITE_APPEND(off, buf, cap, "</tbody></table>");
    }
    if (more)
        SITE_APPEND(off, buf, cap,
            "<p class='meta'>The list is bounded; more pages exist than "
            "are shown here.</p>");
    SITE_APPEND(off, buf, cap, "</main>");
    off += site_emit_footer(buf + off, cap - off, NULL);
    return off;
}

static bool ws_push_row_json(struct json_value *arr, const struct ws_row *r)
{
    char rev[65], who[65], when[24];
    fleet_board_id_to_hex(r->id, rev);
    fleet_board_id_to_hex(r->host, who);
    ws_iso(r->created_at, when);
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_str(&o, "slug", r->slug) &&
              json_push_kv_str(&o, "title", r->title) &&
              json_push_kv_str(&o, "summary", r->summary) &&
              json_push_kv_str(&o, "form", r->entry ? "entry" : "plain") &&
              json_push_kv_int(&o, "updated_at", (int64_t)r->created_at) &&
              json_push_kv_str(&o, "updated", when) &&
              json_push_kv_str(&o, "revision_id", rev) &&
              json_push_kv_str(&o, "signer", who) &&
              json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

static bool ws_index_json(struct json_value *doc, const struct ws_row *rows,
                          size_t shown, bool more)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    json_set_object(doc);
    bool ok = true;
    for (size_t i = 0; ok && i < shown; i++)
        ok = ws_push_row_json(&arr, &rows[i]);
    ok = ok && json_push_kv_str(doc, "schema", WS_SCHEMA_INDEX) &&
         json_push_kv_int(doc, "count", (int64_t)shown) &&
         json_push_kv_bool(doc, "truncated", more) &&
         json_push_kv(doc, "pages", &arr);
    json_free(&arr);
    return ok;
}

/* Serialise `doc` into a heap body of at most cap bytes. NULL on failure. */
static char *ws_json_body(const struct json_value *doc, size_t cap,
                          size_t *len_out)
{
    size_t need = json_write(doc, NULL, 0);
    if (need + 2 > cap)
        LOG_NULL(WS_LOG, "wiki JSON body %zu exceeds cap %zu", need, cap);
    char *out = zcl_malloc(need + 2, "wiki site json body");
    if (!out)
        LOG_NULL(WS_LOG, "wiki JSON body allocation failed");
    size_t wrote = json_write(doc, out, need + 1);
    out[wrote] = '\n';
    out[wrote + 1] = '\0';
    *len_out = wrote + 1;
    return out;
}

/* One index costs up to FLEET_BOARD_LIST_MAX signature checks, and the
 * request is unauthenticated, so the rendered index is kept for
 * WS_CACHE_TTL_MS in a process-local cache: one slot per mount prefix, both
 * forms, bounded to 4 bodies of at most WIKI_SITE_BODY_MAX bytes. The mutex
 * is held across a rebuild on purpose: a burst of requests then verifies
 * once, not once per thread. No thread is added; the lock is leaf-level and
 * never held while a response is written to a socket (the handler only
 * copies into the caller's buffer). */
#define WS_CACHE_TTL_MS 30000
#define WS_CACHE_SLOTS 2

struct ws_cache_slot {
    int64_t built_ms;
    char *html;
    size_t html_len;
    char *json;
    size_t json_len;
};

static pthread_mutex_t g_ws_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ws_cache_slot g_ws_cache[WS_CACHE_SLOTS];
static unsigned g_ws_cache_builds;

static struct ws_cache_slot *ws_cache_slot(const struct ws_request *rq)
{
    return &g_ws_cache[strcmp(rq->base, "/wiki") == 0 ? 0 : 1];
}

static void ws_cache_drop(struct ws_cache_slot *s)
{
    free(s->html);
    free(s->json);
    memset(s, 0, sizeof(*s));
}

static bool ws_cache_fresh(const struct ws_cache_slot *s)
{
    int64_t age = platform_time_monotonic_ms() - s->built_ms;
    return s->html && s->json && age >= 0 && age < WS_CACHE_TTL_MS;
}

/* Render both forms from one verified walk. Caller holds the lock. */
static bool ws_cache_build(struct node_db *ndb, const struct ws_request *rq,
                           struct ws_cache_slot *slot)
{
    struct ws_collect c = {
        .rows = zcl_calloc(FLEET_BOARD_LIST_MAX, sizeof(struct ws_row),
                           "wiki site index rows"),
    };
    bool more = false;
    if (!c.rows || !ws_load_index(ndb, &c, &more)) {
        free(c.rows);
        return false;
    }
    size_t shown = ws_rows_that_fit(c.rows, c.n, WIKI_SITE_BODY_MAX);
    more = more || shown < c.n;
    char *scratch = zcl_malloc(WIKI_SITE_BODY_MAX, "wiki site index scratch");
    char *html = NULL;
    size_t html_len = 0;
    if (scratch) {
        html_len = ws_index_html(scratch, WIKI_SITE_BODY_MAX, c.rows, shown,
                                 more, rq->base);
        if (html_len + 1 < WIKI_SITE_BODY_MAX)
            html = zcl_malloc(html_len + 1, "wiki site index html");
        if (html)
            memcpy(html, scratch, html_len + 1);
    }
    free(scratch);
    struct json_value doc;
    json_init(&doc);
    size_t json_len = 0;
    char *json = ws_index_json(&doc, c.rows, shown, more)
        ? ws_json_body(&doc, WIKI_SITE_BODY_MAX, &json_len) : NULL;
    json_free(&doc);
    free(c.rows);
    if (!html || !json) {
        free(html);
        free(json);
        return false;
    }
    ws_cache_drop(slot);
    *slot = (struct ws_cache_slot){
        .built_ms = platform_time_monotonic_ms(),
        .html = html, .html_len = html_len,
        .json = json, .json_len = json_len,
    };
    g_ws_cache_builds++;
    return true;
}

static size_t ws_serve_index(struct node_db *ndb, const struct ws_request *rq,
                             bool head_only, uint8_t *resp, size_t max)
{
    struct ws_cache_slot *slot = ws_cache_slot(rq);
    size_t out = 0;
    pthread_mutex_lock(&g_ws_cache_lock);
    if (ws_cache_fresh(slot) || ws_cache_build(ndb, rq, slot))
        out = ws_respond("200 OK",
                         rq->json ? "application/json"
                                  : "text/html; charset=utf-8",
                         rq->json ? slot->json : slot->html,
                         rq->json ? slot->json_len : slot->html_len,
                         head_only, resp, max);
    pthread_mutex_unlock(&g_ws_cache_lock);
    if (out == 0)
        out = ws_error("503 Service Unavailable", "wiki_unavailable",
                       rq->json, head_only, resp, max);
    return out;
}

#ifdef ZCL_TESTING
void wiki_site_cache_reset_for_testing(void)
{
    pthread_mutex_lock(&g_ws_cache_lock);
    for (size_t i = 0; i < WS_CACHE_SLOTS; i++)
        ws_cache_drop(&g_ws_cache[i]);
    g_ws_cache_builds = 0;
    pthread_mutex_unlock(&g_ws_cache_lock);
}

unsigned wiki_site_index_builds_for_testing(void)
{
    pthread_mutex_lock(&g_ws_cache_lock);
    unsigned n = g_ws_cache_builds;
    pthread_mutex_unlock(&g_ws_cache_lock);
    return n;
}
#endif

/* ── one page ─────────────────────────────────────────────────────── */

static size_t ws_entry_html(char *buf, size_t cap, size_t off,
                            const struct json_value *entry)
{
    SITE_APPEND(off, buf, cap, "<h2>Summary</h2><p>");
    off = ws_put_esc(buf, cap, off, ws_str(entry, "summary"));
    SITE_APPEND(off, buf, cap, "</p>");
    const struct json_value *applies = json_get(entry, "applies_to");
    if (applies && json_size(applies) > 0) {
        SITE_APPEND(off, buf, cap, "<h2>Applies to</h2><ul>");
        for (size_t i = 0; i < json_size(applies); i++) {
            SITE_APPEND(off, buf, cap, "<li>");
            off = ws_put_esc(buf, cap, off, json_get_str(json_at(applies, i)));
            SITE_APPEND(off, buf, cap, "</li>");
        }
        SITE_APPEND(off, buf, cap, "</ul>");
    }
    const struct json_value *lessons = json_get(entry, "lessons");
    SITE_APPEND(off, buf, cap, "<h2>Lessons</h2><ol>");
    for (size_t i = 0; lessons && i < json_size(lessons); i++) {
        const struct json_value *l = json_at(lessons, i);
        SITE_APPEND(off, buf, cap, "<li><strong>");
        off = ws_put_esc(buf, cap, off, ws_str(l, "rule"));
        SITE_APPEND(off, buf, cap, "</strong>");
        if (ws_str(l, "why")[0]) {
            SITE_APPEND(off, buf, cap, "<br>Why: ");
            off = ws_put_esc(buf, cap, off, ws_str(l, "why"));
        }
        if (ws_str(l, "evidence")[0]) {
            SITE_APPEND(off, buf, cap, "<br>Evidence: ");
            off = ws_put_esc(buf, cap, off, ws_str(l, "evidence"));
        }
        SITE_APPEND(off, buf, cap, "</li>");
    }
    SITE_APPEND(off, buf, cap, "</ol>");
    return off;
}

/* One page, sanitised once: title and text are well-formed UTF-8 copies of
 * the signed bytes, so both forms render the same string. */
struct ws_page {
    const struct db_fleet_board_post *post;
    const struct json_value *entry;      /* NULL for a plain page */
    char title[FLEET_BOARD_TITLE_MAX * 3 + 1];
    char *text;                          /* sanitised plain text */
    bool newer_unverified;
};

static size_t ws_page_html(char *buf, size_t cap, const struct ws_page *pg,
                           const char *base)
{
    const struct db_fleet_board_post *p = pg->post;
    char rev[65], who[65], when[24];
    fleet_board_id_to_hex(p->post.id, rev);
    fleet_board_id_to_hex(p->post.host_pubkey, who);
    ws_iso(p->post.created_at, when);
    const char *title = pg->entry ? ws_str(pg->entry, "topic") : pg->title;
    size_t off = site_emit_head(buf, cap, "Wiki page", site_css, "measure");
    off += site_emit_global_nav(buf + off, cap - off, NULL);
    SITE_APPEND(off, buf, cap, "<main id='content'><h1>");
    off = ws_put_esc(buf, cap, off, title[0] ? title : p->post.slug);
    SITE_APPEND(off, buf, cap, "</h1><p>%s</p>", WS_NOTICE);
    if (pg->newer_unverified)
        SITE_APPEND(off, buf, cap,
            "<p class='meta'>A newer revision of this page is held here but "
            "failed verification; this is the newest revision that "
            "verifies.</p>");
    SITE_APPEND(off, buf, cap,
        "<div class='kv'><b>page</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>revision</b><span class='val mono' "
        "title='%s'>%.12s</span></div>"
        "<div class='kv'><b>signer</b><span class='val mono' "
        "title='%s'>%.16s</span></div>"
        "<div class='kv'><b>updated</b><span class='val'>%s</span></div>",
        p->post.slug, rev, rev, who, who, when);
    if (pg->entry) {
        off = ws_entry_html(buf, cap, off, pg->entry);
    } else {
        SITE_APPEND(off, buf, cap, "<pre>");
        off = ws_put_esc(buf, cap, off, pg->text);
        SITE_APPEND(off, buf, cap, "</pre>");
    }
    SITE_APPEND(off, buf, cap,
        "<p><a href='%s'>&larr; all wiki pages</a> &middot; "
        "<a href='%s/%s.json'>JSON form</a></p></main>",
        base, base, p->post.slug);
    off += site_emit_footer(buf + off, cap - off, NULL);
    return off;
}

static bool ws_page_json(struct json_value *doc, const struct ws_page *pg)
{
    const struct db_fleet_board_post *p = pg->post;
    char rev[65], who[65], when[24];
    fleet_board_id_to_hex(p->post.id, rev);
    fleet_board_id_to_hex(p->post.host_pubkey, who);
    ws_iso(p->post.created_at, when);
    json_set_object(doc);
    bool ok = json_push_kv_str(doc, "schema", WS_SCHEMA_PAGE) &&
              json_push_kv_str(doc, "slug", p->post.slug) &&
              json_push_kv_str(doc, "title", pg->title) &&
              json_push_kv_bool(doc, "verified", true) &&
              json_push_kv_str(doc, "revision_id", rev) &&
              json_push_kv_str(doc, "signer", who) &&
              json_push_kv_int(doc, "updated_at", (int64_t)p->post.created_at) &&
              json_push_kv_str(doc, "updated", when) &&
              json_push_kv_str(doc, "form", pg->entry ? "entry" : "plain");
    if (ok && pg->newer_unverified)
        ok = json_push_kv_bool(doc, "newer_revision_unverified", true);
    if (ok && pg->entry)
        ok = json_push_kv(doc, "entry", pg->entry);
    else if (ok)
        ok = json_push_kv_str(doc, "text", pg->text);
    return ok;
}

/* Render the page in the requested form. The caller frees the result. */
static char *ws_page_body(const struct ws_page *pg, bool json,
                          const char *base, size_t cap, size_t *len)
{
    if (json) {
        struct json_value doc;
        json_init(&doc);
        char *out = ws_page_json(&doc, pg) ? ws_json_body(&doc, cap, len)
                                           : NULL;
        json_free(&doc);
        return out;
    }
    char *out = zcl_malloc(cap, "wiki site page body");
    if (!out)
        LOG_NULL(WS_LOG, "wiki page body allocation failed");
    *len = ws_page_html(out, cap, pg, base);
    if (*len + 1 >= cap) {
        free(out);
        LOG_NULL(WS_LOG, "wiki page body exceeds cap %zu", cap);
    }
    return out;
}

static size_t ws_serve_page(struct node_db *ndb, const struct ws_request *rq,
                            bool head_only, size_t cap, uint8_t *resp,
                            size_t max)
{
    struct db_fleet_board_post *row = zcl_calloc(
        1, sizeof(*row), "wiki site page row");
    struct ws_page pg = {.post = row};
    if (!row)
        return ws_page_error(rq, "503 Service Unavailable",
                             "wiki_unavailable", head_only, resp, max);
    /* An unknown slug, or one whose revisions all fail verification or sit
     * in the fleet-private scope, is the same 404: nothing is shown. */
    if (!db_fleet_board_wiki_read_checked(ndb, rq->slug, row,
                                          &pg.newer_unverified) ||
        !ws_in_scope(row)) {
        free(row);
        return ws_page_error(rq, "404 Not Found", "not_found", head_only,
                             resp, max);
    }
    struct json_value entry;
    json_init(&entry);
    enum fleet_wiki_parse_status st = fleet_wiki_entry_parse_checked(
        row->post.text, row->post.text_len, &entry, NULL);
    pg.entry = st == FLEET_WIKI_PARSE_ENTRY ? &entry : NULL;
    (void)ws_clean(pg.title, sizeof(pg.title), row->post.title,
                   strlen(row->post.title));
    size_t tlen = strlen(row->post.text);
    pg.text = zcl_malloc(tlen * 3 + 1, "wiki site page text");
    char *body = NULL;
    size_t len = 0;
    if (pg.text && st != FLEET_WIKI_PARSE_ALLOC_FAILED) {
        (void)ws_clean(pg.text, tlen * 3 + 1, row->post.text, tlen);
        if (rq->txt) {
            len = strlen(pg.text);
            body = zcl_malloc(len + 1, "wiki site txt body");
            if (body)
                memcpy(body, pg.text, len + 1);
        } else {
            body = ws_page_body(&pg, rq->json, rq->base, cap, &len);
        }
    }
    free(pg.text);
    json_free(&entry);
    free(row);
    if (!body)
        return ws_page_error(rq, "503 Service Unavailable",
                             "wiki_unavailable", head_only, resp, max);
    size_t out = ws_respond("200 OK",
                            rq->json ? "application/json"
                            : rq->txt ? "text/plain; charset=utf-8"
                                      : "text/html; charset=utf-8",
                            body, len, head_only, resp, max);
    free(body);
    return out;
}

/* ── router ───────────────────────────────────────────────────────── */

size_t wiki_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max,
                                const char *datadir)
{
    (void)body;
    (void)body_len;
    (void)datadir; /* the wiki lives in the node db, not in files */
    if (!method || !path || !response || response_max < 4096)
        return 0;
    char route[256];
    size_t rlen = strcspn(path, "?");
    if (rlen >= sizeof(route))
        return 0;
    memcpy(route, path, rlen);
    route[rlen] = '\0';
    struct ws_request rq;
    ws_parse(route, &rq);
    if (rq.route == WS_NOT_WIKI)
        return 0;
    bool head_only = strcmp(method, "HEAD") == 0;
    if (!head_only && strcmp(method, "GET") != 0)
        return ws_error("405 Method Not Allowed", "method_not_allowed",
                        false, false, response, response_max);
    /* The slug is validated by now: a bad one never reaches the database. */
    if (rq.route == WS_BAD)
        return ws_error("404 Not Found", "not_found", false, head_only,
                        response, response_max);
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open)
        return ws_error("503 Service Unavailable", "wiki_unavailable",
                        rq.json, head_only, response, response_max);
    size_t cap = response_max - 1024;
    if (cap > WIKI_SITE_BODY_MAX)
        cap = WIKI_SITE_BODY_MAX;
    return rq.route == WS_INDEX
        ? ws_serve_index(ndb, &rq, head_only, response, response_max)
        : ws_serve_page(ndb, &rq, head_only, cap, response, response_max);
}
