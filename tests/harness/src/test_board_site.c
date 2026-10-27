/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_board_site — the read-only /board room pages gate
 * (contexts/messaging/controllers/src/board_site_controller.c).
 *
 * Coverage:
 *   1. Route coverage: /board, /board/room/<name>, an empty room, an
 *      invalid room name, and an unknown route all render complete HTTP
 *      responses from one fixture store.
 *   2. SCOPE DISCIPLINE (the adversarial one): the store holds a
 *      fleet-scoped post, and no page — not the index, not any room — ever
 *      renders its text or admits the scope exists.
 *   3. Default-room continuity: a legacy pre-scope post and a v2 post that
 *      names "general" appear together on the general room page.
 *   4. HTML escaping: hostile agent and text render escaped, never as raw
 *      markup.
 *   5. Store agreement: the room page shows exactly what
 *      db_fleet_board_list returns for that room filter — no website
 *      database, no second board truth.
 *   6. No node database is a named 503, not a fall-through.
 *
 * Fixtures run fully in-process on :memory: node databases; the handler is
 * called directly, the same shape as the fleet_board RPC tests. */

#include "test/test_core.h"

#include "util/fleet_role_check.h"

#include "controllers/board_site_controller.h"
#include "controllers/wiki_site_controller.h"
#include "net/site_routes.h"

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"

#include <string.h>

#define BS_RESP_CAP 131072
static uint8_t g_resp[BS_RESP_CAP];

static void bs_identity(uint8_t which, uint8_t seed[32], uint8_t pk[32])
{
    uint8_t sk[32];
    memset(seed, 0, 32);
    seed[0] = which;
    seed[31] = (uint8_t)(0xb0 + which);
    ed25519_keypair(pk, sk, seed);
    memcpy(seed, sk, 32);
}

static void bs_compose(struct fleet_board_post *post, uint8_t kind,
                       uint8_t scope, const char *room, const char *agent,
                       const char *text, uint64_t created_at, uint32_t ttl)
{
    memset(post, 0, sizeof(*post));
    post->kind = kind;
    post->scope = scope;
    post->created_at = created_at;
    post->ttl = ttl;
    (void)snprintf(post->room, sizeof(post->room), "%s", room ? room : "");
    (void)snprintf(post->agent, sizeof(post->agent), "%s", agent ? agent : "");
    size_t n = strlen(text);
    memcpy(post->text, text, n);
    post->text[n] = '\0';
    post->text_len = (uint32_t)n;
}

static const char *bs_get(const char *path, size_t *len_out)
{
    size_t n = board_site_handle_request("GET", path, NULL, 0, g_resp,
                                         BS_RESP_CAP - 1, NULL);
    g_resp[n] = '\0';
    if (len_out)
        *len_out = n;
    return (const char *)g_resp;
}

static bool bs_has(const char *resp, const char *needle)
{
    return strstr(resp, needle) != NULL;
}


/* ── public wiki pages (wiki_site_controller.c) ─────────────────────── */

static const char *bsw_get(const char *method, const char *path)
{
    size_t n = wiki_site_handle_request(method, path, NULL, 0, g_resp,
                                        BS_RESP_CAP - 1, NULL);
    g_resp[n] = '\0';
    return (const char *)g_resp;
}

/* The body of the last response, after the header block. */
static const char *bsw_body(const char *resp)
{
    const char *p = strstr(resp, "\r\n\r\n");
    return p ? p + 4 : "";
}

/* The id of the first site route row that would dispatch `path` under the
 * DATADIR boundary the HTTPS and onion listeners apply (prefix match, then
 * NUL, '/' or '?'), or NULL when no row takes it and the request 404s
 * before any handler runs. */
static const char *bsw_routed_row(const char *path)
{
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        const struct zcl_site_route *r = &g_zcl_site_routes[i];
        size_t n = strlen(r->prefix);
        if (strncmp(path, r->prefix, n) != 0)
            continue;
        if (strcmp(r->flavor, "PLAIN") == 0 || path[n] == '\0' ||
            path[n] == '/' || path[n] == '?')
            return r->id;
    }
    return NULL;
}

/* Copy the href of the page's "JSON form" link into out. */
static bool bsw_json_link(const char *html, char *out, size_t cap)
{
    const char *end = strstr(html, "'>JSON form</a>");
    if (!end)
        return false;
    const char *p = end;
    while (p > html && strncmp(p, "href='", 6) != 0)
        p--;
    if (strncmp(p, "href='", 6) != 0)
        return false;
    size_t n = (size_t)(end - (p + 6));
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p + 6, n);
    out[n] = '\0';
    return true;
}

static bool bsw_add(struct node_db *db, const uint8_t seed[32],
                    const uint8_t pk[32], const char *slug, const char *title,
                    const char *agent, const char *text, uint8_t scope,
                    uint64_t created_at, const uint8_t *supersedes,
                    uint8_t id_out[32])
{
    struct fleet_board_post p;
    bs_compose(&p, FLEET_BOARD_KIND_WIKI, scope,
               scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "", agent,
               text, created_at, 86400);
    (void)snprintf(p.slug, sizeof(p.slug), "%s", slug);
    (void)snprintf(p.title, sizeof(p.title), "%s", title);
    if (supersedes)
        memcpy(p.supersedes, supersedes, 32);
    if (fleet_board_post_sign(&p, seed, pk) != FLEET_BOARD_OK)
        return false;
    memcpy(id_out, p.id, 32);
    return db_fleet_board_post_ingest(db, &p, (int64_t)created_at, NULL) ==
           FLEET_BOARD_OK;
}

static bool bsw_json(const char *resp, struct json_value *doc)
{
    const char *body = bsw_body(resp);
    json_init(doc);
    return json_read(doc, body, strlen(body));
}

static int test_board_site_wiki(void)
{
    int failures = 0;
    zcl_fleet_role_checker_install_permissive_for_testing();
    TEST("board site: public wiki lists, renders, escapes and refuses") {
        wiki_site_cache_reset_for_testing();
        /* No runtime: a malformed slug is a 404 decided before any lookup,
         * while a well-formed one needs the database and says so. */
        app_runtime_set_current(NULL);
        ASSERT(strstr(bsw_get("GET", "/wiki/Upper"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/../x"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/a%2fb"), "404 Not Found"));
        char longslug[96] = "/wiki/";
        memset(longslug + 6, 'a', 65);
        longslug[71] = '\0';
        ASSERT(strstr(bsw_get("GET", longslug), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/some-page"),
                      "503 Service Unavailable"));
        /* The .txt form answers every error in plain text. */
        const char *txt_errors[][2] = {
            {"GET", "/wiki/Upper.txt"}, {"GET", "/wiki/a%2fb.txt"},
            {"GET", "/wiki/some-page.txt"}, {"POST", "/wiki/some-page.txt"},
        };
        const char *txt_status[] = {"404 Not Found", "404 Not Found",
                                    "503 Service Unavailable",
                                    "405 Method Not Allowed"};
        for (size_t i = 0; i < 4; i++) {
            const char *r = bsw_get(txt_errors[i][0], txt_errors[i][1]);
            ASSERT(strstr(r, txt_status[i]));
            ASSERT(strstr(r, "Content-Type: text/plain; charset=utf-8"));
            ASSERT(!strstr(r, "<h1>"));
        }
        ASSERT_EQ(wiki_site_handle_request("GET", "/wikipedia", NULL, 0,
                                           g_resp, BS_RESP_CAP, NULL), 0);

        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32], seed2[32], pk2[32];
        bs_identity(1, seed, pk);
        bs_identity(2, seed2, pk2);
        const uint64_t now = (uint64_t)platform_time_wall_time_t();
        uint8_t id_zeta[32], id_alpha1[32], id_alpha2[32], id_bad[32],
                id_fleet[32], id_only[32];
        static const char entry_text[] =
            "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"alpha-page\","
            "\"summary\":\"Run <full> lint & wait\","
            "\"lessons\":[{\"rule\":\"never <script>alert(1)</script> & lint\","
            "\"why\":\"because \\\"quotes\\\"\",\"evidence\":\"see <a href=x>\"}],"
            "\"applies_to\":[\"lint\"],\"updated\":\"2026-10-01T00:00:00Z\"}";
        ASSERT(bsw_add(&db, seed, pk, "zeta-page", "Zeta notes", "lane-a",
                       "first line <b>&amp; more\nsecond line", 0, now,
                       NULL, id_zeta));
        ASSERT(bsw_add(&db, seed2, pk2, "alpha-page", "Alpha", "lane-b",
                       "old alpha text", 0, now + 1, NULL, id_alpha1));
        ASSERT(bsw_add(&db, seed2, pk2, "alpha-page", "Alpha", "lane-b",
                       entry_text, 0, now + 2, id_alpha1, id_alpha2));
        ASSERT(bsw_add(&db, seed, pk, "private-page", "Private", "lane-a",
                       "FLEETONLY-MARKER", FLEET_BOARD_SCOPE_FLEET, now + 3,
                       NULL, id_fleet));
        ASSERT(bsw_add(&db, seed, pk, "broken-only", "Broken", "tamper-a",
                       "will be altered", 0, now + 4, NULL, id_only));
        ASSERT(bsw_add(&db, seed, pk, "half-broken", "Half", "lane-a",
                       "good older revision", 0, now + 5, NULL, id_bad));
        uint8_t id_bad2[32];
        ASSERT(bsw_add(&db, seed, pk, "half-broken", "Half", "tamper-b",
                       "newer revision to alter", 0, now + 6, id_bad,
                       id_bad2));
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='altered' "
                                 "WHERE agent IN ('tamper-a','tamper-b')"));
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);

        char hex_zeta[65], hex_a2[65], hex_a1[65], hex_bad[65], hex_pk[65],
             hex_pk2[65];
        fleet_board_id_to_hex(id_zeta, hex_zeta);
        fleet_board_id_to_hex(id_alpha2, hex_a2);
        fleet_board_id_to_hex(id_alpha1, hex_a1);
        fleet_board_id_to_hex(id_bad, hex_bad);
        fleet_board_id_to_hex(pk, hex_pk);
        fleet_board_id_to_hex(pk2, hex_pk2);

        /* Index: both public pages, slug order, newest revision, signer. */
        const char *resp = bsw_get("GET", "/wiki");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, "Content-Type: text/html; charset=utf-8"));
        ASSERT(strstr(resp, "Content-Security-Policy: default-src 'none'"));
        ASSERT(strstr(resp, "X-Content-Type-Options: nosniff"));
        ASSERT(strstr(resp, "untrusted knowledge"));
        ASSERT(strstr(resp, hex_zeta));
        ASSERT(strstr(resp, hex_a2));
        ASSERT(!strstr(resp, hex_a1));
        char short_pk[17], short_pk2[17];
        memcpy(short_pk, hex_pk, 16);
        short_pk[16] = '\0';
        memcpy(short_pk2, hex_pk2, 16);
        short_pk2[16] = '\0';
        ASSERT(strstr(resp, short_pk));
        ASSERT(strstr(resp, short_pk2));
        const char *a = strstr(resp, "href='/wiki/alpha-page'");
        const char *z = strstr(resp, "href='/wiki/zeta-page'");
        ASSERT(a && z && a < z);
        /* Structured pages list their summary, plain pages their first line,
         * both escaped. */
        ASSERT(strstr(resp, "Run &lt;full&gt; lint &amp; wait"));
        ASSERT(strstr(resp, "first line &lt;b&gt;&amp;amp; more"));
        ASSERT(!strstr(resp, "second line"));
        ASSERT(!strstr(resp, "<b>&amp;"));
        /* Fleet-private and unverifiable-only pages never appear. */
        ASSERT(!strstr(resp, "private-page"));
        ASSERT(!strstr(resp, "FLEETONLY-MARKER"));
        ASSERT(!strstr(resp, "broken-only"));
        ASSERT(strstr(resp, "href='/wiki/half-broken'"));
        /* The emitted JSON link must clear the real mount boundary: a dot
         * straight after the "/wiki" prefix is refused, so it must not be
         * "/wiki.json". */
        char jl[64];
        ASSERT(bsw_json_link(resp, jl, sizeof(jl)));
        ASSERT(bsw_routed_row(jl) != NULL);
        ASSERT(bsw_routed_row("/wiki.json") == NULL);

        /* The same index mounted under /board/wiki links to itself. */
        ASSERT(strstr(bsw_get("GET", "/board/wiki"),
                      "href='/board/wiki/alpha-page'"));
        resp = bs_get("/board/wiki/alpha-page", NULL);
        ASSERT(strstr(resp, "200 OK"));

        /* Index JSON. */
        struct json_value doc;
        resp = bsw_get("GET", jl);
        ASSERT(strstr(resp, "Content-Type: application/json"));
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "schema")),
                         "zcl.public_wiki_index.v1"), 0);
        ASSERT_EQ(json_get_int(json_get(&doc, "count")), 3);
        const struct json_value *rows = json_get(&doc, "pages");
        ASSERT_EQ(strcmp(json_get_str(json_get(json_at(rows, 0), "slug")),
                         "alpha-page"), 0);
        ASSERT_EQ(strcmp(json_get_str(json_get(json_at(rows, 0),
                                               "revision_id")), hex_a2), 0);
        ASSERT_EQ(strcmp(json_get_str(json_get(json_at(rows, 0), "signer")),
                         hex_pk2), 0);
        ASSERT_EQ(strcmp(json_get_str(json_get(json_at(rows, 2), "slug")),
                         "zeta-page"), 0);
        json_free(&doc);

        /* A structured page: every field escaped. */
        resp = bsw_get("GET", "/wiki/alpha-page");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, hex_a2));
        ASSERT(strstr(resp, hex_pk2));
        ASSERT(strstr(resp, "never &lt;script&gt;alert(1)&lt;/script&gt; "
                            "&amp; lint"));
        ASSERT(strstr(resp, "because &quot;quotes&quot;"));
        ASSERT(strstr(resp, "Evidence: see &lt;a href=x&gt;"));
        ASSERT(!strstr(resp, "<script"));
        ASSERT(strstr(resp, "href='/wiki'"));
        ASSERT(strstr(resp, "href='/wiki/alpha-page.json'"));

        /* A plain page: preformatted escaped text. */
        resp = bsw_get("GET", "/wiki/zeta-page");
        ASSERT(strstr(resp, "<pre>first line &lt;b&gt;&amp;amp; more"));
        ASSERT(strstr(resp, "second line"));
        ASSERT(!strstr(resp, "<b>&amp;"));

        /* Plain text: the raw page text, unescaped, as text/plain. */
        resp = bsw_get("GET", "/wiki/zeta-page.txt");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, "Content-Type: text/plain; charset=utf-8"));
        ASSERT(strstr(bsw_body(resp), "first line <b>&amp; more"));
        ASSERT(!strstr(resp, "<pre>"));
        resp = bsw_get("GET", "/wiki/no-such-page.txt");
        ASSERT(strstr(resp, "404 Not Found"));
        ASSERT(strstr(resp, "Content-Type: text/plain; charset=utf-8"));
        ASSERT(!strstr(resp, "<h1>"));

        /* Page JSON matches. */
        resp = bsw_get("GET", "/wiki/alpha-page.json");
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "schema")),
                         "zcl.public_wiki_page.v1"), 0);
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "revision_id")),
                         hex_a2), 0);
        ASSERT(json_get(&doc, "entry") != NULL);
        ASSERT_EQ(strcmp(json_get_str(json_get(json_get(&doc, "entry"),
                                               "topic")), "alpha-page"), 0);
        json_free(&doc);
        resp = bsw_get("GET", "/wiki/zeta-page.json");
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "text")),
                         "first line <b>&amp; more\nsecond line"), 0);
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "signer")), hex_pk), 0);
        json_free(&doc);

        /* Unknown, malformed, private and tampered-only slugs are 404. */
        ASSERT(strstr(bsw_get("GET", "/wiki/no-such-page"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/Upper"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/../x"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", longslug), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/zeta-page/"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/private-page"), "404 Not Found"));
        ASSERT(!strstr((const char *)g_resp, "FLEETONLY-MARKER"));
        ASSERT(strstr(bsw_get("GET", "/wiki/broken-only"), "404 Not Found"));
        ASSERT(strstr(bsw_get("GET", "/wiki/broken-only.json"),
                      "404 Not Found"));

        /* A page whose newest revision fails verification shows the newest
         * revision that does verify, never the altered one. */
        resp = bsw_get("GET", "/wiki/half-broken");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, hex_bad));
        ASSERT(strstr(resp, "good older revision"));
        ASSERT(!strstr(resp, "altered"));

        /* Read-only: HEAD has no body, POST is refused. */
        resp = bsw_get("HEAD", "/wiki/zeta-page");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT_EQ((int)strlen(bsw_body(resp)), 0);
        ASSERT(strstr(bsw_get("POST", "/wiki"), "405 Method Not Allowed"));

        app_runtime_set_current(NULL);
        node_db_close(&db);
        PASS();
    } _test_next:;
    zcl_fleet_role_checker_install(NULL);
    return failures;
}


/* ── hardening: untrusted bytes, the index cache, scopes, the mount ──── */

#define BSW_BIG_CAP 400000

/* Bad bytes, one run each: stray, truncated lead, overlong. Quote, backslash
 * and tab must survive JSON escaping. */
static const char k_bad_text[] =
    "q\"uo\\te\tA\xff" "B\xe2\x82" "C\xc0\xaf" "D";
static const char k_clean_text[] =
    "q\"uo\\te\tA\xEF\xBF\xBD" "B\xEF\xBF\xBD\xEF\xBF\xBD"
    "C\xEF\xBF\xBD\xEF\xBF\xBD" "D";

static size_t bsw_get_big(uint8_t *buf, const char *method, const char *path)
{
    size_t n = wiki_site_handle_request(method, path, NULL, 0, buf,
                                        BSW_BIG_CAP - 1, NULL);
    buf[n] = '\0';
    return n;
}

/* 256 slugs across two keys, ingested in distinct quota windows. */
static bool bsw_fill_256(struct node_db *db, size_t count)
{
    uint8_t seed[32], pk[32], id[32];
    for (size_t i = 0; i < count; i++) {
        bs_identity((uint8_t)(10 + i / 128), seed, pk);
        char slug[32];
        (void)snprintf(slug, sizeof(slug), "pg-%03zu", i);
        /* 20 revisions per key per 600 s window: a new window every 16. */
        uint64_t when = 1800000000u + 700u * (i / 16);
        if (!bsw_add(db, seed, pk, slug, "T", "fill", "page body", 0, when,
                     NULL, id))
            return false;
    }
    return true;
}

static int test_board_site_wiki_hardening(void)
{
    int failures = 0;
    zcl_fleet_role_checker_install_permissive_for_testing();
    TEST("board site: wiki bytes, scopes, cache, mount and edge routes") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        bs_identity(3, seed, pk);
        const uint64_t now = (uint64_t)platform_time_wall_time_t();
        uint8_t id_bad[32], id_pub[32], id_old[32], id_fleet[32], id_a[32],
                id_b[32], id_c[32];
        ASSERT(bsw_add(&db, seed, pk, "bytes-page", "T\xff" "itle", "lane-a",
                       k_bad_text, 0, now, NULL, id_bad));
        ASSERT(bsw_add(&db, seed, pk, "pub-page", "Public", "lane-a",
                       "public scope text", FLEET_BOARD_SCOPE_PUBLIC, now + 1,
                       NULL, id_pub));
        ASSERT(bsw_add(&db, seed, pk, "mixed-page", "Mixed", "lane-a",
                       "older public revision", FLEET_BOARD_SCOPE_PUBLIC,
                       now + 2, NULL, id_old));
        ASSERT(bsw_add(&db, seed, pk, "mixed-page", "Mixed", "lane-a",
                       "FLEETONLY-NEWER", FLEET_BOARD_SCOPE_FLEET, now + 3,
                       NULL, id_fleet));
        ASSERT(bsw_add(&db, seed, pk, "half-broken", "Half", "lane-a",
                       "good older revision", 0, now + 4, NULL, id_a));
        ASSERT(bsw_add(&db, seed, pk, "half-broken", "Half", "tamper-b",
                       "newer revision to alter", 0, now + 5, id_a, id_b));
        ASSERT(bsw_add(&db, seed, pk, "healthy", "Healthy", "lane-a",
                       "all good", 0, now + 6, NULL, id_c));
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='altered' "
                                 "WHERE agent='tamper-b'"));
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);
        wiki_site_cache_reset_for_testing();

        /* The production mount carries the main cases. */
        const char *resp = bs_get("/board/wiki", NULL);
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, "href='/board/wiki/pub-page'"));
        ASSERT(strstr(resp, "href='/board/wiki/bytes-page'"));
        ASSERT(strstr(resp, "href='/board/wiki/healthy'"));
        /* Public scope rows show; a slug whose newest revision is
         * fleet-private is absent, text and slug. */
        ASSERT(!strstr(resp, "mixed-page"));
        ASSERT(!strstr(resp, "FLEETONLY-NEWER"));
        ASSERT(strstr(bs_get("/board/wiki/mixed-page", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki/mixed-page.json", NULL),
                      "404 Not Found"));
        resp = bs_get("/board/wiki/pub-page", NULL);
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, "public scope text"));
        struct json_value doc;
        resp = bs_get("/board/wiki.json", NULL);
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(json_get_int(json_get(&doc, "count")), 4);
        ASSERT(!json_get_int(json_get(&doc, "truncated")));
        json_free(&doc);
        resp = bs_get("/board/wiki/pub-page.json", NULL);
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "text")),
                         "public scope text"), 0);
        json_free(&doc);

        /* Untrusted bytes: the JSON form parses, is valid UTF-8, and carries
         * U+FFFD where the bad bytes were. */
        resp = bs_get("/board/wiki/bytes-page.json", NULL);
        const char *body = bsw_body(resp);
        ASSERT(zutf8_validate_n(body, strlen(body)));
        ASSERT(bsw_json(resp, &doc));
        ASSERT_EQ(strcmp(json_get_str(json_get(&doc, "text")), k_clean_text), 0);
        ASSERT(zutf8_validate(json_get_str(json_get(&doc, "title"))));
        json_free(&doc);
        resp = bs_get("/board/wiki/bytes-page", NULL);
        body = bsw_body(resp);
        ASSERT(zutf8_validate_n(body, strlen(body)));
        ASSERT(strstr(body, "\xEF\xBF\xBD"));
        resp = bs_get("/board/wiki.json", NULL);
        body = bsw_body(resp);
        ASSERT(zutf8_validate_n(body, strlen(body)));

        /* A newer revision that failed verification is disclosed. */
        resp = bs_get("/board/wiki/half-broken.json", NULL);
        ASSERT(bsw_json(resp, &doc));
        ASSERT(json_get_bool(json_get(&doc, "newer_revision_unverified")));
        json_free(&doc);
        ASSERT(strstr(bs_get("/board/wiki/half-broken", NULL),
                      "newer revision of this page is held here but failed "
                      "verification"));
        resp = bs_get("/board/wiki/healthy.json", NULL);
        ASSERT(bsw_json(resp, &doc));
        ASSERT(json_get(&doc, "newer_revision_unverified") == NULL);
        json_free(&doc);

        /* Edge routes. */
        ASSERT(strstr(bs_get("/board/wiki/Upper.json", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki/..%2fx.json", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki//", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki//healthy", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki/.json", NULL), "404 Not Found"));
        ASSERT(strstr(bs_get("/board/wiki/healthy?x=1", NULL), "200 OK"));
        ASSERT(strstr(bs_get("/board/wiki?x=1", NULL), "200 OK"));
        ASSERT(strstr(bs_get("/board/wiki.json?x=1", NULL),
                      "application/json"));
        resp = bsw_get("HEAD", "/board/wiki");
        ASSERT(strstr(resp, "200 OK"));
        ASSERT(strstr(resp, "Content-Length: "));
        ASSERT_EQ((int)strlen(bsw_body(resp)), 0);

        /* The index cache: two quick requests verify once, in both forms
         * and for HEAD; the other mount prefix has its own slot. */
        wiki_site_cache_reset_for_testing();
        ASSERT_EQ((int)wiki_site_index_builds_for_testing(), 0);
        (void)bsw_get("GET", "/board/wiki");
        (void)bsw_get("GET", "/board/wiki");
        (void)bsw_get("GET", "/board/wiki.json");
        (void)bsw_get("HEAD", "/board/wiki");
        ASSERT_EQ((int)wiki_site_index_builds_for_testing(), 1);
        (void)bsw_get("GET", "/wiki");
        ASSERT_EQ((int)wiki_site_index_builds_for_testing(), 2);
        wiki_site_cache_reset_for_testing();
        (void)bsw_get("GET", "/board/wiki");
        ASSERT_EQ((int)wiki_site_index_builds_for_testing(), 1);
        node_db_close(&db);

        /* Exactly 256 pages are complete; a 257th makes the list truncated. */
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        service.node_db = &db;
        ASSERT(bsw_fill_256(&db, 256));
        wiki_site_cache_reset_for_testing();
        uint8_t *big = malloc(BSW_BIG_CAP);
        ASSERT(big != NULL);
        ASSERT(bsw_get_big(big, "GET", "/board/wiki.json") > 0);
        ASSERT(bsw_json((const char *)big, &doc));
        ASSERT_EQ(json_get_int(json_get(&doc, "count")), 256);
        ASSERT(!json_get_int(json_get(&doc, "truncated")));
        json_free(&doc);
        ASSERT(bsw_get_big(big, "GET", "/board/wiki") > 0);
        ASSERT(strstr((const char *)big, "200 OK"));
        ASSERT(!strstr((const char *)big, "The list is bounded"));
        ASSERT(bsw_fill_256(&db, 257));
        wiki_site_cache_reset_for_testing();
        ASSERT(bsw_get_big(big, "GET", "/board/wiki.json") > 0);
        ASSERT(bsw_json((const char *)big, &doc));
        ASSERT_EQ(json_get_int(json_get(&doc, "count")), 256);
        ASSERT(json_get_bool(json_get(&doc, "truncated")));
        json_free(&doc);
        free(big);

        app_runtime_set_current(NULL);
        node_db_close(&db);
        wiki_site_cache_reset_for_testing();
        PASS();
    } _test_next:;
    zcl_fleet_role_checker_install(NULL);
    return failures;
}

static int test_board_site_wiki_root_route(void)
{
    int failures = 0;
    TEST("board site: /wiki and /wiki/<slug> dispatch to the wiki handler "
         "through the generated site route table") {
        /* The HTTPS listener expands site_routes.def in order, with a DATADIR
         * path[N] in {NUL,'/','?'} boundary guard. Resolve each path the same
         * way over g_zcl_site_routes and check which handler it lands on. */
        static const struct { const char *path; const char *want; } k_cases[] = {
            { "/wiki",           "wiki_site_handle_request"  },
            { "/wiki/",          "wiki_site_handle_request"  },
            { "/wiki/some-page", "wiki_site_handle_request"  },
            { "/board/wiki",     "board_site_handle_request" },
            { "/wikipedia",      NULL                        },
        };
        for (size_t c = 0; c < sizeof(k_cases) / sizeof(k_cases[0]); c++) {
            const char *path = k_cases[c].path;
            const char *got = NULL;
            for (size_t i = 0; i < g_zcl_site_routes_count && !got; i++) {
                const struct zcl_site_route *r = &g_zcl_site_routes[i];
                size_t pl = strlen(r->prefix);
                if (strncmp(path, r->prefix, pl) != 0)
                    continue;
                char next = path[pl];
                if (next == '\0' || next == '/' || next == '?')
                    got = r->handler_name;
            }
            ASSERT((got == NULL) == (k_cases[c].want == NULL));
            ASSERT(got == NULL || strcmp(got, k_cases[c].want) == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── /board/post/<id> — one post, whole ─────────────────────────────── */

#define BSP_LEAD 480
#define BSP_NOT_FOUND_CAP 16384

static bool bsp_sign_ingest(struct node_db *db, struct fleet_board_post *p,
                            const uint8_t seed[32], const uint8_t pk[32],
                            int64_t ingest_now)
{
    return fleet_board_post_sign(p, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(db, p, ingest_now, NULL) ==
               FLEET_BOARD_OK;
}

/* Copies the current response into saved; false when it does not fit. */
static bool bsp_save(const char *resp, char *saved, size_t cap)
{
    size_t n = strlen(resp);
    if (n >= cap)
        return false;
    memcpy(saved, resp, n + 1);
    return true;
}

static int test_board_site_post_page(void)
{
    int failures = 0;
    TEST("board site: /board/post/<id> shows one post whole, same rules") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        bs_identity(2, seed, pk);
        const int64_t now = (int64_t)platform_time_wall_time_t();

        /* 479 bytes of 'a', then U+00E9 (two bytes) straddling byte 480,
         * then a tail the preview must not reach, with markup in it. */
        char longtext[700];
        memset(longtext, 'a', 479);
        longtext[479] = '\0';
        strcat(longtext, "\xC3\xA9 TAIL-MARKER <i>x</i> end");
        struct fleet_board_post longp, reply, priv, expired, quotes, shortp;
        bs_compose(&longp, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-<c>", longtext, (uint64_t)now, 3600);
        ASSERT(bsp_sign_ingest(&db, &longp, seed, pk, now));
        bs_compose(&reply, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-c", "reply body", (uint64_t)now + 1, 3600);
        memcpy(reply.ref, longp.id, 32);
        ASSERT(bsp_sign_ingest(&db, &reply, seed, pk, now));
        bs_compose(&priv, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET, "",
                   "lane-c", "PRIVATE-MARKER", (uint64_t)now + 2, 3600);
        ASSERT(bsp_sign_ingest(&db, &priv, seed, pk, now));
        /* Virtual time: valid when ingested at t=1000000, long expired by
         * the real clock the page reads. */
        bs_compose(&expired, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-c", "EXPIRED-MARKER", 1000000u, 10);
        ASSERT(bsp_sign_ingest(&db, &expired, seed, pk, 1000000));
        bs_compose(&shortp, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-c", "short post", (uint64_t)now + 3, 3600);
        ASSERT(bsp_sign_ingest(&db, &shortp, seed, pk, now));

        /* The longest ordinary text, every byte the worst escape. */
        static char qtext[FLEET_BOARD_TEXT_MAX + 1];
        memset(qtext, '"', FLEET_BOARD_TEXT_MAX);
        qtext[FLEET_BOARD_TEXT_MAX] = '\0';
        bs_compose(&quotes, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-c", qtext, (uint64_t)now + 4, 3600);
        ASSERT(bsp_sign_ingest(&db, &quotes, seed, pk, now));

        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);

        char id_hex[65], ref_hex[65], host_hex[65], path[128];
        fleet_board_id_to_hex(longp.id, id_hex);
        fleet_board_id_to_hex(pk, host_hex);
        (void)snprintf(path, sizeof(path), "/board/post/%s", id_hex);

        /* Post page: whole text, full id, full key, escaped, room link. */
        const char *resp = bs_get(path, NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "\xC3\xA9 TAIL-MARKER &lt;i&gt;x&lt;/i&gt; end"));
        ASSERT(!bs_has(resp, "<i>x</i>"));
        ASSERT(bs_has(resp, id_hex));
        ASSERT(bs_has(resp, host_hex));
        ASSERT(bs_has(resp, "/board/room/contrib"));
        ASSERT(bs_has(resp, "lane-&lt;c&gt;"));
        ASSERT(!bs_has(resp, "lane-<c>"));

        /* The reply names its parent in full, as a link. */
        fleet_board_id_to_hex(reply.id, ref_hex);
        (void)snprintf(path, sizeof(path), "/board/post/%s", ref_hex);
        resp = bs_get(path, NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "reply body"));
        char want[160];
        (void)snprintf(want, sizeof(want), "href='/board/post/%s'", id_hex);
        ASSERT(bs_has(resp, want));

        /* Room page: preview clipped on a character boundary, a full-post
         * link, the id linked whole, and a reply marker with a ref link. */
        resp = bs_get("/board/room/contrib", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(!bs_has(resp, "TAIL-MARKER"));
        ASSERT(!bs_has(resp, "\xC3"));
        ASSERT(bs_has(resp, "full post"));
        ASSERT(bs_has(resp, want));
        char re16[40];
        (void)snprintf(re16, sizeof(re16), "re %.16s", id_hex);
        ASSERT(bs_has(resp, re16));
        ASSERT(bs_has(resp, "short post"));
        ASSERT(!bs_has(resp, "PRIVATE-MARKER"));
        ASSERT(!bs_has(resp, "EXPIRED-MARKER"));

        /* The longest ordinary post fits whole: nothing cut. */
        fleet_board_id_to_hex(quotes.id, ref_hex);
        (void)snprintf(path, sizeof(path), "/board/post/%s", ref_hex);
        resp = bs_get(path, NULL);
        ASSERT(bs_has(resp, "200 OK"));
        static char allq[FLEET_BOARD_TEXT_MAX * 6 + 8];
        allq[0] = '\0';
        for (int i = 0; i < FLEET_BOARD_TEXT_MAX; i++)
            strcat(allq + i * 6, "&quot;");
        ASSERT(bs_has(resp, allq));
        ASSERT(bs_has(resp, "</html>") || bs_has(resp, "</main>"));
        resp = bs_get("/board/room/contrib", NULL);
        ASSERT(bs_has(resp, "200 OK"));

        /* Unknown, malformed, fleet-private and expired ids: one 404, the
         * same bytes, so no page tells them apart. */
        static char nf[BSP_NOT_FOUND_CAP];
        resp = bs_get("/board/post/" "00000000000000000000000000000000"
                      "00000000000000000000000000000000", NULL);
        ASSERT(bs_has(resp, "404 Not Found"));
        ASSERT(bsp_save(resp, nf, sizeof(nf)));
        char bad[256];
        const char *k_bad[] = {
            "/board/post/", "/board/post/abc",
            "/board/post/ABCDEF0123456789ABCDEF0123456789"
            "ABCDEF0123456789ABCDEF0123456789",
            "/board/post/zz00000000000000000000000000000000"
            "00000000000000000000000000000000",
        };
        for (size_t i = 0; i < sizeof(k_bad) / sizeof(k_bad[0]); i++) {
            resp = bs_get(k_bad[i], NULL);
            ASSERT(strcmp(resp, nf) == 0);
        }
        (void)snprintf(bad, sizeof(bad), "/board/post/%s/", id_hex);
        ASSERT(strcmp(bs_get(bad, NULL), nf) == 0);
        (void)snprintf(bad, sizeof(bad), "/board/post/%s/x", id_hex);
        ASSERT(strcmp(bs_get(bad, NULL), nf) == 0);
        (void)snprintf(bad, sizeof(bad), "/board/post/%s0", id_hex);
        ASSERT(strcmp(bs_get(bad, NULL), nf) == 0);
        fleet_board_id_to_hex(priv.id, ref_hex);
        (void)snprintf(bad, sizeof(bad), "/board/post/%s", ref_hex);
        ASSERT(strcmp(bs_get(bad, NULL), nf) == 0);
        fleet_board_id_to_hex(expired.id, ref_hex);
        (void)snprintf(bad, sizeof(bad), "/board/post/%s", ref_hex);
        ASSERT(strcmp(bs_get(bad, NULL), nf) == 0);
        ASSERT(!bs_has(nf, "PRIVATE-MARKER"));

        app_runtime_set_current(NULL);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* One public post, then 70 later posts of the same key, kind and slug. The
 * old post is still public and unexpired, so its page must stay reachable
 * however many newer neighbours it has. Ingest times are spread over three
 * quota windows because a key may post at most
 * FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX per window. */
static int test_board_site_post_page_old_post(void)
{
    int failures = 0;
    TEST("board site: an old post stays reachable under 70 later same-key posts") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        bs_identity(3, seed, pk);
        /* Virtual time shared with the page, so no reading of a real clock
         * dates or grades a post. */
        const int64_t now = 1800000000;
        board_site_set_now_for_testing(now);
        struct fleet_board_post first;
        bs_compose(&first, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "contrib", "lane-c", "OLDEST-FULL-TEXT", (uint64_t)now - 1500,
                   7200);
        ASSERT(bsp_sign_ingest(&db, &first, seed, pk, now - 1500));
        for (int i = 0; i < 70; i++) {
            struct fleet_board_post later;
            int64_t at = now - 700 + (i < 35 ? i : 700 + i);
            char text[32];
            (void)snprintf(text, sizeof(text), "later %d", i);
            bs_compose(&later, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                       "contrib", "lane-c", text, (uint64_t)at, 7200);
            ASSERT(bsp_sign_ingest(&db, &later, seed, pk, at));
        }
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);
        char id_hex[65], path[128];
        fleet_board_id_to_hex(first.id, id_hex);
        (void)snprintf(path, sizeof(path), "/board/post/%s", id_hex);
        const char *resp = bs_get(path, NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "OLDEST-FULL-TEXT"));
        app_runtime_set_current(NULL);
        node_db_close(&db);
        PASS();
    } _test_next:;
    board_site_set_now_for_testing(0);
    return failures;
}

int test_board_site(void)
{
    int failures = 0;
    /* The fixture store is filled by ingesting posts signed by keys this
     * group invented, and ingest refuses a key with no role. This group is
     * about what the /board pages render, so the role gate is held open for
     * it and closed again below; the gate is proven elsewhere. */
    zcl_fleet_role_checker_install_permissive_for_testing();
    TEST("board site: room pages render public posts and never fleet rows") {
        /* With no runtime bound, the mount answers a named 503 rather than
         * falling through into another route family. */
        app_runtime_set_current(NULL);
        const char *resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "503 Service Unavailable"));
        ASSERT(bs_has(resp, "Board unavailable"));

        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        uint8_t seed[32], pk[32];
        bs_identity(1, seed, pk);
        /* The handler lists against real wall time, so fixtures are dated by
         * the same clock: the five posts sit between now and now+4 s, inside
         * FLEET_BOARD_FUTURE_SKEW_MAX (300) and the 3600 s TTL, so no assertion
         * depends on a difference between two clock readings. */
        const int64_t now = (int64_t)platform_time_wall_time_t();

        struct fleet_board_post legacy, ops, general, fleet, hostile;
        bs_compose(&legacy, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_LEGACY_PUBLIC,
                   "", "lane-a", "from before scopes", (uint64_t)now, 3600);
        bs_compose(&ops, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                   "ops", "lane-b", "ops room question", (uint64_t)now + 1,
                   3600);
        bs_compose(&general, FLEET_BOARD_KIND_RESULT, FLEET_BOARD_SCOPE_PUBLIC,
                   "general", "lane-b", "default room answer",
                   (uint64_t)now + 2, 3600);
        bs_compose(&fleet, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                   "", "lane-a", "FLEETONLY-MARKER text", (uint64_t)now + 3,
                   3600);
        bs_compose(&hostile, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                   "ops", "<b>bold</b>", "<script>alert(1)</script>",
                   (uint64_t)now + 4, 3600);
        ASSERT_EQ(fleet_board_post_sign(&legacy, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&ops, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&general, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&fleet, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fleet_board_post_sign(&hostile, seed, pk), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &legacy, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &ops, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &general, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &fleet, now, NULL),
                  FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &hostile, now, NULL),
                  FLEET_BOARD_OK);

        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        app_runtime_set_current(&runtime);

        /* The index lists the public rooms and links each one. */
        resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "Board rooms"));
        ASSERT(bs_has(resp, "/board/room/ops"));
        ASSERT(bs_has(resp, "/board/room/general"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));

        /* A room page shows its own posts, newest first, with the store's
         * rows — and nothing from other rooms or scopes. */
        resp = bs_get("/board/room/ops", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "Room: ops"));
        ASSERT(bs_has(resp, "ops room question"));
        ASSERT(!bs_has(resp, "default room answer"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));
        /* Hostile markup is escaped on the way out. */
        ASSERT(!bs_has(resp, "<script>alert(1)</script>"));
        ASSERT(bs_has(resp, "&lt;script&gt;"));
        ASSERT(!bs_has(resp, "<b>bold</b>"));
        ASSERT(bs_has(resp, "&lt;b&gt;bold&lt;/b&gt;"));

        /* The default room shows the v2 general post and the legacy post
         * together: the pre-scope board IS the default room. */
        resp = bs_get("/board/room/general", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "default room answer"));
        ASSERT(bs_has(resp, "from before scopes"));
        ASSERT(!bs_has(resp, "ops room question"));
        ASSERT(!bs_has(resp, "FLEETONLY-MARKER"));

        /* A well-formed room this node holds nothing for is an honest empty
         * page, not an error. */
        resp = bs_get("/board/room/empty-room", NULL);
        ASSERT(bs_has(resp, "200 OK"));
        ASSERT(bs_has(resp, "No posts"));

        /* A name that cannot be a room is a 404, as is an unknown route. */
        resp = bs_get("/board/room/Unknown", NULL);
        ASSERT(bs_has(resp, "404 Not Found"));
        resp = bs_get("/board/bogus", NULL);
        ASSERT(bs_has(resp, "404 Not Found"));

        /* Every answer is a complete, typed HTTP response. */
        resp = bs_get("/board", NULL);
        ASSERT(bs_has(resp, "Content-Type: text/html; charset=utf-8"));

        app_runtime_set_current(NULL);
        node_db_close(&db);
        PASS();
    } _test_next:;
    failures += test_board_site_post_page();
    failures += test_board_site_post_page_old_post();
    failures += test_board_site_wiki();
    failures += test_board_site_wiki_hardening();
    failures += test_board_site_wiki_root_route();
    zcl_fleet_role_checker_install(NULL);
    return failures;
}
