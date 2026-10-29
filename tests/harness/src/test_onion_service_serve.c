/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* test_onion_service_serve: characterization of the three serve handlers in
 * core/modules/net/src/onion_service.c that the onion router reaches for
 * /status, /directory.json and /directory (and /directory/). The handlers
 * are static, so every case drives them through onion_service_handle_request,
 * the public router, against a local fixture: a fresh datadir and its node
 * database. Pinned: the status line, Content-Type, Content-Length and the
 * stable body fields, plus each refusal branch reachable without a network:
 * no datadir, a missing node database, a missing peer_directory table, and
 * the per-row skips (hostile address, expired row). */

#include "test/test_core.h"

#include "platform/time_compat.h"
#include "net/onion_service.h"
#include "net/onion_ratelimit.h"
#include "util/path_check.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Local v3-shaped hosts (56 base32 characters + ".onion"). */
#define SVC_FRESH \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
#define SVC_STALE \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbe.onion"
#define SVC_EXPIRED \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccf.onion"
#define SVC_NOPORT \
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion"
#define SVC_BAD "not-an-onion"

static uint8_t svc_resp[262144];
#define SVC_RESP ((const char *)svc_resp)

static int svc_check(const char *label, bool ok)
{
    printf("onion_service_serve: %s... ", label);
    if (ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL\n");
    return 1;
}

static int64_t svc_now(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static size_t svc_get(const char *path)
{
    onion_ratelimit_test_reset();
    memset(svc_resp, 0, sizeof(svc_resp));
    return onion_service_handle_request("GET", path, NULL, 0,
                                        svc_resp, sizeof(svc_resp) - 1);
}

static const char *svc_body(void)
{
    const char *b = strstr(SVC_RESP, "\r\n\r\n");
    return b ? b + 4 : NULL;
}

static bool svc_has(const char *hay, const char *needle)
{
    return hay && strstr(hay, needle) != NULL;
}

static bool svc_starts(const char *hay, const char *prefix)
{
    return hay && strncmp(hay, prefix, strlen(prefix)) == 0;
}

static bool svc_ends_with(const char *hay, const char *suffix)
{
    if (!hay) return false;
    size_t hl = strlen(hay);
    size_t sl = strlen(suffix);
    return hl >= sl && strcmp(hay + (hl - sl), suffix) == 0;
}

/* The value of "key":<integer> in a flat JSON body. */
static bool svc_json_long(const char *body, const char *key, long *out)
{
    char pat[64];
    if (!body || snprintf(pat, sizeof(pat), "\"%s\":", key) >= (int)sizeof(pat))
        return false;
    const char *p = strstr(body, pat);
    if (!p) return false;
    char *end = NULL;
    *out = strtol(p + strlen(pat), &end, 10);
    return end != p + strlen(pat);
}

/* True when the flat JSON object for `host` carries `field` inside it. Rows
 * are flat, so the first '}' after the host's key closes the object. */
static bool svc_row_has(const char *body, const char *host, const char *field)
{
    char key[160];
    if (!body || snprintf(key, sizeof(key), "{\"onion\":\"%s\"", host) >=
                     (int)sizeof(key))
        return false;
    const char *row = strstr(body, key);
    if (!row) return false;
    const char *end = strchr(row, '}');
    const char *hit = strstr(row, field);
    return end && hit && hit < end;
}

/* Status line, Content-Type, and a Content-Length equal to the body length:
 * the envelope every served document keeps. */
static bool svc_is_200(size_t n, const char *ctype)
{
    const char *ok_line = "HTTP/1.1 200 OK\r\n";
    char want[128];
    const char *body = svc_body();
    if (n == 0 || !body) return false;
    if (snprintf(want, sizeof(want), "Content-Type: %s\r\n", ctype) >=
        (int)sizeof(want))
        return false;
    if (strncmp(SVC_RESP, ok_line, strlen(ok_line)) != 0) return false;
    if (!svc_has(SVC_RESP, want)) return false;
    if (!svc_has(SVC_RESP, "Connection: close\r\n\r\n")) return false;
    const char *cl = strstr(SVC_RESP, "Content-Length: ");
    long declared = -1;
    if (!cl || sscanf(cl, "Content-Length: %ld", &declared) != 1) return false;
    return declared == (long)strlen(body);
}

static size_t svc_count(const char *hay, const char *needle)
{
    size_t c = 0;
    size_t nl = strlen(needle);
    const char *p = hay;
    while (p && (p = strstr(p, needle)) != NULL) {
        c++;
        p += nl;
    }
    return c;
}

/* Fixture: the router's datadir is process-global, so every case stops the
 * service, clears the address, and starts on its own fresh datadir. */
static void svc_stop_and_clear(void)
{
    onion_service_stop();
    onion_service_set_address(NULL);
}

static void svc_start(char *dir, size_t n, const char *tag)
{
    svc_stop_and_clear();
    test_make_tmpdir(dir, n, "svc_serve", tag);
    (void)onion_service_start(dir);
}

static void svc_finish(char *dir)
{
    svc_stop_and_clear();
    test_cleanup_tmpdir(dir);
}

static sqlite3 *svc_open_rw(const char *dir)
{
    char path[1024];
    zcl_node_db_path(path, sizeof(path), dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 2000);
    return db;
}

static void svc_insert_row(sqlite3 *db, const char *host, int port,
                           int64_t last_seen, const char *apps)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO peer_directory "
            "(onion_address, port, services, height, first_seen, last_seen,"
            " last_probe, probe_ok, fail_count, version, self,"
            " clearnet_ip, clearnet_port, source, apps) "
            "VALUES (?1, ?2, 0, 0, ?3, ?3, 0, 0, 0, 'test', 0, '', 0,"
            " 'discovery', ?4)",
            -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return;
    }
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, port);
    sqlite3_bind_int64(s, 3, last_seen);
    sqlite3_bind_text(s, 4, apps, -1, SQLITE_STATIC);
    (void)sqlite3_step(s);
    sqlite3_finalize(s);
}

/* One fresh row, one stale row (past the stale window, inside expiry), one
 * expired row, one row with no known port, and one hostile address. */
static void svc_seed_directory(const char *dir, int64_t now)
{
    sqlite3 *db = svc_open_rw(dir);
    if (!db) return;
    svc_insert_row(db, SVC_FRESH, 8033, now - 60, "blog,yardsale");
    svc_insert_row(db, SVC_STALE, 8033,
                   now - ONION_DIR_STALE_SECS - 600, "");
    svc_insert_row(db, SVC_EXPIRED, 8033,
                   now - ONION_DIR_EXPIRE_SECS - 60, "");
    svc_insert_row(db, SVC_NOPORT, 0, now - 60, "");
    svc_insert_row(db, SVC_BAD, 8033, now - 60, "");
    sqlite3_close(db);
}

static void svc_seed_block(const char *dir, int64_t block_time)
{
    sqlite3 *db = svc_open_rw(dir);
    if (!db) return;
    /* The fixture db carries only peer_directory; /status reads the newest
     * block from `blocks`, so create it with the production schema. */
    (void)sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS blocks ("
        "hash BLOB PRIMARY KEY,height INTEGER NOT NULL,"
        "prev_hash BLOB NOT NULL,version INTEGER NOT NULL,"
        "merkle_root BLOB NOT NULL,time INTEGER NOT NULL,"
        "bits INTEGER NOT NULL,nonce BLOB NOT NULL,"
        "solution BLOB NOT NULL,chain_work BLOB NOT NULL,"
        "status INTEGER NOT NULL DEFAULT 0)", NULL, NULL, NULL);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO blocks (hash, height, prev_hash, version,"
            " merkle_root, time, bits, nonce, solution, chain_work) "
            "VALUES (zeroblob(32), 1, zeroblob(32), 1, zeroblob(32), ?1,"
            " 0, zeroblob(0), zeroblob(0), zeroblob(0))",
            -1, &s, NULL) == SQLITE_OK && s) {
        sqlite3_bind_int64(s, 1, block_time);
        (void)sqlite3_step(s);
    }
    if (s) sqlite3_finalize(s);
    sqlite3_close(db);
}

/* ── /status ──────────────────────────────────────────────────── */

static int svc_status_shape(void)
{
    static char dir[256];
    int failures = 0;
    svc_start(dir, sizeof(dir), "status");
    size_t n = svc_get("/status");
    const char *body = svc_body();
    failures += svc_check("/status answers 200 as JSON with CORS",
        svc_is_200(n, "engine/application/json") &&
        svc_has(SVC_RESP, "Access-Control-Allow-Origin: *\r\n"));
    failures += svc_check("/status opens with height, peers, version, uptime",
        svc_starts(body, "{\"height\":0,\"peers\":0,\"version\":\"0.1.0\","
                         "\"uptime\":"));
    failures += svc_check("/status with no block reports age -1, 0 transactions",
        svc_ends_with(body, "\"last_block_age\":-1,\"transactions\":0}"));
    failures += svc_check("/status with no address: not ready, no onion key",
        svc_has(body, "\"onion_service_ready\":false") &&
        !svc_has(body, "\"onion\":"));
    failures += svc_check("/status carries tor_ready and syncing",
        svc_has(body, "\"tor_ready\":") && svc_has(body, "\"syncing\":"));
    svc_finish(dir);
    return failures;
}

static int svc_status_block_and_onion(void)
{
    static char dir[256];
    int failures = 0;
    svc_start(dir, sizeof(dir), "status_block");
    svc_seed_block(dir, svc_now() - 1000);
    onion_service_set_address(SVC_FRESH);
    size_t n = svc_get("/status");
    const char *body = svc_body();
    long age = -1;
    failures += svc_check("/status with a stored block answers 200 JSON",
        svc_is_200(n, "engine/application/json"));
    failures += svc_check("/status reports the age of the newest block",
        svc_json_long(body, "last_block_age", &age) &&
        age >= 1000 && age <= 1010);
    failures += svc_check("/status with an address reports it last as onion",
        svc_ends_with(body, ",\"onion\":\"" SVC_FRESH "\"}"));
    failures += svc_check("/status with an address reports onion_service_ready",
        svc_has(body, "\"onion_service_ready\":true"));
    svc_finish(dir);
    return failures;
}

static int svc_status_no_datadir(void)
{
    int failures = 0;
    svc_stop_and_clear();
    size_t n = svc_get("/status");
    const char *body = svc_body();
    failures += svc_check("/status with no datadir still answers 200 JSON",
        svc_is_200(n, "engine/application/json"));
    failures += svc_check("/status with no datadir reports zero height and peers",
        svc_starts(body, "{\"height\":0,\"peers\":0,"));
    failures += svc_check("/status with no datadir reports no block, no txs",
        svc_ends_with(body, "\"last_block_age\":-1,\"transactions\":0}"));
    return failures;
}

/* ── /directory.json and /directory: refusals ─────────────────── */

static int svc_directory_without_datadir(void)
{
    int failures = 0;
    svc_stop_and_clear();
    failures += svc_check("/directory.json refused with no bytes, no datadir",
        svc_get("/directory.json") == 0);
    failures += svc_check("/directory refused with no bytes, no datadir",
        svc_get("/directory") == 0);
    failures += svc_check("/directory/ refused with no bytes, no datadir",
        svc_get("/directory/") == 0);
    return failures;
}

static int svc_directory_missing_database(void)
{
    static char dir[256];
    char path[1024];
    int failures = 0;
    svc_start(dir, sizeof(dir), "nodb");
    zcl_node_db_path(path, sizeof(path), dir);
    failures += svc_check("the fixture node database can be removed",
        unlink(path) == 0);
    failures += svc_check("/directory.json refused with no bytes, no database",
        svc_get("/directory.json") == 0);
    failures += svc_check("/directory refused with no bytes, no database",
        svc_get("/directory") == 0);
    failures += svc_check("/status with no database still answers zeros",
        svc_get("/status") > 0 &&
        svc_starts(svc_body(), "{\"height\":0,\"peers\":0,"));
    svc_finish(dir);
    return failures;
}

static bool svc_drop_peer_table(const char *dir)
{
    sqlite3 *db = svc_open_rw(dir);
    if (!db) return false;
    bool ok = sqlite3_exec(db, "DROP TABLE IF EXISTS peer_directory",
                           NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static int svc_directory_missing_table(void)
{
    static char dir[256];
    int failures = 0;
    svc_start(dir, sizeof(dir), "notable");
    failures += svc_check("the peer_directory table can be dropped",
        svc_drop_peer_table(dir));
    failures += svc_check("/directory.json refused with no bytes, no table",
        svc_get("/directory.json") == 0);
    failures += svc_check("/directory refused with no bytes, no table",
        svc_get("/directory") == 0);
    svc_finish(dir);
    return failures;
}

/* ── /directory.json: the served document ─────────────────────── */

static int svc_directory_json_policy(const char *body)
{
    char want[160];
    (void)snprintf(want, sizeof(want),
        "\"stale_after_secs\":%lld,\"expire_after_secs\":%lld",
        (long long)ONION_DIR_STALE_SECS, (long long)ONION_DIR_EXPIRE_SECS);
    int failures = 0;
    failures += svc_check("the freshness policy travels with the list",
        svc_has(body, want));
    failures += svc_check("the document states generated_at and refresh_secs",
        svc_has(body, "\"generated_at\":") && svc_has(body, "\"refresh_secs\":"));
    failures += svc_check("exactly one expired row is withheld and counted",
        svc_has(body, "\"skipped_expired\":1,"));
    failures += svc_check("the document carries count and artifacts",
        svc_has(body, "\"count\":") && svc_has(body, "\"artifacts\":"));
    return failures;
}

static int svc_directory_json_row_fields(const char *body)
{
    int failures = 0;
    failures += svc_check("a fresh row is served with its age and stale=false",
        svc_row_has(body, SVC_FRESH, "\"age_secs\":") &&
        svc_row_has(body, SVC_FRESH, "\"stale\":false"));
    failures += svc_check("a fresh row carries its advertised apps as an array",
        svc_row_has(body, SVC_FRESH, "\"apps\":[\"blog\",\"yardsale\"]"));
    failures += svc_check("a fresh row carries port 8033 and source discovery",
        svc_row_has(body, SVC_FRESH, "\"port\":8033") &&
        svc_row_has(body, SVC_FRESH, "\"source\":\"discovery\""));
    failures += svc_check("an unknown height serves as JSON null",
        svc_row_has(body, SVC_FRESH, "\"height\":null"));
    failures += svc_check("a stale row is served with stale=true",
        svc_row_has(body, SVC_STALE, "\"stale\":true"));
    failures += svc_check("a row with no port serves port and height as null",
        svc_row_has(body, SVC_NOPORT, "\"port\":null") &&
        svc_row_has(body, SVC_NOPORT, "\"height\":null"));
    return failures;
}

static int svc_directory_json_withheld(const char *body)
{
    int failures = 0;
    failures += svc_check("an expired row is NOT served",
        !svc_has(body, "{\"onion\":\"" SVC_EXPIRED "\""));
    failures += svc_check("a hostile address is NOT served",
        !svc_has(body, SVC_BAD));
    return failures;
}

static int svc_directory_json_rows(void)
{
    static char dir[256];
    int failures = 0;
    svc_start(dir, sizeof(dir), "json");
    svc_seed_directory(dir, svc_now());
    size_t n = svc_get("/directory.json");
    const char *body = svc_body();
    failures += svc_check("/directory.json answers 200 as JSON with CORS",
        svc_is_200(n, "engine/application/json") &&
        svc_has(SVC_RESP, "Access-Control-Allow-Origin: *\r\n"));
    failures += svc_check("the document is a nodes array closed by an object",
        svc_starts(body, "{\"nodes\":[") && svc_ends_with(body, "}"));
    failures += svc_directory_json_policy(body);
    failures += svc_directory_json_row_fields(body);
    failures += svc_directory_json_withheld(body);
    svc_finish(dir);
    return failures;
}

/* ── /directory: the HTML page ────────────────────────────────── */

static int svc_directory_html_page(const char *body)
{
    int failures = 0;
    failures += svc_check("the page carries the node table heading",
        svc_has(body, "<h1>Node Directory</h1>") &&
        svc_has(body, "<table>"));
    failures += svc_check("a fresh row links its raw address as its label",
        svc_has(body, "<a href='http://" SVC_FRESH "/'>" SVC_FRESH "</a>"));
    failures += svc_check("exactly one row carries the stale marker",
        svc_count(body, " (stale)") == 1 &&
        svc_has(body, "href='http://" SVC_STALE "/'"));
    failures += svc_check("an unknown port and height render as em dashes",
        svc_has(body, "<td>&mdash;</td><td>&mdash;</td>"));
    return failures;
}

static int svc_directory_html_withheld(const char *body)
{
    int failures = 0;
    failures += svc_check("an expired row is NOT on the page",
        !svc_has(body, "href='http://" SVC_EXPIRED "/'"));
    failures += svc_check("a hostile address is NOT on the page",
        !svc_has(body, SVC_BAD));
    failures += svc_check("the footer names the expiry window and JSON API",
        svc_has(body, "nodes in directory (rows unseen for more than ") &&
        svc_has(body, "href='/directory.json'>JSON API</a>"));
    return failures;
}

static int svc_directory_html_rows(void)
{
    static char dir[256];
    int failures = 0;
    svc_start(dir, sizeof(dir), "html");
    svc_seed_directory(dir, svc_now());
    size_t n = svc_get("/directory");
    const char *body = svc_body();
    failures += svc_check("/directory answers 200 as HTML",
        svc_is_200(n, "text/html; charset=utf-8"));
    failures += svc_directory_html_page(body);
    failures += svc_directory_html_withheld(body);
    n = svc_get("/directory/");
    failures += svc_check("/directory/ routes to the same HTML page",
        svc_is_200(n, "text/html; charset=utf-8"));
    svc_finish(dir);
    return failures;
}

int test_onion_service_serve(void)
{
    int failures = 0;
    printf("\n=== Onion service serve handlers (/status, /directory) ===\n");

    /* The address singleton is process-global; the sequential runner shares
     * it across groups. Snapshot and restore. */
    const char *prev = onion_service_get_address();
    char saved[128] = "";
    if (prev) snprintf(saved, sizeof(saved), "%s", prev);

    failures += svc_status_shape();
    failures += svc_status_block_and_onion();
    failures += svc_status_no_datadir();
    failures += svc_directory_without_datadir();
    failures += svc_directory_missing_database();
    failures += svc_directory_missing_table();
    failures += svc_directory_json_rows();
    failures += svc_directory_html_rows();

    onion_service_stop();
    onion_service_set_address(saved[0] ? saved : NULL);

    printf("=== Onion service serve handlers: %d failure(s) ===\n", failures);
    return failures;
}
