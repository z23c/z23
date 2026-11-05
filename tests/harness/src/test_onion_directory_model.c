/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sub-test of the `onion_directory` group (dispatched from
 * test_onion_directory.c, which owns that group's entry point).
 *
 * test_onion_directory.c drives the net-side directory
 * (core/modules/net/src/onion_directory.c). The on-chain projection MODEL
 * (engine/models/src/onion_directory.c: validate, save, find, list_active,
 * the counts, truncate, dump_state_json) was only exercised by test_zdir.
 * A mutation sweep of that model file through this group measured 0 kills
 * of 191, so the group did not reach it at all. This file pins the model's
 * contract here, every column and every refusal at its boundary:
 *
 *  1. validate names each failing field, one message per field, in order,
 *     and accepts the boundary values (height 0, a key whose only non-zero
 *     byte is the first or the last).
 *  2. save / find round-trip every one of the 7 columns with distinct
 *     values, store the NULL forms, REPLACE on the hostname key, and refuse
 *     on a closed handle without writing.
 *  3. list_active is seniority-first (height, then hostname), bounded by
 *     max and offset, and never writes past max.
 *  4. counts, truncate and the table-missing failure paths.
 *  5. the `ops state` dump: totals, and one row resolved by hostname.
 *
 * Fixtures are private in-memory databases; nothing here reads the clock. */

#include "test/test_core.h"

#include "config/db_service.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/onion_directory.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OM_CHECK(label, cond) do { \
    printf("onion_directory model: %s... ", (label)); \
    if (cond) { printf("OK\n"); } \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void om_host(char *out, size_t n, char c)
{
    char body[57];
    memset(body, c, 56);
    body[56] = '\0';
    snprintf(out, n, "%s.onion", body);
}

static void om_row(struct db_onion_directory *r, char c, int32_t height,
                   const char *status)
{
    memset(r, 0, sizeof(*r));
    om_host(r->hostname, sizeof(r->hostname), c);
    for (int i = 0; i < 32; i++)
        r->txid[i] = (uint8_t)(i + 1);
    r->height = height;
    r->updated_height = height + 7;
    snprintf(r->status, sizeof(r->status), "%s", status);
}

static int om_count_sql(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            n = sqlite3_column_int(s, 0);
    }
    if (s) sqlite3_finalize(s);
    return n;
}

/* The exact message and count validate gives one row. */
static bool om_verdict(const struct db_onion_directory *r, int want_count,
                       const char *want_first)
{
    struct ar_errors e;
    memset(&e, 0, sizeof(e));
    e.count = 3;                    /* stale: validate must clear it */
    bool ok = db_onion_directory_validate(r, &e);
    if (want_count == 0)
        return ok && e.count == 0;
    return !ok && e.count == want_count &&
           strcmp(e.messages[0], want_first) == 0;
}

/* ── 1. validate ──────────────────────────────────────────────────── */

static int om_validate_fields(void)
{
    int failures = 0;
    struct db_onion_directory r;
    struct ar_errors e;
    memset(&e, 0, sizeof(e));

    om_row(&r, 'b', 0, ONION_DIRECTORY_STATUS_ACTIVE);
    OM_CHECK("a good row at height 0 is accepted, stale errors cleared",
             om_verdict(&r, 0, NULL));

    om_row(&r, 'b', 5, ONION_DIRECTORY_STATUS_RETIRED);
    OM_CHECK("retired is a known status", om_verdict(&r, 0, NULL));

    om_row(&r, 'b', 5, ONION_DIRECTORY_STATUS_ACTIVE);
    snprintf(r.hostname, sizeof(r.hostname), "nope.onion");
    OM_CHECK("bad hostname: exactly one hostname message",
             om_verdict(&r, 1, "hostname must be a Tor v3 onion hostname "
                               "(56 base32 + .onion)"));

    om_row(&r, 'b', 5, "gone");
    OM_CHECK("unknown status: exactly one status message",
             om_verdict(&r, 1, "status must be one of active|retired"));
    om_row(&r, 'b', 5, "activ");
    OM_CHECK("a status prefix of a known one is unknown",
             om_verdict(&r, 1, "status must be one of active|retired"));
    om_row(&r, 'b', 5, "");
    OM_CHECK("an empty status is unknown",
             om_verdict(&r, 1, "status must be one of active|retired"));

    om_row(&r, 'b', -1, ONION_DIRECTORY_STATUS_ACTIVE);
    OM_CHECK("height -1: exactly one height message",
             om_verdict(&r, 1, "height must be non-negative"));
    om_row(&r, 'b', 5, ONION_DIRECTORY_STATUS_ACTIVE);
    r.updated_height = -1;
    OM_CHECK("updated_height -1: exactly one updated_height message",
             om_verdict(&r, 1, "updated_height must be non-negative"));
    r.updated_height = 0;
    OM_CHECK("updated_height 0 is accepted", om_verdict(&r, 0, NULL));

    OM_CHECK("a NULL row is refused with one message",
             !db_onion_directory_validate(NULL, &e) && e.count == 1 &&
             strcmp(e.messages[0], "row is NULL") == 0);
    return failures;
}

static int om_validate_key_and_all(void)
{
    int failures = 0;
    struct db_onion_directory r;
    struct ar_errors e;
    memset(&e, 0, sizeof(e));

    om_row(&r, 'b', 5, ONION_DIRECTORY_STATUS_ACTIVE);
    r.has_pubkey = true;
    OM_CHECK("a present all-zero key: exactly one master_pubkey message",
             om_verdict(&r, 1, "master_pubkey is present but all-zero"));
    r.master_pubkey[0] = 1;
    OM_CHECK("a key whose only non-zero byte is the first is accepted",
             om_verdict(&r, 0, NULL));
    r.master_pubkey[0] = 0;
    r.master_pubkey[31] = 1;
    OM_CHECK("a key whose only non-zero byte is the LAST is accepted",
             om_verdict(&r, 0, NULL));
    r.master_pubkey[31] = 0;
    r.has_pubkey = false;
    OM_CHECK("an absent key is not judged by its zero bytes",
             om_verdict(&r, 0, NULL));

    /* Everything wrong at once: five messages, in field order. */
    memset(&r, 0, sizeof(r));
    snprintf(r.hostname, sizeof(r.hostname), "x");
    snprintf(r.status, sizeof(r.status), "bad");
    r.has_pubkey = true;
    r.height = -2;
    r.updated_height = -3;
    bool refused = !db_onion_directory_validate(&r, &e);
    OM_CHECK("five bad fields give five messages in field order",
             refused && e.count == 5 &&
             strncmp(e.messages[0], "hostname ", 9) == 0 &&
             strncmp(e.messages[1], "status ", 7) == 0 &&
             strncmp(e.messages[2], "master_pubkey ", 14) == 0 &&
             strncmp(e.messages[3], "height ", 7) == 0 &&
             strncmp(e.messages[4], "updated_height ", 15) == 0);
    return failures;
}

/* ── 2. save / find ───────────────────────────────────────────────── */

static int om_roundtrip(struct node_db *ndb)
{
    int failures = 0;
    struct db_onion_directory r, got;
    om_row(&r, 'b', 2147483640, ONION_DIRECTORY_STATUS_RETIRED);
    r.updated_height = 2147483647;
    memset(r.owner_address, 'o', ONION_DIRECTORY_ADDRESS_MAX - 1);
    for (int i = 0; i < 32; i++)
        r.master_pubkey[i] = (uint8_t)(0xa0 + i);
    r.has_pubkey = true;

    memset(&got, 0xff, sizeof(got));
    bool ok = db_onion_directory_save(ndb, &r) &&
              db_onion_directory_find(ndb, r.hostname, &got);
    OM_CHECK("save then find returns the 7 columns",
             ok && strcmp(got.hostname, r.hostname) == 0 &&
             memcmp(got.txid, r.txid, 32) == 0 &&
             got.height == 2147483640 && got.updated_height == 2147483647 &&
             strcmp(got.owner_address, r.owner_address) == 0 &&
             strlen(got.owner_address) == ONION_DIRECTORY_ADDRESS_MAX - 1 &&
             got.has_pubkey &&
             memcmp(got.master_pubkey, r.master_pubkey, 32) == 0 &&
             strcmp(got.status, "retired") == 0);

    struct db_onion_directory again = r;
    again.height = 11;
    again.updated_height = 12;
    again.owner_address[0] = '\0';
    again.has_pubkey = false;
    memset(again.master_pubkey, 0, 32);
    snprintf(again.status, sizeof(again.status), "active");
    memset(&got, 0xff, sizeof(got));
    ok = db_onion_directory_save(ndb, &again) &&
         db_onion_directory_count(ndb) == 1 &&
         db_onion_directory_find(ndb, r.hostname, &got);
    OM_CHECK("a second save REPLACEs the row on its hostname key",
             ok && got.height == 11 && got.updated_height == 12 &&
             got.owner_address[0] == '\0' && !got.has_pubkey &&
             strcmp(got.status, "active") == 0);
    OM_CHECK("empty owner and no key are stored as NULL",
             om_count_sql(ndb, "SELECT COUNT(*) FROM onion_directory WHERE "
                               "owner_address IS NULL AND "
                               "master_pubkey IS NULL") == 1);
    OM_CHECK("a present owner and key are stored non-NULL",
             db_onion_directory_save(ndb, &r) &&
             om_count_sql(ndb, "SELECT COUNT(*) FROM onion_directory WHERE "
                               "owner_address IS NOT NULL AND "
                               "master_pubkey IS NOT NULL AND "
                               "length(txid)=32 AND "
                               "length(master_pubkey)=32") == 1);
    return failures;
}

static int om_find_edges(struct node_db *ndb)
{
    int failures = 0;
    struct db_onion_directory got;
    char miss[64];
    om_host(miss, sizeof(miss), 'z');
    memset(&got, 0xff, sizeof(got));
    OM_CHECK("find misses leave out untouched",
             !db_onion_directory_find(ndb, miss, &got) &&
             got.height == -1 && got.hostname[0] == (char)0xff);
    OM_CHECK("find refuses an empty or NULL hostname and a NULL out",
             !db_onion_directory_find(ndb, "", &got) &&
             !db_onion_directory_find(ndb, NULL, &got) &&
             !db_onion_directory_find(ndb, miss, NULL));
    om_host(miss, sizeof(miss), 'b');
    OM_CHECK("find with a NULL out does not hit even a stored host",
             !db_onion_directory_find(ndb, miss, NULL));
    return failures;
}

/* A handle that says it is closed is refused before any write or read. */
static int om_closed_handle(struct node_db *ndb)
{
    int failures = 0;
    struct db_onion_directory r, got, page[2];
    om_row(&r, 'd', 3, ONION_DIRECTORY_STATUS_ACTIVE);
    int64_t before = db_onion_directory_count(ndb);

    ndb->open = false;
    bool saved = db_onion_directory_save(ndb, &r);
    bool found = db_onion_directory_find(ndb, r.hostname, &got);
    int listed = db_onion_directory_list_active(ndb, page, 2, 0);
    int64_t counted = db_onion_directory_count(ndb);
    int64_t by = db_onion_directory_count_by_status(ndb, "active");
    bool trunc = db_onion_directory_truncate(ndb);
    ndb->open = true;

    OM_CHECK("closed handle: save/find/list/count/truncate all refuse",
             !saved && !found && listed == 0 && counted == 0 && by == 0 &&
             !trunc);
    OM_CHECK("closed handle: nothing was written or deleted",
             db_onion_directory_count(ndb) == before && before > 0);
    OM_CHECK("NULL handle: save, find, list, count, truncate refuse",
             !db_onion_directory_save(NULL, &r) &&
             !db_onion_directory_find(NULL, r.hostname, &got) &&
             db_onion_directory_list_active(NULL, page, 2, 0) == 0 &&
             db_onion_directory_count(NULL) == 0 &&
             db_onion_directory_count_by_status(NULL, "active") == 0 &&
             !db_onion_directory_truncate(NULL));
    OM_CHECK("save refuses a NULL row", !db_onion_directory_save(ndb, NULL));
    return failures;
}

/* ── 3. list_active ───────────────────────────────────────────────── */

static int om_list_fixture(struct node_db *ndb)
{
    struct db_onion_directory r;
    /* Saved newest-first and hostname-descending so insertion order can
     * not produce the expected order by accident. */
    const struct { char c; int32_t h; const char *st; } rows[] = {
        { 'g', 9, "active" }, { 'f', 5, "active" }, { 'e', 5, "active" },
        { 'd', 3, "active" }, { 'h', 1, "retired" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        om_row(&r, rows[i].c, rows[i].h, rows[i].st);
        if (!db_onion_directory_save(ndb, &r)) return 0;
    }
    return 1;
}

static int om_list_active(struct node_db *ndb)
{
    int failures = 0;
    struct db_onion_directory page[8];
    char e5[64], f5[64], d3[64], g9[64];
    om_host(d3, sizeof(d3), 'd');
    om_host(e5, sizeof(e5), 'e');
    om_host(f5, sizeof(f5), 'f');
    om_host(g9, sizeof(g9), 'g');

    OM_CHECK("list fixture saved", om_list_fixture(ndb));
    memset(page, 0, sizeof(page));
    int n = db_onion_directory_list_active(ndb, page, 8, 0);
    OM_CHECK("active rows by height ASC then hostname ASC, retired skipped",
             n == 4 && strcmp(page[0].hostname, d3) == 0 &&
             strcmp(page[1].hostname, e5) == 0 &&
             strcmp(page[2].hostname, f5) == 0 &&
             strcmp(page[3].hostname, g9) == 0);
    OM_CHECK("every listed row carries all its columns",
             page[0].height == 3 && page[0].updated_height == 10 &&
             page[0].txid[0] == 1 && page[0].txid[31] == 32 &&
             strcmp(page[0].status, "active") == 0);

    memset(page, 0, sizeof(page));
    n = db_onion_directory_list_active(ndb, page, 2, 1);
    OM_CHECK("max=2 offset=1 is the second and third rows",
             n == 2 && strcmp(page[0].hostname, e5) == 0 &&
             strcmp(page[1].hostname, f5) == 0);
    memset(page, 0, sizeof(page));
    n = db_onion_directory_list_active(ndb, page, 8, 3);
    OM_CHECK("offset 3 leaves exactly the last row",
             n == 1 && strcmp(page[0].hostname, g9) == 0);
    OM_CHECK("offset past the end is an empty page",
             db_onion_directory_list_active(ndb, page, 8, 4) == 0);

    memset(page, 0xee, sizeof(page));
    n = db_onion_directory_list_active(ndb, page, 3, 0);
    OM_CHECK("max bounds the page and nothing is written past it",
             n == 3 && page[3].height == (int32_t)0xeeeeeeee &&
             page[3].hostname[0] == (char)0xee);
    OM_CHECK("max=1 returns exactly one row",
             db_onion_directory_list_active(ndb, page, 1, 0) == 1 &&
             page[0].height == 3);
    OM_CHECK("max 0 / -1, offset -1 and a NULL out are empty",
             db_onion_directory_list_active(ndb, page, 0, 0) == 0 &&
             db_onion_directory_list_active(ndb, page, -1, 0) == 0 &&
             db_onion_directory_list_active(ndb, page, 8, -1) == 0 &&
             db_onion_directory_list_active(ndb, NULL, 8, 0) == 0);
    return failures;
}

/* ── 4. counts, truncate, missing table ───────────────────────────── */

static int om_counts_truncate(struct node_db *ndb)
{
    int failures = 0;
    OM_CHECK("count is every row", db_onion_directory_count(ndb) == 6);
    OM_CHECK("count by status splits active / retired",
             db_onion_directory_count_by_status(ndb, "active") == 4 &&
             db_onion_directory_count_by_status(ndb, "retired") == 2);
    OM_CHECK("count by an unknown, empty or NULL status is 0",
             db_onion_directory_count_by_status(ndb, "bogus") == 0 &&
             db_onion_directory_count_by_status(ndb, "") == 0 &&
             db_onion_directory_count_by_status(ndb, NULL) == 0);
    return failures;
}

static int om_missing_table(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("onion_directory model: open scratch db... FAIL\n");
        return 1;
    }
    struct db_onion_directory r, got, page[2];
    om_row(&r, 'b', 1, ONION_DIRECTORY_STATUS_ACTIVE);
    bool dropped = node_db_exec(&ndb, "DROP TABLE onion_directory");
    OM_CHECK("scratch table dropped", dropped);
    OM_CHECK("with the table gone every operation fails closed",
             !db_onion_directory_save(&ndb, &r) &&
             !db_onion_directory_find(&ndb, r.hostname, &got) &&
             db_onion_directory_list_active(&ndb, page, 2, 0) == 0 &&
             db_onion_directory_count(&ndb) == 0 &&
             db_onion_directory_count_by_status(&ndb, "active") == 0 &&
             !db_onion_directory_truncate(&ndb));
    node_db_close(&ndb);
    return failures;
}

/* ── 5. dump_state_json ───────────────────────────────────────────── */

static void om_hex(const uint8_t *p, char *out)
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", p[i]);
}

static int om_dump_totals(void)
{
    int failures = 0;
    struct json_value v = {0};
    OM_CHECK("dump refuses a NULL out",
             !onion_directory_dump_state_json(NULL, NULL));

    app_runtime_set_current(NULL);
    OM_CHECK("no runtime: totals dump reports db_open false and zeros",
             onion_directory_dump_state_json(&v, NULL) &&
             !json_get_bool(json_get(&v, "db_open")) &&
             json_get_int(json_get(&v, "total_rows")) == 0 &&
             json_get_int(json_get(&v, "active_rows")) == 0 &&
             json_get_int(json_get(&v, "retired_rows")) == 0 &&
             json_get(&v, "key") == NULL);
    json_free(&v);

    memset(&v, 0, sizeof(v));
    OM_CHECK("no runtime: a keyed dump echoes the key, found false",
             onion_directory_dump_state_json(&v, "somekey") &&
             !json_get_bool(json_get(&v, "db_open")) &&
             strcmp(json_get_str(json_get(&v, "key")), "somekey") == 0 &&
             !json_get_bool(json_get(&v, "found")) &&
             json_get(&v, "total_rows") == NULL);
    json_free(&v);
    return failures;
}

struct om_live {
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context rt;
    bool db_up;
    bool svc_up;
};

static void om_live_close(struct om_live *x)
{
    app_runtime_set_current(NULL);
    if (x->svc_up) db_service_stop(&x->svc);
    if (x->db_up) node_db_close(&x->ndb);
}

static int om_dump_live(struct om_live *x)
{
    int failures = 0;
    struct db_onion_directory a, b;
    om_row(&a, 'a', 40, ONION_DIRECTORY_STATUS_ACTIVE);
    snprintf(a.owner_address, sizeof(a.owner_address), "t1owner");
    for (int i = 0; i < 32; i++)
        a.master_pubkey[i] = (uint8_t)(0x10 + i);
    a.has_pubkey = true;
    om_row(&b, 'b', 41, ONION_DIRECTORY_STATUS_RETIRED);
    OM_CHECK("live fixture rows saved",
             db_onion_directory_save(&x->ndb, &a) &&
             db_onion_directory_save(&x->ndb, &b));

    struct json_value v = {0};
    bool ok = onion_directory_dump_state_json(&v, "");
    OM_CHECK("live totals: db_open, total 2, active 1, retired 1",
             ok && json_get_bool(json_get(&v, "db_open")) &&
             json_get_int(json_get(&v, "total_rows")) == 2 &&
             json_get_int(json_get(&v, "active_rows")) == 1 &&
             json_get_int(json_get(&v, "retired_rows")) == 1 &&
             json_get(&v, "found") == NULL);
    json_free(&v);

    char txhex[65], pkhex[65];
    om_hex(a.txid, txhex);
    om_hex(a.master_pubkey, pkhex);
    memset(&v, 0, sizeof(v));
    ok = onion_directory_dump_state_json(&v, a.hostname);
    OM_CHECK("keyed dump of a keyed row: every field, key as lowercase hex",
             ok && json_get_bool(json_get(&v, "found")) &&
             strcmp(json_get_str(json_get(&v, "hostname")), a.hostname) == 0 &&
             strcmp(json_get_str(json_get(&v, "txid")), txhex) == 0 &&
             json_get_int(json_get(&v, "height")) == 40 &&
             strcmp(json_get_str(json_get(&v, "owner_address")),
                    "t1owner") == 0 &&
             strcmp(json_get_str(json_get(&v, "master_pubkey")), pkhex) == 0 &&
             strcmp(json_get_str(json_get(&v, "status")), "active") == 0 &&
             json_get_int(json_get(&v, "updated_height")) == 47 &&
             json_get(&v, "total_rows") == NULL);
    json_free(&v);
    return failures;
}

static int om_dump_live_misses(struct om_live *x)
{
    int failures = 0;
    struct db_onion_directory b;
    om_row(&b, 'b', 41, ONION_DIRECTORY_STATUS_RETIRED);
    struct json_value v = {0};
    bool ok = onion_directory_dump_state_json(&v, b.hostname);
    OM_CHECK("keyed dump of a keyless row omits master_pubkey",
             ok && json_get_bool(json_get(&v, "found")) &&
             json_get(&v, "master_pubkey") == NULL &&
             strcmp(json_get_str(json_get(&v, "status")), "retired") == 0);
    json_free(&v);

    char miss[64];
    om_host(miss, sizeof(miss), 'y');
    memset(&v, 0, sizeof(v));
    ok = onion_directory_dump_state_json(&v, miss);
    OM_CHECK("keyed dump of an unknown host: found false, no row fields",
             ok && json_get_bool(json_get(&v, "db_open")) &&
             !json_get_bool(json_get(&v, "found")) &&
             json_get(&v, "hostname") == NULL &&
             json_get(&v, "txid") == NULL);
    json_free(&v);
    (void)x;
    return failures;
}

static int om_dump_state(void)
{
    int failures = om_dump_totals();
    struct om_live x;
    memset(&x, 0, sizeof(x));
    x.db_up = node_db_open(&x.ndb, ":memory:") && x.ndb.open;
    if (!x.db_up) {
        printf("onion_directory model: open live db... FAIL\n");
        return failures + 1;
    }
    db_service_init(&x.svc);
    x.svc_up = db_service_attach(&x.svc, &x.ndb) &&
               db_service_start_test_worker(&x.svc);
    if (!x.svc_up) {
        printf("onion_directory model: start db service... FAIL\n");
        om_live_close(&x);
        return failures + 1;
    }
    x.rt.db_service = &x.svc;
    app_runtime_set_current(&x.rt);
    failures += om_dump_live(&x);
    failures += om_dump_live_misses(&x);
    om_live_close(&x);
    return failures;
}

/* ── Sub-test entry point ─────────────────────────────────────────
 * Named for its subject, not its file: a filename-matching name would be a
 * test-registration entry point. Dispatched from the `onion_directory`
 * group in test_onion_directory.c. */
int od_model_contract(void);

int od_model_contract(void)
{
    int failures = 0;
    failures += om_validate_fields();
    failures += om_validate_key_and_all();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("onion_directory model: open in-memory db... FAIL\n");
        return failures + 1;
    }
    failures += om_roundtrip(&ndb);
    failures += om_find_edges(&ndb);
    failures += om_closed_handle(&ndb);
    failures += om_list_active(&ndb);
    failures += om_counts_truncate(&ndb);
    OM_CHECK("truncate empties the table and says so",
             db_onion_directory_truncate(&ndb) &&
             db_onion_directory_count(&ndb) == 0 &&
             db_onion_directory_count_by_status(&ndb, "active") == 0);
    node_db_close(&ndb);

    failures += om_missing_table();
    failures += om_dump_state();
    return failures;
}
