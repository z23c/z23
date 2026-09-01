/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the sovereign-identity anchor projection (zid_identities):
 *
 *  1. Schema: the v37 migration lands the table + both indexes, and the
 *     open db reports NODE_DB_MAX_SCHEMA.
 *  2. save/find round-trip: every field survives a write/read cycle,
 *     including the NULL-column forms (no successor, no name, no owner)
 *     and a re-save overwriting in place on the master_pubkey key.
 *  3. Validation rejections: each bad status literal, each bad source
 *     literal, successor present without status=='rotated', status
 *     'rotated' with no successor, an all-zero successor, and negative
 *     heights. A rejected row must not reach the table.
 *  4. find_by_name: resolves a znam_text row by its name, misses on an
 *     unknown name, and misses on a row that has no name.
 *  5. list paging: newest-anchor-first, max caps the page, offset walks
 *     it, and a bad page (max<=0 / offset<0) yields 0.
 *  6. The dumper emits a well-formed object: totals with no key, and a
 *     resolved identity for both key forms (64-hex pubkey, ZNAM name).
 *     It resolves through app_runtime_node_db(), so (6) stands up its own
 *     file-backed node.db + db_service and installs it as the process
 *     runtime context — otherwise the resolve branches never execute. */

#include "test/test_core.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "models/explorer_index.h"
#include "models/znam.h"
#include "config/runtime.h"
#include "config/db_service.h"
#include "json/json.h"
#include "overlay/overlay_projection.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "zid/zid_anchor.h"
#include "znam/znam.h"
#include "zanc/zanc.h"
#include "zslp/slp.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── Helpers ──────────────────────────────────────────────────────── */

static int count_rows(struct node_db *ndb, const char *sql)
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

static void mk_row(struct zid_identity *r, uint8_t seed, int32_t height,
                   const char *status, const char *source, const char *name)
{
    memset(r, 0, sizeof(*r));
    memset(r->master_pubkey, seed, 32);
    memset(r->anchor_txid, (uint8_t)(seed ^ 0xa5), 32);
    r->anchor_height = height;
    r->updated_height = height;
    snprintf(r->status, sizeof(r->status), "%s", status);
    snprintf(r->source, sizeof(r->source), "%s", source);
    if (name) snprintf(r->name, sizeof(r->name), "%s", name);
}

static void hex32(const uint8_t *b, char out[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hx[b[i] >> 4];
        out[i * 2 + 1] = hx[b[i] & 0x0f];
    }
    out[64] = '\0';
}

/* ── (1)+(2) schema, save/find round-trip ─────────────────────────── */

static int test_schema_and_roundtrip(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("zid_identity: open in-memory node.db (schema v%d)... ",
           NODE_DB_MAX_SCHEMA);
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("zid_identity: schema_version is %d... ", NODE_DB_MAX_SCHEMA);
    { int v = node_db_schema_version(&ndb);
      if (v == NODE_DB_MAX_SCHEMA) printf("OK\n");
      else { printf("FAIL (got %d)\n", v); failures++; } }

    printf("zid_identity: v37 created zid_identities... ");
    { int n = count_rows(&ndb,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        " AND name='zid_identities'");
      if (n == 1) printf("OK\n");
      else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("zid_identity: name + anchor_height indexes exist... ");
    { int n = count_rows(&ndb,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
        " AND name IN ('idx_zid_identities_name',"
        "              'idx_zid_identities_height')");
      if (n == 2) printf("OK\n");
      else { printf("FAIL (got %d)\n", n); failures++; } }

    /* Full-field row: rotated, znam_text, named, with an owner. */
    struct zid_identity r;
    mk_row(&r, 0x11, 1000, ZID_IDENTITY_STATUS_ROTATED,
           ZID_IDENTITY_SOURCE_ZNAM_TEXT, "alice");
    memset(r.successor_pubkey, 0x22, 32);
    r.has_successor = true;
    snprintf(r.owner_address, sizeof(r.owner_address),
             "t1KpuGw6vqrARbCsRWcxNBQGGXpiCDeqZuS");
    r.updated_height = 1500;

    printf("zid_identity: save a full rotated/znam_text row... ");
    if (db_zid_identity_save(&ndb, &r)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_identity: find round-trips every field... ");
    { struct zid_identity got;
      memset(&got, 0xff, sizeof(got));
      bool ok = db_zid_identity_find(&ndb, r.master_pubkey, &got) &&
                memcmp(got.master_pubkey, r.master_pubkey, 32) == 0 &&
                memcmp(got.anchor_txid, r.anchor_txid, 32) == 0 &&
                got.anchor_height == 1000 &&
                got.updated_height == 1500 &&
                strcmp(got.status, ZID_IDENTITY_STATUS_ROTATED) == 0 &&
                got.has_successor &&
                memcmp(got.successor_pubkey, r.successor_pubkey, 32) == 0 &&
                strcmp(got.source, ZID_IDENTITY_SOURCE_ZNAM_TEXT) == 0 &&
                strcmp(got.name, "alice") == 0 &&
                strcmp(got.owner_address, r.owner_address) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* Minimal row: active, zid_overlay, no name / owner / successor. */
    struct zid_identity m;
    mk_row(&m, 0x33, 42, ZID_IDENTITY_STATUS_ACTIVE,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);

    printf("zid_identity: save a minimal overlay row (NULL columns)... ");
    if (db_zid_identity_save(&ndb, &m)) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_identity: NULL successor/name/owner read back empty... ");
    { struct zid_identity got;
      memset(&got, 0xff, sizeof(got));
      bool ok = db_zid_identity_find(&ndb, m.master_pubkey, &got) &&
                !got.has_successor && got.name[0] == '\0' &&
                got.owner_address[0] == '\0' &&
                strcmp(got.status, ZID_IDENTITY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: find misses on an unknown pubkey... ");
    { uint8_t unknown[32];
      memset(unknown, 0x99, 32);
      struct zid_identity got;
      bool ok = !db_zid_identity_find(&ndb, unknown, &got);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: re-save overwrites in place (PK master_pubkey)... ");
    { struct zid_identity up = m;
      snprintf(up.status, sizeof(up.status), "%s",
               ZID_IDENTITY_STATUS_REVOKED);
      up.updated_height = 4242;
      struct zid_identity got;
      bool ok = db_zid_identity_save(&ndb, &up) &&
                db_zid_identity_count(&ndb) == 2 &&
                db_zid_identity_find(&ndb, m.master_pubkey, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_REVOKED) == 0 &&
                got.updated_height == 4242;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: count_by_status splits the table... ");
    { bool ok = db_zid_identity_count(&ndb) == 2 &&
                db_zid_identity_count_by_status(
                    &ndb, ZID_IDENTITY_STATUS_ROTATED) == 1 &&
                db_zid_identity_count_by_status(
                    &ndb, ZID_IDENTITY_STATUS_REVOKED) == 1 &&
                db_zid_identity_count_by_status(
                    &ndb, ZID_IDENTITY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: truncate empties the rebuildable projection... ");
    { bool ok = db_zid_identity_truncate(&ndb) &&
                db_zid_identity_count(&ndb) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── (3) validation rejections ────────────────────────────────────── */

static int zid_validation_cases(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zid_identity validation: open FAIL\n");
        return 1;
    }

    struct ar_errors errs;
    struct zid_identity r;

    printf("zid_identity validate: NULL row rejected... ");
    { bool ok = !db_zid_identity_validate(NULL, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: active/znam_text accepted... ");
    mk_row(&r, 0x01, 10, ZID_IDENTITY_STATUS_ACTIVE,
           ZID_IDENTITY_SOURCE_ZNAM_TEXT, "bob");
    { bool ok = db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: revoked/zid_overlay accepted... ");
    mk_row(&r, 0x02, 10, ZID_IDENTITY_STATUS_REVOKED,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    { bool ok = db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: rotated + successor accepted... ");
    mk_row(&r, 0x03, 10, ZID_IDENTITY_STATUS_ROTATED,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    memset(r.successor_pubkey, 0x7e, 32);
    r.has_successor = true;
    { bool ok = db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: unknown status rejected... ");
    mk_row(&r, 0x04, 10, "expired", ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: empty status rejected... ");
    mk_row(&r, 0x05, 10, "", ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: unknown source rejected... ");
    mk_row(&r, 0x06, 10, ZID_IDENTITY_STATUS_ACTIVE, "hearsay", NULL);
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: empty source rejected... ");
    mk_row(&r, 0x07, 10, ZID_IDENTITY_STATUS_ACTIVE, "", NULL);
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: rotated WITHOUT successor rejected... ");
    mk_row(&r, 0x08, 10, ZID_IDENTITY_STATUS_ROTATED,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: active WITH successor rejected... ");
    mk_row(&r, 0x09, 10, ZID_IDENTITY_STATUS_ACTIVE,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    memset(r.successor_pubkey, 0x5c, 32);
    r.has_successor = true;
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: revoked WITH successor rejected... ");
    mk_row(&r, 0x0a, 10, ZID_IDENTITY_STATUS_REVOKED,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    memset(r.successor_pubkey, 0x5c, 32);
    r.has_successor = true;
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: all-zero successor rejected... ");
    mk_row(&r, 0x0b, 10, ZID_IDENTITY_STATUS_ROTATED,
           ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
    r.has_successor = true;  /* successor_pubkey left all-zero */
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: negative anchor_height rejected... ");
    mk_row(&r, 0x0c, 10, ZID_IDENTITY_STATUS_ACTIVE,
           ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
    r.anchor_height = -1;
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity validate: negative updated_height rejected... ");
    mk_row(&r, 0x0d, 10, ZID_IDENTITY_STATUS_ACTIVE,
           ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
    r.updated_height = -7;
    { bool ok = !db_zid_identity_validate(&r, &errs);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: an invalid row never reaches the table... ");
    { mk_row(&r, 0x0e, 10, "bogus", ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
      bool ok = !db_zid_identity_save(&ndb, &r) &&
                db_zid_identity_count(&ndb) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: save on a closed db fails loudly... ");
    { struct node_db closed;
      memset(&closed, 0, sizeof(closed));
      mk_row(&r, 0x0f, 10, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZNAM_TEXT, NULL);
      bool ok = !db_zid_identity_save(&closed, &r) &&
                !db_zid_identity_save(&ndb, NULL);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── (4)+(5) find_by_name, list paging ────────────────────────────── */

static int test_resolve_and_paging(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zid_identity resolve: open FAIL\n");
        return 1;
    }

    /* Four named znam_text rows at ascending heights + one unnamed. */
    static const char *names[4] = {"alpha", "bravo", "charlie", "delta"};
    for (int i = 0; i < 4; i++) {
        struct zid_identity r;
        mk_row(&r, (uint8_t)(0x40 + i), 100 + i, ZID_IDENTITY_STATUS_ACTIVE,
               ZID_IDENTITY_SOURCE_ZNAM_TEXT, names[i]);
        if (!db_zid_identity_save(&ndb, &r)) failures++;
    }
    { struct zid_identity r;
      mk_row(&r, 0x50, 5, ZID_IDENTITY_STATUS_ACTIVE,
             ZID_IDENTITY_SOURCE_ZID_OVERLAY, NULL);
      if (!db_zid_identity_save(&ndb, &r)) failures++; }

    printf("zid_identity: 5 rows seeded... ");
    { int64_t n = db_zid_identity_count(&ndb);
      if (n == 5) printf("OK\n");
      else { printf("FAIL (got %lld)\n", (long long)n); failures++; } }

    printf("zid_identity: find_by_name resolves a znam_text row... ");
    { struct zid_identity got;
      bool ok = db_zid_identity_find_by_name(&ndb, "charlie", &got) &&
                got.anchor_height == 102 &&
                strcmp(got.name, "charlie") == 0 &&
                got.master_pubkey[0] == 0x42;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: find_by_name misses an unknown name... ");
    { struct zid_identity got;
      bool ok = !db_zid_identity_find_by_name(&ndb, "nobody", &got);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: find_by_name rejects NULL/empty name... ");
    { struct zid_identity got;
      bool ok = !db_zid_identity_find_by_name(&ndb, NULL, &got) &&
                !db_zid_identity_find_by_name(&ndb, "", &got);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity: list is newest-anchor-first... ");
    { struct zid_identity page[8];
      int n = db_zid_identity_list(&ndb, page, 8, 0);
      bool ok = n == 5 &&
                page[0].anchor_height == 103 &&
                page[1].anchor_height == 102 &&
                page[2].anchor_height == 101 &&
                page[3].anchor_height == 100 &&
                page[4].anchor_height == 5;
      if (ok) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zid_identity: list max caps the page... ");
    { struct zid_identity page[8];
      int n = db_zid_identity_list(&ndb, page, 2, 0);
      bool ok = n == 2 && page[0].anchor_height == 103 &&
                page[1].anchor_height == 102;
      if (ok) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zid_identity: list offset walks the page... ");
    { struct zid_identity page[8];
      int n = db_zid_identity_list(&ndb, page, 2, 2);
      bool ok = n == 2 && page[0].anchor_height == 101 &&
                page[1].anchor_height == 100;
      if (ok) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zid_identity: list past the end returns 0... ");
    { struct zid_identity page[8];
      int n = db_zid_identity_list(&ndb, page, 4, 99);
      if (n == 0) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zid_identity: list rejects a bad page (max<=0, offset<0)... ");
    { struct zid_identity page[8];
      bool ok = db_zid_identity_list(&ndb, page, 0, 0) == 0 &&
                db_zid_identity_list(&ndb, page, -1, 0) == 0 &&
                db_zid_identity_list(&ndb, page, 4, -1) == 0 &&
                db_zid_identity_list(&ndb, NULL, 4, 0) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── (6) the state dumper ─────────────────────────────────────────── */

static int test_dumper(void)
{
    int failures = 0;

    printf("zid_identity dump: rejects a NULL out... ");
    { bool ok = !zid_identity_dump_state_json(NULL, NULL);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* The dumper resolves through app_runtime_node_db(), so wire a real
     * runtime handle at this test's own file-backed node.db — otherwise the
     * resolve branches never execute and this group proves only shape. */
    char dir[256];
    char dbpath[320];
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    test_make_tmpdir(dir, sizeof(dir), "zid_identity", "dump");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    memset(&ndb, 0, sizeof(ndb));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));

    bool wired = node_db_open(&ndb, dbpath) && ndb.open;
    if (wired) {
        db_service_init(&dbsvc);
        wired = db_service_attach(&dbsvc, &ndb) && db_service_start(&dbsvc);
    }
    if (wired) {
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);
    }

    printf("zid_identity dump: runtime node.db wired... ");
    if (wired && app_runtime_node_db() == &ndb) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("zid_identity dump: no key emits a well-formed totals object... ");
    { struct json_value out;
      json_init(&out);
      bool ok = zid_identity_dump_state_json(&out, NULL) &&
                out.type == JSON_OBJ &&
                json_get(&out, "db_open") != NULL &&
                json_get(&out, "total_rows") != NULL &&
                json_get(&out, "active_rows") != NULL &&
                json_get(&out, "rotated_rows") != NULL &&
                json_get(&out, "revoked_rows") != NULL &&
                json_get(&out, "found") == NULL;
      json_free(&out);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid_identity dump: a key form always reports found... ");
    { struct json_value out;
      json_init(&out);
      bool ok = zid_identity_dump_state_json(&out, "alpha") &&
                out.type == JSON_OBJ &&
                json_get(&out, "key") != NULL &&
                json_get(&out, "found") != NULL;
      json_free(&out);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    struct node_db *rt = app_runtime_node_db();
    if (rt && rt->open) {
        struct zid_identity r;
        mk_row(&r, 0x71, 777, ZID_IDENTITY_STATUS_ACTIVE,
               ZID_IDENTITY_SOURCE_ZNAM_TEXT, "dumpername");
        bool seeded = db_zid_identity_save(rt, &r);

        char pk_hex[65];
        hex32(r.master_pubkey, pk_hex);

        printf("zid_identity dump: 64-hex pubkey key resolves the row... ");
        { struct json_value out;
          json_init(&out);
          bool ok = seeded && zid_identity_dump_state_json(&out, pk_hex) &&
                    json_get_bool(json_get(&out, "found")) &&
                    json_get(&out, "master_pubkey") != NULL &&
                    json_get(&out, "anchor_txid") != NULL &&
                    json_get_int(json_get(&out, "anchor_height")) == 777 &&
                    json_get(&out, "successor_pubkey") == NULL;
          json_free(&out);
          if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

        printf("zid_identity dump: ZNAM-name key resolves the row... ");
        { struct json_value out;
          json_init(&out);
          bool ok = seeded &&
                    zid_identity_dump_state_json(&out, "dumpername") &&
                    json_get_bool(json_get(&out, "found")) &&
                    json_get_int(json_get(&out, "updated_height")) == 777;
          json_free(&out);
          if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

        printf("zid_identity dump: totals count the seeded row... ");
        { struct json_value out;
          json_init(&out);
          bool ok = seeded && zid_identity_dump_state_json(&out, NULL) &&
                    json_get_int(json_get(&out, "total_rows")) >= 1 &&
                    json_get_int(json_get(&out, "active_rows")) >= 1;
          json_free(&out);
          if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

        printf("zid_identity dump: an unknown key reports found=false... ");
        { struct json_value out;
          json_init(&out);
          bool ok = zid_identity_dump_state_json(&out, "no-such-name") &&
                    json_get(&out, "found") != NULL &&
                    !json_get_bool(json_get(&out, "found")) &&
                    json_get(&out, "master_pubkey") == NULL;
          json_free(&out);
          if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

        db_zid_identity_truncate(rt);
    } else {
        printf("zid_identity dump: runtime resolve asserts... FAIL (no db)\n");
        failures++;
    }

    if (wired) {
        app_runtime_set_current(NULL);
        db_service_stop(&dbsvc);
    }
    if (ndb.open) node_db_close(&ndb);
    test_rm_rf(dir);
    return failures;
}

/* ── (7) chain ingestion: the overlay registry + both ZID feeds ──────
 *
 * Everything below drives the REAL per-block indexer (explorer_index_block)
 * over synthetic one-tx blocks against an in-memory node.db — the only honest
 * way to prove the registry dispatch and the projections that hang off it.
 * Harness pattern borrowed from test_explorer_index.c. */

/* Seed a spendable tx_output owned by `addr20` at outpoint (prevbyte×32, n),
 * so a later tx spending it resolves that address as its signer. */
static void seed_owner_utxo(struct node_db *ndb, uint8_t prevbyte, uint32_t n,
                            const uint8_t addr20[20], int height)
{
    uint8_t txid[32];
    memset(txid, prevbyte, 32);
    db_tx_output_save(ndb, txid, n, 5 * COIN, 0, addr20, height);
}

/* Build a one-tx block spending outpoint (prevbyte×32, prevn) whose sole
 * output is `script` (a full OP_RETURN scriptPubKey), and run the per-block
 * indexer at `height`. */
static bool run_op(struct node_db *ndb, const uint8_t *script, size_t slen,
                   uint8_t prevbyte, uint32_t prevn, int height)
{
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 1);
    memset(tx.vin[0].prevout.hash.data, prevbyte, 32);
    tx.vin[0].prevout.n = prevn;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;
    tx.vout[0].value = 0;
    memcpy(tx.vout[0].script_pub_key.data, script, slen);
    tx.vout[0].script_pub_key.size = slen;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)height;

    struct uint256 bhash;
    memset(bhash.data, 0x60, 32);
    bhash.data[0] = (uint8_t)height;
    bhash.data[1] = (uint8_t)(height >> 8);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

/* The registry is the single enumeration of every on-chain overlay. */
static int test_overlay_registry_adopted(void)
{
    int failures = 0;
    const struct overlay_registry *reg = explorer_index_overlays();

    printf("zid ingest: registry holds every overlay... ");
    { bool ok = reg != NULL && overlay_registry_count(reg) == 5;
      if (ok) printf("OK\n");
      else { printf("FAIL (count=%zu)\n",
                    reg ? overlay_registry_count(reg) : (size_t)0);
             failures++; } }

    printf("zid ingest: each lokad resolves its descriptor... ");
    { bool ok = reg &&
                overlay_registry_find(reg, SLP_LOKAD_BYTES) != NULL &&
                overlay_registry_find(reg, ZNAM_LOKAD_BYTES) != NULL &&
                overlay_registry_find(reg, ZANC_LOKAD_BYTES) != NULL &&
                overlay_registry_find(reg, ZID_ANCHOR_LOKAD_BYTES) != NULL &&
                overlay_registry_find(reg, "ZZZZ") == NULL;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    return failures;
}

/* One block per lokad: dispatch must reach all four projections, and a
 * non-overlay OP_RETURN must touch none of them. */
static int test_dispatch_reaches_every_overlay(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zid ingest dispatch: open FAIL\n");
        return 1;
    }

    uint8_t owner[20];
    memset(owner, 0x31, 20);
    for (uint8_t i = 0; i < 5; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xD0 + i), 0, owner, 10);

    uint8_t buf[256];
    size_t len;

    printf("zid ingest: ZSLP lokad reaches the zslp projection... ");
    len = slp_build_genesis(buf, sizeof(buf), "TKN", "Token", NULL, NULL,
                            8, 0, 1000);
    run_op(&ndb, buf, len, 0xD0, 0, 400);
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_tokens");
      if (n == 1) printf("OK\n");
      else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("zid ingest: ZNAM lokad reaches the znam projection... ");
    len = znam_build_register(buf, sizeof(buf), "dispatchname",
                              ZNAM_TYPE_TADDR, "t1target");
    run_op(&ndb, buf, len, 0xD1, 0, 401);
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM znam_names");
      if (n == 1) printf("OK\n");
      else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("zid ingest: ZANC lokad reaches the zanc projection... ");
    { uint8_t digest[ZANC_DIGEST_LEN];
      memset(digest, 0x77, sizeof(digest));
      len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256, digest,
                              "label");
      run_op(&ndb, buf, len, 0xD2, 0, 402);
      int n = count_rows(&ndb, "SELECT COUNT(*) FROM zanc_anchors");
      if (n == 1) printf("OK\n");
      else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("zid ingest: ZID lokad reaches the zid projection... ");
    { uint8_t key[32];
      memset(key, 0x81, 32);
      len = zid_anchor_build_anchor(buf, sizeof(buf), key);
      run_op(&ndb, buf, len, 0xD3, 0, 403);
      int64_t n = db_zid_identity_count(&ndb);
      if (n == 1) printf("OK\n");
      else { printf("FAIL (got %lld)\n", (long long)n); failures++; } }

    /* A plain OP_RETURN matches no lokad: the op_returns row still lands,
     * and not one projection moves. */
    printf("zid ingest: non-overlay OP_RETURN is a clean no-op... ");
    { uint8_t plain[6] = {0x6a, 0x04, 'Z', 'Z', 'Z', 'Z'};
      int before_or = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns");
      run_op(&ndb, plain, sizeof(plain), 0xD4, 0, 404);
      bool ok = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns")
                    == before_or + 1 &&
                count_rows(&ndb, "SELECT COUNT(*) FROM zslp_tokens") == 1 &&
                count_rows(&ndb, "SELECT COUNT(*) FROM znam_names") == 1 &&
                count_rows(&ndb, "SELECT COUNT(*) FROM zanc_anchors") == 1 &&
                db_zid_identity_count(&ndb) == 1;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* Feed 2 — the dedicated ZID overlay: ANCHOR / ROTATE / REVOKE + the
 * owner-authorization refusals. */
static int test_zid_overlay_feed(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zid overlay feed: open FAIL\n");
        return 1;
    }

    uint8_t ownerA[20], attackerB[20];
    memset(ownerA, 0x41, 20);
    memset(attackerB, 0x42, 20);
    for (uint8_t i = 0; i < 6; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xE0 + i), 0, ownerA, 10);
    seed_owner_utxo(&ndb, 0xEF, 0, attackerB, 10);

    uint8_t k1[32], k2[32];
    memset(k1, 0x91, 32);
    memset(k2, 0x92, 32);
    uint8_t buf[128];
    size_t len;

    printf("zid overlay: ANCHOR projects an active row... ");
    len = zid_anchor_build_anchor(buf, sizeof(buf), k1);
    run_op(&ndb, buf, len, 0xE0, 0, 500);
    struct zid_identity r1;
    { bool ok = db_zid_identity_find(&ndb, k1, &r1) &&
                strcmp(r1.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
                strcmp(r1.source, ZID_IDENTITY_SOURCE_ZID_OVERLAY) == 0 &&
                r1.anchor_height == 500 && r1.updated_height == 500 &&
                !r1.has_successor && r1.owner_address[0] != '\0' &&
                r1.name[0] == '\0';
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* An unauthorized ROTATE is a logged no-op — never fatal, and it must
     * leave the standing identity untouched. */
    printf("zid overlay: ROTATE by a non-owner is refused... ");
    len = zid_anchor_build_rotate(buf, sizeof(buf), k1, k2);
    run_op(&ndb, buf, len, 0xEF, 0, 501);
    { struct zid_identity still, target;
      bool ok = db_zid_identity_find(&ndb, k1, &still) &&
                strcmp(still.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
                !still.has_successor &&
                still.updated_height == 500 &&
                !db_zid_identity_find(&ndb, k2, &target) &&
                db_zid_identity_count(&ndb) == 1;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid overlay: ROTATE by the owner supersedes the old key... ");
    len = zid_anchor_build_rotate(buf, sizeof(buf), k1, k2);
    run_op(&ndb, buf, len, 0xE1, 0, 502);
    { struct zid_identity old, new_row;
      bool ok = db_zid_identity_find(&ndb, k1, &old) &&
                strcmp(old.status, ZID_IDENTITY_STATUS_ROTATED) == 0 &&
                old.has_successor &&
                memcmp(old.successor_pubkey, k2, 32) == 0 &&
                old.anchor_height == 500 &&    /* the ANCHOR, not the rotate */
                old.updated_height == 502 &&
                db_zid_identity_find(&ndb, k2, &new_row) &&
                strcmp(new_row.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
                new_row.anchor_height == 502 &&
                db_zid_identity_count(&ndb) == 2;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid overlay: REVOKE by a non-owner is refused... ");
    len = zid_anchor_build_revoke(buf, sizeof(buf), k2);
    run_op(&ndb, buf, len, 0xEF, 1, 503);
    { struct zid_identity got;
      bool ok = db_zid_identity_find(&ndb, k2, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zid overlay: REVOKE by the owner retires the key... ");
    len = zid_anchor_build_revoke(buf, sizeof(buf), k2);
    run_op(&ndb, buf, len, 0xE2, 0, 504);
    { struct zid_identity got;
      bool ok = db_zid_identity_find(&ndb, k2, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_REVOKED) == 0 &&
                !got.has_successor && got.updated_height == 504;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* A revoked key stays dead: a fresh ANCHOR must not resurrect it. */
    printf("zid overlay: re-ANCHOR of a revoked key is refused... ");
    len = zid_anchor_build_anchor(buf, sizeof(buf), k2);
    run_op(&ndb, buf, len, 0xE3, 0, 505);
    { struct zid_identity got;
      bool ok = db_zid_identity_find(&ndb, k2, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_REVOKED) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* Re-walking a block must rewrite identical rows, not fork them. */
    printf("zid overlay: re-processing the ANCHOR block is idempotent... ");
    { struct node_db idb;
      memset(&idb, 0, sizeof(idb));
      bool ok = node_db_open(&idb, ":memory:") && idb.open;
      if (ok) {
          seed_owner_utxo(&idb, 0xC1, 0, ownerA, 10);
          uint8_t k[32];
          memset(k, 0xA7, 32);
          size_t n = zid_anchor_build_anchor(buf, sizeof(buf), k);
          run_op(&idb, buf, n, 0xC1, 0, 600);
          struct zid_identity first;
          ok = db_zid_identity_find(&idb, k, &first);
          run_op(&idb, buf, n, 0xC1, 0, 600);
          struct zid_identity again;
          ok = ok && db_zid_identity_find(&idb, k, &again) &&
               db_zid_identity_count(&idb) == 1 &&
               memcmp(&first, &again, sizeof(first)) == 0 &&
               count_rows(&idb, "SELECT COUNT(*) FROM op_returns") == 1;
          node_db_close(&idb);
      }
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* Feed 1 — the ZNAM "zid" text convention (this is the one that ships
 * first, so it must stand up with no ZID overlay involved at all). */
static int test_znam_zid_text_feed(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("znam zid text: open FAIL\n");
        return 1;
    }

    uint8_t ownerA[20];
    memset(ownerA, 0x51, 20);
    for (uint8_t i = 0; i < 10; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xF0 + i), 0, ownerA, 10);

    uint8_t buf[256];
    size_t len;
    char k1_hex[65], k2_hex[65];
    uint8_t k1[32], k2[32];
    memset(k1, 0xB1, 32);
    memset(k2, 0xB2, 32);
    hex32(k1, k1_hex);
    hex32(k2, k2_hex);

    len = znam_build_register(buf, sizeof(buf), "zidname", ZNAM_TYPE_TADDR,
                              "t1zidowner");
    run_op(&ndb, buf, len, 0xF0, 0, 700);

    printf("znam zid text: SET_TEXT zid=<64-hex> projects an identity... ");
    len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", k1_hex);
    run_op(&ndb, buf, len, 0xF1, 0, 701);
    { struct zid_identity got;
      bool ok = db_zid_identity_find(&ndb, k1, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
                strcmp(got.source, ZID_IDENTITY_SOURCE_ZNAM_TEXT) == 0 &&
                strcmp(got.name, "zidname") == 0 &&
                got.owner_address[0] != '\0' &&
                got.anchor_height == 701;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: find_by_name resolves the anchored key... ");
    { struct zid_identity got;
      bool ok = db_zid_identity_find_by_name(&ndb, "zidname", &got) &&
                memcmp(got.master_pubkey, k1, 32) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* A malformed value is not an identity — the TEXT RECORD is still
     * stored exactly as today, and nothing is projected. */
    printf("znam zid text: a 63-char value stores text, projects nothing... ");
    { char short_hex[64];
      memcpy(short_hex, k2_hex, 63);
      short_hex[63] = '\0';
      int64_t before = db_zid_identity_count(&ndb);
      len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", short_hex);
      run_op(&ndb, buf, len, 0xF2, 0, 702);
      char txt[256] = {0};
      bool ok = db_zid_identity_count(&ndb) == before &&
                db_znam_text_get(&ndb, "zidname", "zid", txt, sizeof(txt)) &&
                strcmp(txt, short_hex) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: a non-hex 64-char value projects nothing... ");
    { char bad[65];
      memset(bad, 'z', 64);
      bad[64] = '\0';
      int64_t before = db_zid_identity_count(&ndb);
      len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", bad);
      run_op(&ndb, buf, len, 0xF3, 0, 703);
      char txt[256] = {0};
      bool ok = db_zid_identity_count(&ndb) == before &&
                db_znam_text_get(&ndb, "zidname", "zid", txt, sizeof(txt)) &&
                strcmp(txt, bad) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: a non-'zid' text key projects nothing... ");
    { int64_t before = db_zid_identity_count(&ndb);
      len = znam_build_set_text(buf, sizeof(buf), "zidname", "onion", k2_hex);
      run_op(&ndb, buf, len, 0xF4, 0, 704);
      bool ok = db_zid_identity_count(&ndb) == before;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: a new key from the same owner rotates... ");
    len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", k2_hex);
    run_op(&ndb, buf, len, 0xF5, 0, 705);
    { struct zid_identity old, new_row;
      bool ok = db_zid_identity_find(&ndb, k1, &old) &&
                strcmp(old.status, ZID_IDENTITY_STATUS_ROTATED) == 0 &&
                old.has_successor &&
                memcmp(old.successor_pubkey, k2, 32) == 0 &&
                old.anchor_height == 701 && old.updated_height == 705 &&
                db_zid_identity_find(&ndb, k2, &new_row) &&
                strcmp(new_row.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
                strcmp(new_row.name, "zidname") == 0 &&
                new_row.anchor_height == 705;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: find_by_name follows the rotation... ");
    { struct zid_identity got;
      bool ok = db_zid_identity_find_by_name(&ndb, "zidname", &got) &&
                memcmp(got.master_pubkey, k2, 32) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: re-processing the SET_TEXT block is idempotent... ");
    { int64_t before = db_zid_identity_count(&ndb);
      struct zid_identity a1, a2, b1, b2;
      bool ok = db_zid_identity_find(&ndb, k1, &a1) &&
                db_zid_identity_find(&ndb, k2, &b1);
      run_op(&ndb, buf, len, 0xF5, 0, 705);
      ok = ok && db_zid_identity_count(&ndb) == before &&
           db_zid_identity_find(&ndb, k1, &a2) &&
           db_zid_identity_find(&ndb, k2, &b2) &&
           memcmp(&a1, &a2, sizeof(a1)) == 0 &&
           memcmp(&b1, &b2, sizeof(b1)) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("znam zid text: an empty value revokes the identity... ");
    len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", "");
    run_op(&ndb, buf, len, 0xF6, 0, 706);
    { struct zid_identity got;
      bool ok = db_zid_identity_find(&ndb, k2, &got) &&
                strcmp(got.status, ZID_IDENTITY_STATUS_REVOKED) == 0 &&
                !got.has_successor && got.updated_height == 706;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* The upstream owner check is untouched: a non-owner SET_TEXT never
     * reaches the identity feed at all. */
    printf("znam zid text: a non-owner SET_TEXT projects nothing... ");
    { uint8_t attacker[20];
      memset(attacker, 0x52, 20);
      seed_owner_utxo(&ndb, 0xFB, 0, attacker, 10);
      uint8_t k3[32];
      char k3_hex[65];
      memset(k3, 0xB3, 32);
      hex32(k3, k3_hex);
      int64_t before = db_zid_identity_count(&ndb);
      len = znam_build_set_text(buf, sizeof(buf), "zidname", "zid", k3_hex);
      run_op(&ndb, buf, len, 0xFB, 0, 707);
      struct zid_identity got;
      bool ok = db_zid_identity_count(&ndb) == before &&
                !db_zid_identity_find(&ndb, k3, &got);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_zid_identity(void)
{
    int failures = 0;
    printf("\n=== ZID Identity Projection Tests ===\n");
    failures += test_schema_and_roundtrip();
    failures += zid_validation_cases();
    failures += test_resolve_and_paging();
    failures += test_dumper();
    failures += test_overlay_registry_adopted();
    failures += test_dispatch_reaches_every_overlay();
    failures += test_zid_overlay_feed();
    failures += test_znam_zid_text_feed();
    return failures;
}
