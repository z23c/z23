/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for ZCL Anchors (ZANC) — codec (parse/build + pedantic negatives),
 * the zanc_anchors projection (save/find/list, mirroring the explorer-index
 * ingestion seam), the anchor_verify/anchor_list RPC surface (hit/miss), and
 * digest-of-file correctness against known SHA2-256/SHA3-256 vectors. */

#include "test/test_core.h"
#include "models/database.h"
#include "models/zanc.h"
#include "zanc/zanc.h"
#include "script/standard.h"
#include "controllers/anchor_controller.h"
#include "rpc/server.h"
#include "json/json.h"
#include "encoding/utilstrencodings.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static bool open_test_zanc_db(sqlite3 **db_out, struct node_db *ndb_out)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return false;
    sqlite3_exec(db,
        "CREATE TABLE zanc_anchors("
        "txid BLOB PRIMARY KEY, height INTEGER, hash_type INTEGER,"
        "digest BLOB, label TEXT NOT NULL DEFAULT '')",
        NULL, NULL, NULL);
    *db_out = db;
    ndb_out->db = db;
    ndb_out->open = true;
    return true;
}

static void mk_digest(uint8_t d[32], uint8_t fill)
{
    memset(d, fill, 32);
}

/* Call an anchor_* RPC with a single JSON-object argument (the --input form). */
static bool call_anchor_obj(struct rpc_table *t, const char *method,
                            struct json_value *obj, struct json_value *result)
{
    const struct rpc_command *cmd = rpc_table_find(t, method);
    if (!cmd) return false;
    struct json_value params = {0};
    json_set_array(&params);
    json_push_back(&params, obj);
    bool ok = cmd->actor(&params, false, result);
    json_free(&params);
    return ok;
}

int test_zanc(void)
{
    int failures = 0;
    printf("\n=== ZANC Tests ===\n");

    /* ── Codec: build + parse round-trip ──────────────────────────── */

    printf("zanc build+parse SHA3 with label roundtrip... ");
    {
        uint8_t digest[32];
        mk_digest(digest, 0xAB);
        uint8_t buf[128];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, "zclassic23@1.0");
        struct zanc_message m;
        bool ok = len > 0 && zanc_parse(buf, len, &m) &&
                  m.version == ZANC_VERSION &&
                  m.hash_type == ZANC_HASH_SHA3_256 &&
                  memcmp(m.digest, digest, 32) == 0 &&
                  strcmp(m.label, "zclassic23@1.0") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("zanc build+parse SHA2 empty-label roundtrip... ");
    {
        uint8_t digest[32];
        mk_digest(digest, 0x01);
        uint8_t buf[128];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA2_256,
                                       digest, NULL);
        struct zanc_message m;
        bool ok = len > 0 && zanc_parse(buf, len, &m) &&
                  m.hash_type == ZANC_HASH_SHA2_256 &&
                  m.label_len == 0 && m.label[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Codec: pedantic negatives ────────────────────────────────── */

    printf("zanc_parse: reject NULL/empty... ");
    {
        struct zanc_message m;
        if (!zanc_parse(NULL, 0, &m) && !zanc_parse((const uint8_t *)"", 0, &m))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_parse: reject non-OP_RETURN... ");
    {
        uint8_t bad[] = {0x76, 0x04, 'Z', 'A', 'N', 'C'};
        struct zanc_message m;
        if (!zanc_parse(bad, sizeof(bad), &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_parse: reject wrong lokad... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, "x");
        buf[2] = 'X';   /* corrupt "ZANC" -> "XANC" */
        struct zanc_message m;
        if (len > 0 && !zanc_parse(buf, len, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_parse: reject unknown version... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, "x");
        /* version push is at bytes [6]=len(1) [7]=value; bump value to 9. */
        buf[7] = 9;
        struct zanc_message m;
        if (len > 0 && !zanc_parse(buf, len, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_build: reject invalid hash_type... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        if (zanc_build_anchor(buf, sizeof(buf), 0, digest, NULL) == 0 &&
            zanc_build_anchor(buf, sizeof(buf), 3, digest, NULL) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_build: maximal anchor fits the 223-byte relay cap... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x33);
        char label[ZANC_LABEL_MAX + 1];
        memset(label, 'L', ZANC_LABEL_MAX);
        label[ZANC_LABEL_MAX] = '\0';
        uint8_t buf[512];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, label);
        struct zanc_message m;
        if (len > 0 && len <= MAX_OP_RETURN_RELAY &&
            zanc_parse(buf, len, &m) && m.label_len == ZANC_LABEL_MAX)
            printf("OK\n");
        else { printf("FAIL (len=%zu)\n", len); failures++; }
    }

    printf("zanc_parse: reject bad hash_type byte on-chain... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, NULL);
        buf[9] = 7;   /* hash_type push value byte */
        struct zanc_message m;
        if (len > 0 && !zanc_parse(buf, len, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_build: reject oversize label (>32)... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        char big[40];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        if (zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                              digest, big) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_build: reject control-byte label... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[128];
        if (zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                              digest, "bad\x01tab") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_parse: reject trailing bytes... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t buf[130];
        size_t len = zanc_build_anchor(buf, sizeof(buf), ZANC_HASH_SHA3_256,
                                       digest, NULL);
        buf[len] = 0x00;   /* append a stray byte */
        struct zanc_message m;
        if (len > 0 && !zanc_parse(buf, len + 1, &m)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_build: reject too-small buffer... ");
    {
        uint8_t digest[32]; mk_digest(digest, 0x22);
        uint8_t tiny[8];
        if (zanc_build_anchor(tiny, sizeof(tiny), ZANC_HASH_SHA3_256,
                              digest, NULL) == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("zanc_label_valid: accepts UTF-8, rejects overlong... ");
    {
        bool ok = zanc_label_valid("héllo", strlen("héllo")) &&
                  !zanc_label_valid("\xc0\xaf", 2);   /* overlong '/' */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Projection: save / find_by_digest / list ─────────────────── */

    printf("zanc DB save+find_by_digest+list... ");
    {
        sqlite3 *db = NULL;
        struct node_db ndb = {0};
        if (!open_test_zanc_db(&db, &ndb)) {
            printf("FAIL (open)\n"); failures++;
        } else {
            struct zanc_anchor a = {0};
            memset(a.txid, 0xE1, 32);
            a.height = 1000;
            a.hash_type = ZANC_HASH_SHA3_256;
            mk_digest(a.digest, 0x55);
            snprintf(a.label, sizeof(a.label), "pkg@1");
            bool save_ok = db_zanc_save(&ndb, &a);

            /* Second anchor of the SAME digest at a later height — find must
             * return the earliest (height 1000). */
            struct zanc_anchor a2 = a;
            memset(a2.txid, 0xE2, 32);
            a2.height = 2000;
            db_zanc_save(&ndb, &a2);

            struct zanc_anchor got = {0};
            bool find_ok = db_zanc_find_by_digest(&ndb, ZANC_HASH_SHA3_256,
                                                  a.digest, &got);
            struct zanc_anchor list[10];
            int count = db_zanc_list(&ndb, list, 10);

            uint8_t other[32]; mk_digest(other, 0x99);
            struct zanc_anchor miss = {0};
            bool miss_ok = !db_zanc_find_by_digest(&ndb, ZANC_HASH_SHA3_256,
                                                   other, &miss);
            /* Right digest, wrong hash_type -> miss. */
            bool type_miss = !db_zanc_find_by_digest(&ndb, ZANC_HASH_SHA2_256,
                                                     a.digest, &miss);

            if (save_ok && find_ok && got.height == 1000 &&
                strcmp(got.label, "pkg@1") == 0 && count == 2 &&
                list[0].height == 2000 && miss_ok && type_miss)
                printf("OK\n");
            else {
                printf("FAIL (save=%d find=%d h=%d count=%d miss=%d tmiss=%d)\n",
                       save_ok, find_ok, got.height, count, miss_ok, type_miss);
                failures++;
            }
            sqlite3_close(db);
        }
    }

    printf("zanc DB save rejects all-zero txid (validator)... ");
    {
        sqlite3 *db = NULL;
        struct node_db ndb = {0};
        if (!open_test_zanc_db(&db, &ndb)) { printf("FAIL\n"); failures++; }
        else {
            struct zanc_anchor a = {0};   /* txid all-zero */
            a.height = 1; a.hash_type = ZANC_HASH_SHA3_256;
            mk_digest(a.digest, 0x55);
            if (!db_zanc_save(&ndb, &a)) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
            sqlite3_close(db);
        }
    }

    /* ── RPC verify/list hit + miss ───────────────────────────────── */

    printf("\n=== ZANC RPC verify/list ===\n");
    {
        sqlite3 *db = NULL;
        struct node_db ndb = {0};
        if (!open_test_zanc_db(&db, &ndb)) {
            printf("zanc RPC fixture: FAIL\n"); failures++;
        } else {
            struct zanc_anchor a = {0};
            memset(a.txid, 0x7A, 32);
            a.height = 3176325;
            a.hash_type = ZANC_HASH_SHA3_256;
            mk_digest(a.digest, 0x42);
            snprintf(a.label, sizeof(a.label), "release@2");
            db_zanc_save(&ndb, &a);

            rpc_anchor_set_state(&ndb);
            struct rpc_table t;
            rpc_table_init(&t);
            register_anchor_rpc_commands(&t);

            char hex[65];
            HexStr(a.digest, 32, false, hex, sizeof(hex));

            /* verify: hit */
            {
                struct json_value obj = {0}, r = {0};
                json_set_object(&obj);
                json_push_kv_str(&obj, "digest", hex);
                json_push_kv_str(&obj, "hash_type", "sha3");
                printf("anchor_verify: digest hit... ");
                bool ok = call_anchor_obj(&t, "anchor_verify", &obj, &r);
                const struct json_value *an = json_get(&r, "anchored");
                if (ok && an && json_get_bool(an)) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&obj); json_free(&r);
            }

            /* verify: miss */
            {
                struct json_value obj = {0}, r = {0};
                json_set_object(&obj);
                json_push_kv_str(&obj, "digest",
                    "0000000000000000000000000000000000000000000000000000000000000000");
                printf("anchor_verify: digest miss... ");
                bool ok = call_anchor_obj(&t, "anchor_verify", &obj, &r);
                const struct json_value *an = json_get(&r, "anchored");
                if (ok && an && !json_get_bool(an)) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&obj); json_free(&r);
            }

            /* verify: bad digest length */
            {
                struct json_value obj = {0}, r = {0};
                json_set_object(&obj);
                json_push_kv_str(&obj, "digest", "abcd");
                printf("anchor_verify: reject short digest... ");
                bool ok = call_anchor_obj(&t, "anchor_verify", &obj, &r);
                if (!ok) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&obj); json_free(&r);
            }

            /* list */
            {
                struct json_value obj = {0}, r = {0};
                json_set_object(&obj);
                json_push_kv_int(&obj, "limit", 10);
                printf("anchor_list: returns the anchor... ");
                bool ok = call_anchor_obj(&t, "anchor_list", &obj, &r);
                const struct json_value *cnt = json_get(&r, "count");
                if (ok && cnt && json_get_int(cnt) == 1) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&obj); json_free(&r);
            }

            /* publish (no wallet) returns op_return hex */
            {
                struct json_value obj = {0}, r = {0};
                json_set_object(&obj);
                json_push_kv_str(&obj, "digest", hex);
                json_push_kv_str(&obj, "label", "pkg@3");
                printf("anchor_publish: no-wallet returns ready hex... ");
                bool ok = call_anchor_obj(&t, "anchor_publish", &obj, &r);
                bool pass = ok &&
                    strcmp(json_get_str(json_get(&r, "status")), "ready") == 0 &&
                    json_get(&r, "op_return_hex") != NULL;
                if (pass) printf("OK\n");
                else { printf("FAIL\n"); failures++; }
                json_free(&obj); json_free(&r);
            }

            rpc_anchor_set_state(NULL);
            sqlite3_close(db);
        }
    }

    /* ── Digest-of-file correctness (known vectors) ───────────────── */

    printf("\n=== ZANC file digest vectors ===\n");
    printf("anchor_verify file: SHA2-256/SHA3-256 of \"abc\"... ");
    {
        char path[] = "/tmp/zanc_test_XXXXXX";
        int fd = mkstemp(path);
        bool wrote = fd >= 0 && write(fd, "abc", 3) == 3;
        if (fd >= 0) close(fd);

        struct node_db ndb = {0};
        sqlite3 *db = NULL;
        bool opened = open_test_zanc_db(&db, &ndb);
        rpc_anchor_set_state(&ndb);
        struct rpc_table t;
        rpc_table_init(&t);
        register_anchor_rpc_commands(&t);

        struct json_value obj = {0}, r = {0};
        json_set_object(&obj);
        json_push_kv_str(&obj, "file", path);
        bool ok = wrote && opened &&
                  call_anchor_obj(&t, "anchor_verify", &obj, &r);
        const char *s2 = ok ? json_get_str(json_get(&r, "sha2_256")) : NULL;
        const char *s3 = ok ? json_get_str(json_get(&r, "sha3_256")) : NULL;
        bool pass = s2 && s3 &&
            strcmp(s2, "ba7816bf8f01cfea414140de5dae2223"
                       "b00361a396177a9cb410ff61f20015ad") == 0 &&
            strcmp(s3, "3a985da74fe225b2045c172d6bd390bd"
                       "855f086e3e9d525b46bfe24511431532") == 0;
        if (pass) printf("OK\n");
        else {
            printf("FAIL (s2=%s s3=%s)\n", s2 ? s2 : "(null)",
                   s3 ? s3 : "(null)");
            failures++;
        }
        json_free(&obj); json_free(&r);
        rpc_anchor_set_state(NULL);
        if (opened) sqlite3_close(db);
        if (wrote) unlink(path);
    }

    printf("\n%d ZANC test(s) failed\n", failures);
    return failures;
}
