/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the block_index_sidecar storage seam.
 *
 * bii_verify() cross-checks the loader's declared tip against the
 * SQLite `blocks` table via exactly one read — "SELECT height FROM
 * blocks WHERE hash=?". That read now lives behind
 * block_index_sidecar_port, backed by the sqlite adapter under
 * platform/adapters/outbound/persistence/. This file exercises BOTH layers over
 * ISOLATED in-memory / temp-file fixtures, never the live node DB:
 *
 *   1. Drive the sqlite adapter directly: against a node_db whose
 *      `blocks` table holds a known (hash,height) row, assert the
 *      lookup returns FOUND with the exact height, NOT_FOUND for an
 *      unknown hash, and UNAVAILABLE for a NULL connection.
 *   2. Drive the full service bii_verify() over the same kind of
 *      fixture (real sidecar + real `blocks` rows) and assert the
 *      integrity verdict is identical to the pre-seam behaviour:
 *      BII_OK on match, BII_TIP_HEIGHT_MISMATCH on drift,
 *      BII_TIP_MISSING_IN_SQL when the tip hash is absent.
 *   3. NULL-arg guards on the bind and lookup.
 *
 * NOTE on coupling: test_block_index_integrity.c already drives the
 * full sidecar verifier (sidecar writer, hash mismatch, quarantine,
 * SQLite cross-check) over its own scratch datadirs; that group is left
 * untouched. This file is the hermetic adapter/port-level companion.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/block_index_sidecar_sqlite.h"
#include "ports/block_index_sidecar_port.h"

#include "services/block_index_integrity.h"
#include "models/database.h"
#include "chain/chain.h"
#include "core/uint256.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BISP_CHECK(name, expr) do {                       \
    printf("block_index_sidecar_port: %s... ", (name));   \
    if ((expr)) { printf("OK\n"); }                       \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* Insert one row into the node_db `blocks` table with the given hash
 * and height. All NOT NULL columns are supplied to satisfy the schema
 * (same column set test_block_index_integrity.c uses). */
static bool insert_block_row(struct node_db *ndb,
                             const uint8_t hash32[32], int64_t height)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(ndb->db,
        "INSERT INTO blocks("
        "hash,height,prev_hash,version,merkle_root,"
        "time,bits,nonce,solution,chain_work) "
        "VALUES(?,?,?,0,?,0,0,?,?,?)",
        -1, &st, NULL);
    if (rc != SQLITE_OK || !st)
        return false;
    static const uint8_t zero32[32] = {0};
    static const uint8_t dummy_solution[4] = {0};
    sqlite3_bind_blob(st, 1, hash32, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zero32, 32, SQLITE_STATIC);  /* merkle_root */
    sqlite3_bind_blob(st, 5, zero32, 32, SQLITE_STATIC);  /* nonce */
    sqlite3_bind_blob(st, 6, dummy_solution, sizeof(dummy_solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, zero32, 32, SQLITE_STATIC);  /* chain_work */
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* ── Datadir harness (mirrors test_block_index_integrity.c) ──── */

static void bisp_write_body(const char *dir, const char *bytes, size_t n)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(bytes, 1, n, f); fclose(f); }
}

static void bisp_tear_down(const char *dir)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/block_index.bin", dir);      unlink(p);
    snprintf(p, sizeof(p), "%s/block_index.bin.sha3", dir); unlink(p);
    rmdir(dir);
}

int test_block_index_sidecar_port(void)
{
    int failures = 0;

    /* A fixed 32-byte tip hash the fixture will store. */
    uint8_t tip_hash[32] = {0};
    tip_hash[0] = 0x11; tip_hash[31] = 0xEE;
    const int64_t tip_height = 4242;

    /* ── 1. adapter direct: FOUND / height / NOT_FOUND ── */
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        BISP_CHECK("node_db opens (:memory:)",
                   node_db_open(&ndb, ":memory:"));
        BISP_CHECK("blocks row inserted",
                   insert_block_row(&ndb, tip_hash, tip_height));

        struct block_index_sidecar_sqlite_ctx ctx;
        struct block_index_sidecar_port port = {0};
        BISP_CHECK("bind ok",
                   block_index_sidecar_sqlite_bind(&ctx, ndb.db, &port));

        int64_t h = -1;
        BISP_CHECK("lookup known hash -> FOUND",
                   port.lookup_block_height(port.self, tip_hash, &h)
                       == BII_HEIGHT_FOUND);
        BISP_CHECK("lookup returns exact stored height", h == tip_height);

        uint8_t unknown[32] = {0};
        unknown[0] = 0xAB; unknown[1] = 0xCD;
        int64_t h2 = 999;
        BISP_CHECK("lookup unknown hash -> NOT_FOUND",
                   port.lookup_block_height(port.self, unknown, &h2)
                       == BII_HEIGHT_NOT_FOUND);
        BISP_CHECK("out_height untouched on NOT_FOUND", h2 == 999);

        node_db_close(&ndb);
    }

    /* ── 2. adapter direct: NULL connection -> UNAVAILABLE (skip) ── */
    {
        struct block_index_sidecar_sqlite_ctx ctx;
        struct block_index_sidecar_port port = {0};
        BISP_CHECK("bind NULL conn ok",
                   block_index_sidecar_sqlite_bind(&ctx, NULL, &port));
        int64_t h = 7;
        BISP_CHECK("lookup NULL conn -> UNAVAILABLE",
                   port.lookup_block_height(port.self, tip_hash, &h)
                       == BII_HEIGHT_UNAVAILABLE);
        BISP_CHECK("out_height untouched on UNAVAILABLE", h == 7);
    }

    /* ── 3. service over same fixture: verdict identical ──
     * bii_verify with a valid sidecar + a declared tip whose hash and
     * height match the SQLite row must return BII_OK; drift -> mismatch;
     * absent hash -> missing-in-SQL. This is the integrity verdict the
     * port now backs, and it must not change. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "bisp", "sidecar");
        BISP_CHECK("tmpdir made", dir[0] != '\0');
        const char body[] = "body-for-sidecar-port-test";
        bisp_write_body(dir, body, sizeof(body) - 1);
        BISP_CHECK("sidecar written", bii_write_sidecar(dir).ok);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        node_db_open(&ndb, ":memory:");
        BISP_CHECK("blocks row inserted (service)",
                   insert_block_row(&ndb, tip_hash, tip_height));

        struct uint256 hash = {{0}};
        memcpy(hash.data, tip_hash, 32);

        /* Matching tip -> BII_OK. */
        struct block_index tip = {0};
        tip.phashBlock = &hash;
        tip.nHeight = (int)tip_height;
        char err[256];
        BISP_CHECK("service: matching tip -> BII_OK",
                   bii_verify(dir, &ndb, &tip, err, sizeof(err)) == BII_OK);

        /* Drifted height -> BII_TIP_HEIGHT_MISMATCH. */
        tip.nHeight = (int)tip_height + 1;
        BISP_CHECK("service: drifted height -> TIP_HEIGHT_MISMATCH",
                   bii_verify(dir, &ndb, &tip, err, sizeof(err))
                       == BII_TIP_HEIGHT_MISMATCH);

        /* Absent hash -> BII_TIP_MISSING_IN_SQL. */
        struct uint256 absent = {{0}};
        absent.data[0] = 0x77; absent.data[31] = 0x33;
        struct block_index tip2 = {0};
        tip2.phashBlock = &absent;
        tip2.nHeight = 1;
        BISP_CHECK("service: absent tip hash -> TIP_MISSING_IN_SQL",
                   bii_verify(dir, &ndb, &tip2, err, sizeof(err))
                       == BII_TIP_MISSING_IN_SQL);

        /* NULL db skips the cross-check entirely -> BII_OK. */
        tip.nHeight = 999999;  /* would mismatch if checked */
        BISP_CHECK("service: NULL db skips cross-check -> BII_OK",
                   bii_verify(dir, NULL, &tip, err, sizeof(err)) == BII_OK);

        node_db_close(&ndb);
        bisp_tear_down(dir);
    }

    /* ── 4. bind NULL-arg guards ── */
    {
        struct block_index_sidecar_sqlite_ctx ctx;
        struct block_index_sidecar_port port = {0};
        BISP_CHECK("bind rejects NULL ctx",
                   !block_index_sidecar_sqlite_bind(NULL, (sqlite3 *)0x1, &port));
        BISP_CHECK("bind rejects NULL out_port",
                   !block_index_sidecar_sqlite_bind(&ctx, (sqlite3 *)0x1, NULL));
    }

    return failures;
}
