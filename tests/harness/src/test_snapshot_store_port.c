/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the fast-sync snapshot storage seam.
 *
 * The snapshot subsystem (snapshot_offer.c / snapshot_fetch.c /
 * snapshot_sync_service.c) performs its raw sqlite work — the active-UTXO
 * count, the staging-row count, the tip-chainwork lookup, the cached
 * staging insert, and the receive-mode busy-timeout — through
 * snapshot_store_port. This file exercises the sqlite adapter that now
 * backs those ops against an ISOLATED file-backed fixture DB in ./test-tmp,
 * never the live node DB.
 *
 * The subsystem is CONSENSUS-ADJACENT: the snapshot is pinned to a SHA3-256
 * UTXO commitment. The adapter moves only the STORAGE access, not the
 * commitment math, so this test asserts the staged rows round-trip
 * byte-for-byte (the bytes the commitment is computed over are unchanged).
 *
 * Coverage:
 *   - staging_insert writes db_utxo rows; the bytes (txid/script/value/...)
 *     round-trip byte-for-byte out of the staging table.
 *   - staging_count counts staged rows; -1 sentinel on a closed connection.
 *   - utxo_count counts the active utxos table.
 *   - tip_chainwork returns the 32-byte blob for a present block, false for
 *     a missing block, and false for a zero-chainwork block (the guard).
 *   - set_busy_timeout succeeds on an open connection.
 *   - Driving the service over the same fixture (snapsync_get_status_snapshot)
 *     reports the SAME staged-row count the adapter does.
 *   - NULL / closed-connection guards.
 *
 * NOTE on coupling: test_snapshot_sync_service.c drives the full state
 * machine and is left untouched; this file is hermetic.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/snapshot_store_sqlite.h"
#include "ports/snapshot_store_port.h"
#include "net/snapshot_sync_contract.h"
#include "models/database.h"
#include "models/utxo.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SSP_DIR "./test-tmp"

#define SSP_CHECK(name, expr) do {                       \
    printf("snapshot_store_port: %s... ", (name));       \
    if ((expr)) { printf("OK\n"); }                      \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* Deterministic script bytes for staged-row i (length varies a little so the
 * round-trip exercises non-uniform blobs). */
static size_t ssp_script_for(int i, uint8_t out[64])
{
    size_t len = (size_t)(20 + (i % 8));
    for (size_t b = 0; b < len; b++)
        out[b] = (uint8_t)((i * 17 + (int)b * 5 + 0x40) & 0xff);
    return len;
}

static void ssp_txid_for(int i, uint8_t out[32])
{
    for (int b = 0; b < 32; b++)
        out[b] = (uint8_t)((i * 13 + b * 3 + 0x10) & 0xff);
}

/* Read a staged row back directly from the fixture (raw sqlite — test
 * fixture verification, NOT the adapter under test). Returns true on a hit
 * and fills the out fields. */
static bool ssp_read_staged(struct node_db *ndb, int i,
                            int64_t *out_value, uint8_t *out_script,
                            int *out_script_len, int *out_height,
                            int *out_coinbase)
{
    uint8_t txid[32];
    ssp_txid_for(i, txid);
    sqlite3_stmt *st = NULL;
    bool got = false;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT value,script,height,is_coinbase "
            "FROM snapshot_staging_utxos WHERE txid=? AND vout=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, i);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_value = sqlite3_column_int64(st, 0);
        const void *blob = sqlite3_column_blob(st, 1);
        int blen = sqlite3_column_bytes(st, 1);
        if (blob && blen >= 0 && blen <= 64) {
            memcpy(out_script, blob, (size_t)blen);
            *out_script_len = blen;
        } else {
            *out_script_len = -1;
        }
        *out_height = sqlite3_column_int(st, 2);
        *out_coinbase = sqlite3_column_int(st, 3);
        got = true;
    }
    sqlite3_finalize(st);
    return got;
}

/* Seed one block row (raw sqlite — fixture setup) with a chosen 32-byte
 * chain_work blob. Other NOT NULL columns get trivial placeholder values. */
static bool ssp_seed_block(struct node_db *ndb, const uint8_t hash[32],
                           const uint8_t chain_work[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO blocks"
            "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
            "solution,chain_work,status) "
            "VALUES(?,1,?,4,?,0,0,?,?,?,3)", -1, &st, NULL) != SQLITE_OK)
        return false;
    uint8_t zeros[32] = {0};
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, zeros, 32, SQLITE_STATIC);   /* prev_hash */
    sqlite3_bind_blob(st, 3, zeros, 32, SQLITE_STATIC);   /* merkle_root */
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);   /* nonce */
    sqlite3_bind_blob(st, 5, zeros, 1,  SQLITE_STATIC);   /* solution */
    sqlite3_bind_blob(st, 6, chain_work, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Seed one active utxos row (raw sqlite — fixture setup). */
static bool ssp_seed_utxo(struct node_db *ndb, int i)
{
    uint8_t txid[32];
    ssp_txid_for(i + 1000, txid);
    uint8_t script[4] = {0x76, 0xa9, 0x14, 0x00};
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO utxos"
            "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
            " VALUES(?,0,1000,?,0,NULL,1,0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, script, sizeof(script), SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

int test_snapshot_store_port(void)
{
    int failures = 0;
    mkdir(SSP_DIR, 0755);

    char db_path[256];
    snprintf(db_path, sizeof(db_path),
             SSP_DIR "/ssp_%d.db", (int)getpid());
    unlink(db_path);

    struct node_db ndb;
    bool opened = node_db_open(&ndb, db_path);
    SSP_CHECK("fixture node_db opens", opened);
    if (!opened) { unlink(db_path); return failures + 1; }

    struct snapshot_store_sqlite_ctx ctx;
    struct snapshot_store_port port = {0};
    SSP_CHECK("bind ok",
              snapshot_store_sqlite_bind(&ctx, &ndb, &port));

    /* ---- staging_insert + byte-for-byte round-trip ---- */
    const int N = 12;
    bool insert_ok = true;
    for (int i = 0; i < N; i++) {
        struct db_utxo u;
        memset(&u, 0, sizeof(u));
        ssp_txid_for(i, u.txid);
        u.vout = (uint32_t)i;
        u.value = 1000000 + i;
        uint8_t script[64];
        u.script_len = ssp_script_for(i, script);
        u.script = script;
        u.script_type = (enum script_type)0;
        u.has_address = false;
        u.height = 100 + i;
        u.is_coinbase = (i % 3 == 0);
        if (!port.staging_insert(port.self, &u)) {
            insert_ok = false;
            break;
        }
    }
    SSP_CHECK("staging_insert all rows ok", insert_ok);

    /* staging_count reflects the inserts. */
    SSP_CHECK("staging_count == N", port.staging_count(port.self) == N);

    /* Each staged row's bytes are byte-for-byte identical to what was
     * written — the commitment is computed over exactly these bytes. */
    bool rows_identical = true;
    for (int i = 0; i < N; i++) {
        uint8_t want_script[64];
        size_t want_len = ssp_script_for(i, want_script);
        int64_t got_value = 0;
        uint8_t got_script[64] = {0};
        int got_len = -1, got_height = -1, got_cb = -1;
        if (!ssp_read_staged(&ndb, i, &got_value, got_script,
                             &got_len, &got_height, &got_cb) ||
            got_value != (int64_t)(1000000 + i) ||
            got_len != (int)want_len ||
            memcmp(got_script, want_script, want_len) != 0 ||
            got_height != 100 + i ||
            got_cb != (i % 3 == 0 ? 1 : 0)) {
            rows_identical = false;
            break;
        }
    }
    SSP_CHECK("staged rows round-trip byte-for-byte", rows_identical);

    /* ---- utxo_count over the active utxos table ---- */
    int64_t utxos0 = -1;
    SSP_CHECK("utxo_count ok on empty utxos",
              port.utxo_count(port.self, &utxos0) && utxos0 == 0);
    bool seeded_utxos = true;
    for (int i = 0; i < 7; i++)
        seeded_utxos &= ssp_seed_utxo(&ndb, i);
    SSP_CHECK("seeded 7 utxos", seeded_utxos);
    int64_t utxos1 = -1;
    SSP_CHECK("utxo_count == 7",
              port.utxo_count(port.self, &utxos1) && utxos1 == 7);

    /* ---- tip_chainwork: present / missing / zero ---- */
    uint8_t hash_present[32];
    uint8_t cw_present[32];
    for (int b = 0; b < 32; b++) { hash_present[b] = (uint8_t)(b + 1);
                                   cw_present[b] = (uint8_t)(0xA0 + b); }
    SSP_CHECK("seed block w/ chainwork",
              ssp_seed_block(&ndb, hash_present, cw_present));
    uint8_t cw_out[32] = {0};
    bool cw_ok = port.tip_chainwork(port.self, hash_present, cw_out);
    SSP_CHECK("tip_chainwork present returns true", cw_ok);
    SSP_CHECK("tip_chainwork blob matches",
              memcmp(cw_out, cw_present, 32) == 0);

    uint8_t hash_missing[32];
    for (int b = 0; b < 32; b++) hash_missing[b] = (uint8_t)(0xEE);
    uint8_t cw_miss[32] = {0};
    SSP_CHECK("tip_chainwork missing block false",
              !port.tip_chainwork(port.self, hash_missing, cw_miss));

    uint8_t hash_zero[32];
    uint8_t cw_zero[32] = {0};
    for (int b = 0; b < 32; b++) hash_zero[b] = (uint8_t)(0x55 + b);
    SSP_CHECK("seed block w/ zero chainwork",
              ssp_seed_block(&ndb, hash_zero, cw_zero));
    uint8_t cw_z_out[32] = {0};
    SSP_CHECK("tip_chainwork zero-chainwork block false (guard)",
              !port.tip_chainwork(port.self, hash_zero, cw_z_out));

    /* ---- set_busy_timeout ---- */
    SSP_CHECK("set_busy_timeout ok", port.set_busy_timeout(port.self, 10000));

    /* ---- drive the SERVICE over the same fixture ---- */
    {
        struct snapshot_sync_service svc;
        snapsync_init(&svc, &ndb);
        struct snapsync_status st;
        memset(&st, 0, sizeof(st));
        snapsync_get_status_snapshot(&svc, &st);
        /* The service reads staged_row_count through the same port; it must
         * agree with the adapter's direct count. */
        SSP_CHECK("service status staged_row_count == adapter count",
                  st.staged_row_count == port.staging_count(port.self));
        SSP_CHECK("service status staged_row_count == N",
                  st.staged_row_count == N);
    }

    /* ---- NULL / bad-arg guards ---- */
    {
        struct snapshot_store_sqlite_ctx c2;
        struct snapshot_store_port p2 = {0};
        SSP_CHECK("bind rejects NULL ctx",
                  !snapshot_store_sqlite_bind(NULL, &ndb, &p2));
        SSP_CHECK("bind rejects NULL out_port",
                  !snapshot_store_sqlite_bind(&c2, &ndb, NULL));

        /* NULL ndb is permitted by bind; methods then fail safely. */
        struct snapshot_store_port pnull = {0};
        SSP_CHECK("bind accepts NULL ndb",
                  snapshot_store_sqlite_bind(&c2, NULL, &pnull));
        int64_t n = -7;
        SSP_CHECK("utxo_count false on NULL ndb",
                  !pnull.utxo_count(pnull.self, &n));
        SSP_CHECK("utxo_count leaves out on NULL ndb", n == -7);
        SSP_CHECK("staging_count -1 on NULL ndb",
                  pnull.staging_count(pnull.self) == -1);
        uint8_t h[32] = {1}, o[32] = {0};
        SSP_CHECK("tip_chainwork false on NULL ndb",
                  !pnull.tip_chainwork(pnull.self, h, o));
        struct db_utxo u0;
        memset(&u0, 0, sizeof(u0));
        SSP_CHECK("staging_insert false on NULL ndb (no cached stmt)",
                  !pnull.staging_insert(pnull.self, &u0));
        SSP_CHECK("set_busy_timeout false on NULL ndb",
                  !pnull.set_busy_timeout(pnull.self, 1000));

        /* utxo_count tolerates a NULL out. */
        SSP_CHECK("utxo_count false on NULL out",
                  !port.utxo_count(port.self, NULL));
    }

    node_db_close(&ndb);
    unlink(db_path);
    return failures;
}
