/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fresh-process Sapling trial-decryption initialization. */
#include "test/test_core.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "primitives/transaction.h"
#include "wallet/sapling_keys.h"
#include "util/safe_alloc.h"
#include "support/cleanse.h"
#include "../../../engine/services/src/node_db_catchup_internal.h"
#include "catchup_parallel_cold_vector.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
size_t node_db_catchup_parallel_test_selected(void);
int node_db_catchup_parallel_test_worker_count(const struct catchup_parallel_state *state);

static bool cold_blob(sqlite3_stmt *stmt, int col, const uint8_t *expected, int size)
{
    return sqlite3_column_type(stmt, col) == SQLITE_BLOB &&
        sqlite3_column_bytes(stmt, col) == size && sqlite3_column_blob(stmt, col) &&
        memcmp(sqlite3_column_blob(stmt, col), expected, (size_t)size) == 0;
}

static bool cold_note(struct node_db *db, const struct transaction *tx)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT value,rcm,memo,ivk,diversifier,cm,nullifier "
        "FROM wallet_sapling_notes WHERE txid=? AND output_index=0";
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(stmt, 1, tx->hash.data, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int64(stmt, 0) == 10 &&
        cold_blob(stmt, 1, cold_plaintext + 20, 32) && cold_blob(stmt, 2, cold_plaintext + 52, 512) &&
        cold_blob(stmt, 3, cold_ivk, 32) && cold_blob(stmt, 4, cold_plaintext + 1, 11) &&
        cold_blob(stmt, 5, cold_cm, 32) && cold_blob(stmt, 6, cold_nf_position0, 32) &&
        sqlite3_step(stmt) == SQLITE_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && ok;
}

static void cold_inputs(struct transaction *tx, struct sapling_key_entry *keys)
{
    tx->num_shielded_output = 1;
    memcpy(tx->v_shielded_output[0].ephemeral_key.data, cold_epk, 32);
    memcpy(tx->v_shielded_output[0].cm.data, cold_cm, 32);
    memcpy(tx->v_shielded_output[0].enc_ciphertext, cold_ciphertext, 580);
    for (size_t i = 0; i < 20; ++i) { keys[i].used = true; keys[i].ivk[0] = (uint8_t)(i + 1); }
    memcpy(keys[19].ivk, cold_ivk, 32);
    memcpy(keys[19].xfvk.fvk.ak, cold_ak, 32);
    memcpy(keys[19].xfvk.fvk.nk, cold_nk, 32);
}

static bool cold_result(struct node_db *db, struct transaction *tx,
    const struct catchup_parallel_state *pool, const struct sapling_replay_delivery *delivery, int found)
{
    return node_db_catchup_parallel_test_worker_count(pool) >= 2 && found == 1 &&
        node_db_catchup_parallel_test_selected() == 19 && delivery->count == 1 && cold_note(db, tx);
}

int test_catchup_parallel_cold(void)
{
    char dir[256], path[320];
    test_make_tmpdir(dir, sizeof(dir), "catchup_parallel", "cold");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db db = {0};
    struct transaction tx;
    transaction_init(&tx);
    tx.version = SAPLING_TX_VERSION;
    tx.overwintered = true;
    tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    tx.v_shielded_output = zcl_calloc(1, sizeof(*tx.v_shielded_output), "cold trial output");
    struct sapling_key_entry *keys = zcl_calloc(20, sizeof(*keys), "cold trial keys");
    bool ok = tx.v_shielded_output && keys && node_db_open(&db, path);
    static const uint8_t zero_diversifier[11] = {0};
    if (ok) ok = memcmp(cold_plaintext + 1, zero_diversifier, sizeof(zero_diversifier)) != 0;
    if (ok) cold_inputs(&tx, keys);
    struct catchup_parallel_state pool = {0};
    struct sapling_replay_delivery delivery = {0};
    int found = -1;
    bool begun = ok && node_db_begin(&db);
    if (begun) ok = node_db_catchup_replay_sapling_decrypt_parallel(&db, &tx, keys, 20,
        1, &found, &delivery, &pool);
    else ok = false;
    if (ok) ok = cold_result(&db, &tx, &pool, &delivery, found);
    if (begun && !node_db_rollback(&db)) ok = false;
    node_db_catchup_parallel_free(&pool);
    db_sapling_replay_delivery_clear(&delivery);
    if (keys) { memory_cleanse(keys, 20 * sizeof(*keys)); free(keys); }
    transaction_free(&tx);
    if (db.open) node_db_close(&db);
    (void)test_rm_rf_recursive(dir);
    return ok ? 0 : 1;
}
#else
int test_catchup_parallel_cold(void) { return 0; }
#endif
