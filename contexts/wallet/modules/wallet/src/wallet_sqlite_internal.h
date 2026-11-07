/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared private declarations for wallet SQLite C modules. */
#ifndef ZCL_WALLET_SQLITE_INTERNAL_H
#define ZCL_WALLET_SQLITE_INTERNAL_H

#include "wallet/wallet_sqlite.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum wsql_snapshot_kind { WSQL_SNAPSHOT_SCAN, WSQL_SNAPSHOT_V2 };
/* Caller owns the connection and its read savepoint; failed cleanup fail-stops. */
bool wsql_snapshot_release(sqlite3 *db, enum wsql_snapshot_kind kind);

struct zcl_result wsql_fail(struct wallet_sqlite *ws, struct zcl_result r);
void wallet_sqlite_reset_all_statements(struct wallet_sqlite *ws);
bool wallet_sqlite_replace_keypool_locked(struct wallet_sqlite *ws,
                                          const struct wallet *w,
                                          bool persisted_only);

/* At-rest envelope helpers shared by the transparent and Sapling row code. */
bool wsql_is_wks1_blob(const void *data, size_t len);
bool wsql_encrypt_blob(const uint8_t *plain, size_t plen, uint8_t **out,
                       size_t *out_len);
bool wsql_decrypt_blob(const uint8_t *envelope, size_t env_len, uint8_t **out,
                       size_t *out_len);
void wsql_wipe_free(uint8_t *plain, size_t len);
bool wsql_sapling_key_row_exists(struct wallet_sqlite *ws,
                                 const uint8_t ivk[32]);

/* True when a Sapling seed row is stored; the seed is not opened. */
bool wsql_sapling_seed_row_exists(struct wallet_sqlite *ws);

/* Counters and the first write error from one flush attempt. */
struct wsql_flush_halt {
    bool halt;
    struct zcl_result first_fail;
    int n_key_fail, n_keypool_fail, n_tx_fail;
    int n_zseed_fail, n_zkey_fail, n_script_fail, n_scanh_fail;
};
bool wsql_write_height_encoding(struct wallet_sqlite *ws, int height);
bool wsql_write_tx_reference(struct wallet_sqlite *ws, const struct wallet_tx *wtx,
                             bool v2, int reference);
bool wsql_used_entries_stored(struct wallet_sqlite *ws, const struct wallet *w,
                              bool writes_secrets);
struct wsql_flush_halt wsql_flush_write_keypool_and_tx(
    struct wallet_sqlite *ws, struct wallet *w, bool held);
struct zcl_result wsql_flush_commit_txn(struct wallet_sqlite *ws);

#endif /* ZCL_WALLET_SQLITE_INTERNAL_H */
