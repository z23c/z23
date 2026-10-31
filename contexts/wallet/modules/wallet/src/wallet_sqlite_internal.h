/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared private declarations for wallet SQLite C modules. */
#ifndef ZCL_WALLET_SQLITE_INTERNAL_H
#define ZCL_WALLET_SQLITE_INTERNAL_H

#include "wallet/wallet_sqlite.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#endif /* ZCL_WALLET_SQLITE_INTERNAL_H */
