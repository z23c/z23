/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared private declarations for wallet SQLite C modules. */
#ifndef ZCL_WALLET_SQLITE_INTERNAL_H
#define ZCL_WALLET_SQLITE_INTERNAL_H

#include "wallet/wallet_sqlite.h"

struct zcl_result wsql_fail(struct wallet_sqlite *ws, struct zcl_result r);
void wallet_sqlite_reset_all_statements(struct wallet_sqlite *ws);
bool wallet_sqlite_replace_keypool_locked(struct wallet_sqlite *ws,
                                          const struct wallet *w);

#endif /* ZCL_WALLET_SQLITE_INTERNAL_H */
