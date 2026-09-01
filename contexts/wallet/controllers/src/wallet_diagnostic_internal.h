/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the wallet-diagnostic
 * controller. The public surface lives in
 * controllers/wallet_diagnostic_controller.h. This header is private
 * to engine/controllers/src/wallet_diagnostic*.c and declares helpers
 * that needed to become non-static so the controller could be split
 * into health / audit / repair siblings. Do not include from outside
 * engine/controllers/src/. */

#ifndef ZCL_APP_CONTROLLERS_SRC_WALLET_DIAGNOSTIC_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_WALLET_DIAGNOSTIC_INTERNAL_H

#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/wallet_helpers.h"
#include "models/database.h"

#include <stdbool.h>

/* Shared helpers (definitions live in wallet_diagnostic_controller.c).
 * wallet_ctx_db_ready is shared across all wallet controllers and is
 * declared in controllers/wallet_helpers.h. */

struct wallet_rpc_context *wallet_ctx(void);
bool wallet_diag_begin_checked(struct node_db *ndb, const char *label);
bool wallet_diag_commit_checked(struct node_db *ndb, const char *label);
void wallet_diag_rollback_best_effort(struct node_db *ndb,
                                      const char *label);

/* ── RPC handler declarations (defined in sibling files) ── */

struct json_value;

/* wallet_diagnostic_health.c */
bool rpc_getwalletaccounting(const struct json_value *params, bool help,
                             struct json_value *result);
bool rpc_db_info(const struct json_value *params, bool help,
                 struct json_value *result);
bool rpc_getchaincoins(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_traceutxo(const struct json_value *params, bool help,
                   struct json_value *result);
bool rpc_listwalletkeys(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_listwallettxdetail(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_getbalanceflow(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_walletbackupstatus(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_walletbackupnow(const struct json_value *params, bool help,
                         struct json_value *result);

/* wallet_diagnostic_audit.c */
bool rpc_walletaudit(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_diagnoseutxos(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_walletledger(const struct json_value *params, bool help,
                      struct json_value *result);

/* wallet_diagnostic_repair.c */
bool rpc_scanblockfiles(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_reindexdb(const struct json_value *params, bool help,
                   struct json_value *result);
bool rpc_importlegacy(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_removestalletxs(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_reconcilewalletutxos(const struct json_value *params, bool help,
                              struct json_value *result);
bool rpc_purgephantomutxos(const struct json_value *params, bool help,
                           struct json_value *result);

#endif
