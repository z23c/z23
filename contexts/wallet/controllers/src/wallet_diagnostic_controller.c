/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Wallet diagnostic controller — public surface, shared helpers, RPC
 * command registration. The route handlers live in the sibling files:
 *
 *   wallet_diagnostic_health.c   — read-only inspection RPCs
 *   wallet_diagnostic_audit.c    — cross-reference / non-mutating audits
 *   wallet_diagnostic_repair.c   — destructive wallet/DB mutations
 *
 * See wallet_diagnostic_internal.h for cross-sibling declarations. */

#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/wallet_helpers.h"
#include "models/database.h"
#include "wallet_diagnostic_internal.h"

#include "util/log_macros.h"

#include <stdio.h>

struct wallet_rpc_context *wallet_ctx(void)
{
    return wallet_rpc_context_current();
}

/* wallet_ctx_db_ready lives in wallet_helpers.c (shared by all wallet
 * controllers) and is declared in controllers/wallet_helpers.h. */

bool wallet_diag_begin_checked(struct node_db *ndb, const char *label)
{
    if (!ndb || !ndb->open || !node_db_begin(ndb))
        LOG_FAIL("wallet_diag", "%s failed: %s", label,
                 (ndb && ndb->db) ? sqlite3_errmsg(ndb->db) : "db unavailable");
    return true;
}

bool wallet_diag_commit_checked(struct node_db *ndb, const char *label)
{
    if (!ndb || !ndb->open || !node_db_commit(ndb))
        LOG_FAIL("wallet_diag", "%s failed: %s", label,
                 (ndb && ndb->db) ? sqlite3_errmsg(ndb->db) : "db unavailable");
    return true;
}

void wallet_diag_rollback_best_effort(struct node_db *ndb, const char *label)
{
    if (!ndb || !ndb->open)
        return;
    if (!node_db_rollback(ndb)) {
        LOG_WARN("wallet_diag", "[wallet_diag] %s: rollback failed: %s", label, ndb->db ? sqlite3_errmsg(ndb->db) : "db unavailable");
    }
}

void register_wallet_diagnostic_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "scanblockfiles",      rpc_scanblockfiles,       false },
        { "wallet", "reindexdb",           rpc_reindexdb,            false },
        { "wallet", "importlegacy",        rpc_importlegacy,         false },
        { "wallet", "getwalletaccounting", rpc_getwalletaccounting,  false },
        { "wallet", "db_info",             rpc_db_info,              false },
        { "wallet", "removestalletxs",     rpc_removestalletxs,      false },
        { "wallet", "walletaudit",         rpc_walletaudit,          false },
        { "wallet", "getchaincoins",       rpc_getchaincoins,        false },
        { "wallet", "traceutxo",           rpc_traceutxo,            false },
        { "wallet", "listwalletkeys",      rpc_listwalletkeys,       false },
        { "wallet", "listwallettxdetail",  rpc_listwallettxdetail,   false },
        { "wallet", "getbalanceflow",      rpc_getbalanceflow,       false },
        { "wallet", "walletbackupstatus",  rpc_walletbackupstatus,   false },
        { "wallet", "walletbackupnow",     rpc_walletbackupnow,      false },
        { "wallet", "reconcilewalletutxos", rpc_reconcilewalletutxos, false },
        { "wallet", "purgephantomutxos",   rpc_purgephantomutxos,    false },
        { "wallet", "diagnoseutxos",       rpc_diagnoseutxos,        false },
        { "wallet", "walletledger",        rpc_walletledger,         false },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
