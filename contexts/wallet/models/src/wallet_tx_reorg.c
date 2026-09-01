/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet transaction/UTXO projections used by reorg rollback and status.
 * ar-validate-skip:reorg-projection-operations — row writes delegate to the
 * validated wallet transaction save lifecycle. */

#include "models/wallet_tx.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

void db_wallet_tx_free(struct db_wallet_tx *tx)
{
    if (!tx) return;
    free(tx->raw_tx);
    tx->raw_tx = NULL;
    tx->raw_tx_len = 0;
}

bool db_wallet_tx_mark_unconfirmed(struct node_db *ndb,
                                   const uint8_t txid[32], bool *found_out)
{
    struct db_wallet_tx tx;
    if (found_out) *found_out = false;
    if (!ndb || !ndb->open || !txid)
        LOG_FAIL("wallet_tx", "mark unconfirmed: invalid argument");
    memset(&tx, 0, sizeof(tx));
    if (!db_wallet_tx_find(ndb, txid, &tx))
        return true;
    if (found_out) *found_out = true;
    tx.has_block = false;
    tx.block_height = 0;
    memset(tx.block_hash, 0, sizeof(tx.block_hash));
    bool ok = db_wallet_tx_save(ndb, &tx);
    db_wallet_tx_free(&tx);
    return ok;
}

int db_wallet_tx_confirmed_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_SQL(ndb,
        "SELECT COUNT(*) FROM wallet_transactions "
        "WHERE block_hash IS NOT NULL AND length(block_hash)=32 "
        "AND block_hash!=zeroblob(32)");
}

int64_t db_wallet_utxo_encumbered_balance(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT COALESCE(SUM(u.value),0) FROM wallet_utxos u "
        "JOIN wallet_transactions w ON w.txid=u.spent_txid "
        "WHERE u.spent_txid IS NOT NULL AND (w.block_hash IS NULL "
        "OR length(w.block_hash)!=32 OR w.block_hash=zeroblob(32))", -1);
    int64_t total = 0;
    if (AR_STEP_ROW(s)) total = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return total;
}

bool db_wallet_utxo_delete_for_tx(struct node_db *ndb,
                                  const uint8_t txid[32])
{
    if (!ndb || !ndb->open || !txid)
        LOG_FAIL("wallet_tx", "delete UTXOs for transaction: invalid argument");
    for (;;) {
        sqlite3_stmt *s = NULL;
        AR_PREPARE_BOOL(ndb, s,
            "SELECT vout FROM wallet_utxos WHERE txid=? LIMIT 1");
        AR_BIND_BLOB(s, 1, txid, 32);
        if (!AR_STEP_ROW(s)) {
            AR_FINALIZE(s);
            return true;
        }
        uint32_t vout = (uint32_t)AR_COL_INT(s, 0);
        AR_FINALIZE(s);
        if (!db_wallet_utxo_delete(ndb, txid, vout))
            return false; /* raw-return-ok:delete function logged context */
    }
}
