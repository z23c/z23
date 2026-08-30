/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ActiveRecord model for byte-bound encrypted wallet-backup authority. */

#include "models/wallet_backup_receipt.h"

#include "models/model_text.h"
#include "platform/path_compat.h"
#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(wallet_backup_receipt)

bool db_wallet_backup_receipt_validate(
    const struct wallet_backup_receipt *receipt, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!receipt) {
        ar_errors_add(errors, "receipt", "is NULL");
        return false;
    }
    validates_positive(errors, receipt, completed_unix);
    validates_non_negative(errors, receipt, key_count);
    validates_positive(errors, receipt, tables_verified);
    validates_positive(errors, receipt, size_bytes);
    validates_custom(errors, platform_path_is_absolute(receipt->backup_path) &&
                     strlen(receipt->backup_path) <
                         WALLET_BACKUP_RECEIPT_PATH_MAX &&
                     model_string_is_printable(receipt->backup_path),
                     "backup_path", "must be a bounded absolute path");
    return !ar_errors_any(errors);
}

bool db_wallet_backup_receipt_save(
    struct node_db *ndb, const struct wallet_backup_receipt *receipt)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("wallet_backup_receipt", "save: database is not open");
    if (!receipt)
        LOG_FAIL("wallet_backup_receipt", "save: receipt is NULL");

    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO wallet_backup_receipts("
        "singleton_id,completed_unix,key_count,tables_verified,size_bytes,"
        "file_sha3,backup_path) VALUES(1,?,?,?,?,?,?) "
        "ON CONFLICT(singleton_id) DO UPDATE SET "
        "completed_unix=excluded.completed_unix,"
        "key_count=excluded.key_count,"
        "tables_verified=excluded.tables_verified,"
        "size_bytes=excluded.size_bytes,"
        "file_sha3=excluded.file_sha3,"
        "backup_path=excluded.backup_path",
        db_wallet_backup_receipt_callbacks(), "wallet_backup_receipt", receipt,
        db_wallet_backup_receipt_validate,
        AR_BIND_INT(s, 1, receipt->completed_unix);
        AR_BIND_INT(s, 2, receipt->key_count);
        AR_BIND_INT(s, 3, receipt->tables_verified);
        AR_BIND_INT(s, 4, receipt->size_bytes);
        AR_BIND_BLOB(s, 5, receipt->file_sha3, sizeof(receipt->file_sha3));
        AR_BIND_TEXT(s, 6, receipt->backup_path));
}

bool db_wallet_backup_receipt_find(
    struct node_db *ndb, struct wallet_backup_receipt *out)
{
    if (!ndb || !ndb->open || !out)
        LOG_FAIL("wallet_backup_receipt", "find: invalid arguments");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT completed_unix,key_count,tables_verified,size_bytes,"
        "file_sha3,backup_path FROM wallet_backup_receipts "
        "WHERE singleton_id=1",
        ,
        out->completed_unix = AR_COL_INT(s, 0);
        out->key_count = AR_COL_INT(s, 1);
        out->tables_verified = (int)AR_COL_INT(s, 2);
        out->size_bytes = AR_COL_INT(s, 3);
        AR_READ_BLOB(s, 4, out->file_sha3, sizeof(out->file_sha3));
        AR_READ_STR(s, 5, out->backup_path, sizeof(out->backup_path)));
}
