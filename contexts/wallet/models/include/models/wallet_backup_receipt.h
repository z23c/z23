/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Durable authority for the latest verified encrypted wallet backup. */

#ifndef ZCL_DB_MODEL_WALLET_BACKUP_RECEIPT_H
#define ZCL_DB_MODEL_WALLET_BACKUP_RECEIPT_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

#define WALLET_BACKUP_RECEIPT_PATH_MAX 512

struct wallet_backup_receipt {
    int64_t completed_unix;
    int64_t key_count;
    int tables_verified;
    int64_t size_bytes;
    uint8_t file_sha3[32];
    char backup_path[WALLET_BACKUP_RECEIPT_PATH_MAX];
};

struct ar_callbacks *db_wallet_backup_receipt_callbacks(void);
bool db_wallet_backup_receipt_validate(
    const struct wallet_backup_receipt *receipt, struct ar_errors *errors);
bool db_wallet_backup_receipt_save(
    struct node_db *ndb, const struct wallet_backup_receipt *receipt);
bool db_wallet_backup_receipt_find(
    struct node_db *ndb, struct wallet_backup_receipt *out);

#endif
