/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_UTXO_IMPORT_PIPELINE_H
#define ZCL_SERVICES_UTXO_IMPORT_PIPELINE_H

#include "util/result.h"

#include <stdint.h>
#include <stddef.h>

struct node_db;
typedef struct sqlite3_stmt sqlite3_stmt;

#define UTXO_IMPORT_NUM_DECODERS_MAX 32
#define UTXO_IMPORT_VALUE_MAX_BYTES (4u * 1024u * 1024u)

struct utxo_import_raw_entry {
    uint8_t  txid[32];
    uint8_t *value;
    uint32_t value_len;
};

struct utxo_import_row {
    uint8_t  txid[32];
    uint8_t  address_hash[20];
    uint8_t  script[80];
    uint8_t *script_overflow;
    int64_t  value;
    int32_t  height;
    uint32_t vout;
    uint16_t script_len;
    uint8_t  script_type;
    uint8_t  has_address;
    uint8_t  is_coinbase;
};

int utxo_import_num_decoders(void);
struct zcl_result utxo_import_value_len_checked(size_t value_len,
                                                uint32_t *out_len);
int utxo_import_decode_entry(const struct utxo_import_raw_entry *raw,
                             struct utxo_import_row *out,
                             int max_rows);
struct zcl_result utxo_import_writer_bind_checked(sqlite3_stmt *stmt,
                                                  const char *label,
                                                  int rc,
                                                  const struct node_db *ndb,
                                                  int row_no);
struct zcl_result utxo_import_writer_step_checked(sqlite3_stmt *stmt,
                                                  const struct node_db *ndb,
                                                  int row_no);

#endif /* ZCL_SERVICES_UTXO_IMPORT_PIPELINE_H */
