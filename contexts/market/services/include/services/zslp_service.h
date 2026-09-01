/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZSLP application service — validation and persistence helpers. */

#ifndef ZCL_ZSLP_SERVICE_H
#define ZCL_ZSLP_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#include "util/result.h"

struct tx_destination;
struct db_zslp_token_info;
struct db_zslp_transfer_info;
struct wallet;

struct zslp_token_create_request {
    const char *ticker;
    const char *name;
    uint8_t decimals;
    uint64_t initial_supply;
};

struct zslp_token_transfer_request {
    const char *token_id;
    const char *recipient_addr;
    uint64_t amount;
    bool strict_chain_addr;
};

bool zslp_service_is_alphanumeric(const char *str, size_t len);
bool zslp_service_is_hex_string(const char *str, size_t len);
struct zcl_result zslp_service_validate_token_key(const char *token_key);
struct zcl_result zslp_service_decode_transparent_destination(
    const char *addr, struct tx_destination *dest);
struct zcl_result zslp_service_validate_recipient_addr(const char *addr,
                                          bool strict_chain_addr);
const char *zslp_service_validate_create_request(
    const struct zslp_token_create_request *req);
const char *zslp_service_validate_transfer_request(
    const struct zslp_token_transfer_request *req);

struct zcl_result zslp_service_open_db(const char *datadir, sqlite3 **db_out,
                                       bool *owns_db);
void zslp_service_close_db(sqlite3 *db, bool owns_db);

uint64_t zslp_service_get_balance(sqlite3 *db, const char *token_id,
                                  const char *addr);
struct zcl_result zslp_service_get_token(sqlite3 *db, const char *token_id,
                                         struct db_zslp_token_info *out);
int zslp_service_list_tokens(sqlite3 *db, struct db_zslp_token_info *out,
                             size_t max_out);
int zslp_service_list_transfers(sqlite3 *db, const char *token_id,
                                struct db_zslp_transfer_info *out,
                                size_t max_out);
struct zcl_result zslp_service_credit_balance(sqlite3 *db, const char *token_id,
                                              const char *recipient_addr,
                                              uint64_t amount);
struct zcl_result zslp_service_store_token(sqlite3 *db, const char *token_id,
                                           const char *ticker, const char *name,
                                           int decimals, int64_t initial_supply);

struct zcl_result zslp_payment_generate_address(struct wallet *wallet,
                                                char *z_addr_out, size_t max);
int64_t zslp_payment_check_received(const char *datadir,
                                    const char *z_addr,
                                    int64_t min_amount);

#endif
