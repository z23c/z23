/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private seams shared by the split ZSLP transaction controllers. */

#ifndef ZCL_ZSLP_CONTROLLER_INTERNAL_H
#define ZCL_ZSLP_CONTROLLER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct db_zslp_token_info;
struct db_zslp_transfer_info;
struct json_value;
struct tx_mempool;
struct wallet;
struct wallet_tx;

struct wallet *zslp_controller_wallet(void);
struct tx_mempool *zslp_controller_mempool(void);
const char *zslp_controller_datadir(const char *datadir);
bool zslp_controller_validity_ready(struct json_value *result,
                                    const char *verb);
bool zslp_controller_publish(struct wallet_tx *wtx, char txid_out[65],
                             char *error_out, size_t error_size);
bool zslp_controller_parse_amount(const struct json_value *value,
                                  uint64_t *amount_out);
void zslp_controller_render_validity(struct json_value *out,
                                     const struct db_zslp_token_info *token);
void zslp_controller_render_transfer(
    struct json_value *out, const struct db_zslp_transfer_info *transfer);
bool zslp_controller_require_token(const char *token_key,
                                   struct json_value *result);
bool zslp_controller_require_address(const char *address,
                                     bool strict_chain_address,
                                     struct json_value *result);

#endif
