/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared controller-only helpers for the shop fulfillment branch. */
#ifndef ZCL_CONTROLLER_SHOP_NATIVE_FULFILL_INTERNAL_H
#define ZCL_CONTROLLER_SHOP_NATIVE_FULFILL_INTERNAL_H

#include "command/native_command.h"
#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

void shf_fail(struct zcl_command_reply *reply,
              enum zcl_command_status status,
              enum zcl_command_exit exit_code, const char *code,
              const char *phase, const char *message, const char *evidence);
const char *shf_datadir(const struct zcl_command_request *request);
bool shf_now(const struct zcl_command_request *request, int64_t *out,
             struct zcl_command_reply *reply);
void shf_derive_pubkey(uint8_t pubkey[32], const uint8_t seed[32]);
bool shf_seller_secret(const struct zcl_command_request *request,
                       uint8_t out[32], struct zcl_command_reply *reply);
bool shf_required_id(const struct zcl_command_request *request,
                     const char *key, uint8_t out[32],
                     struct zcl_command_reply *reply);
bool shf_optional_id(const struct zcl_command_request *request,
                     const char *key, uint8_t out[32],
                     struct zcl_command_reply *reply);
bool shf_open_readonly(const char *datadir, struct sqlite3 **db,
                       struct node_db *ndb,
                       struct zcl_command_reply *reply);
bool shf_open_write(const char *datadir, struct node_db *ndb,
                    struct zcl_command_reply *reply);
bool shf_resolve_profile(const struct zcl_command_request *request,
                         const char *datadir, int *profile_out,
                         struct zcl_command_reply *reply);

#endif
