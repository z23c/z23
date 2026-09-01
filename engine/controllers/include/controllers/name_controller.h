/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Name Controller — RPC commands for ZCL Names (ZNAM).
 *
 * Commands:
 *   name_register    — register a name on-chain
 *   name_update      — replace a name's primary target (owner-only)
 *   name_transfer    — hand ownership to a new owner (owner-only)
 *   name_renew       — extend the registration term (permissionless)
 *   name_set_record  — set an additional multi-coin address record
 *                      (owner-only)
 *   name_set_text    — set an arbitrary key/value text record
 *                      (owner-only)
 *   name_resolve     — look up a name
 *   name_list        — list registered names */

#ifndef ZCL_CONTROLLERS_NAME_H
#define ZCL_CONTROLLERS_NAME_H

#include "rpc/server.h"
#include "models/database.h"
#include <stddef.h>
#include <stdint.h>

struct wallet;
struct tx_mempool;
struct main_state;
struct coins_view_cache;

void rpc_name_set_state(struct node_db *ndb);
void rpc_name_set_wallet(struct wallet *w, struct tx_mempool *mp,
                         struct main_state *main_state,
                         struct coins_view_cache *coins_tip);
void register_name_rpc_commands(struct rpc_table *t);
void register_znam_intent_rpc_command(struct rpc_table *table);
const char *znam_type_name(uint8_t t);

/* Boot-wired names runtime context (node.db + wallet path), snapshotted so the
 * read-only HTML site controller + the shared REGISTER compose reach the same
 * handles the RPC/REST surface uses. Fields are NULL before boot wiring. */
struct name_controller_ctx {
    struct node_db          *ndb;
    struct wallet           *wallet;
    struct tx_mempool       *mempool;
    struct main_state       *main_state;
    struct coins_view_cache *coins_tip;
};
void name_controller_get_ctx(struct name_controller_ctx *out);

/* THE single REGISTER tx-compose path — shared by the JSON-RPC name_register
 * handler and the HTML register POST. Defined in name_site_controller.c (kept
 * out of name_controller.c for the file-size ceiling). See there for the
 * contract. */
bool name_controller_compose_register(const char *name, uint8_t target_type,
                                      const char *value, char *txid_hex,
                                      size_t txid_cap, int64_t *fee_out,
                                      char *err, size_t err_cap);

/* name_records RPC actor (list a name's resolver records — the has_many
 * relationship). Defined in name_site_controller.c; registered by
 * register_name_rpc_commands. */
bool rpc_name_records(const struct json_value *params, bool help,
                      struct json_value *result);

/* REST API */
#include "json/json.h"
bool api_name_list(struct json_value *result);
bool rpc_name_resolve_api(const char *name, struct json_value *result);
bool api_name_service_directory(const char *name, struct json_value *result);
bool api_name_service_directory_path(const char *name, const char *path,
                                     struct json_value *result,
                                     char *err, size_t err_len);
size_t api_serve_name_service_directory(const char *name, const char *path,
                                        const char *freshness,
                                        uint8_t *response,
                                        size_t response_max);
void api_name_append_records(struct node_db *ndb, const char *name,
                             struct json_value *obj);

#endif
