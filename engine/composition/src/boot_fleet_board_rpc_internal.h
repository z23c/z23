/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared input and error semantics for resident board RPC operations. */
#ifndef ZCL_BOOT_FLEET_BOARD_RPC_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_RPC_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>
struct json_value;
struct node_db;
struct db_fleet_board_post;
void fb_error(struct json_value *result, const char *code, const char *message);
const char *fb_str(const struct json_value *in, const char *key, const char *fallback);
int64_t fb_int(const struct json_value *in, const char *key, int64_t fallback);
bool fb_bool(const struct json_value *in, const char *key);
bool fb_render_post_fields(struct json_value *into,
                           const struct db_fleet_board_post *row, bool include_text);
bool fb_render_list(struct json_value *result,
                    const struct db_fleet_board_post *rows, int n);
void fb_op_list(struct node_db *ndb, const struct json_value *in,
                struct json_value *result, int64_t now);
#endif
