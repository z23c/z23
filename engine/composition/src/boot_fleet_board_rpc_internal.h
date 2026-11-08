/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared input and error semantics for resident board RPC operations. */
#ifndef ZCL_BOOT_FLEET_BOARD_RPC_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_RPC_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>
struct json_value;
void fb_error(struct json_value *result, const char *code, const char *message);
const char *fb_str(const struct json_value *in, const char *key, const char *fallback);
int64_t fb_int(const struct json_value *in, const char *key, int64_t fallback);
bool fb_bool(const struct json_value *in, const char *key);
#endif
