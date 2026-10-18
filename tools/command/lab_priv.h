/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Helpers shared by the lab command leaves (run, test, show). */
#ifndef ZCL_TOOLS_COMMAND_LAB_PRIV_H
#define ZCL_TOOLS_COMMAND_LAB_PRIV_H

#include "command/lab.h"
#include "kernel/command_registry.h"

struct lab_ctx {
    struct lab_dirs dirs;
    struct lab_toolchain tc;
    struct lab_source src;
    char root[LAB_ROOT_HEX + 1];
};

void lab_fail(struct zcl_command_reply *reply, const char *code,
              const char *phase, const char *message);
const char *lab_in_str(const struct zcl_command_request *rq, const char *key);
bool lab_in_bool(const struct zcl_command_request *rq, const char *key,
                 bool fallback);
bool lab_in_uint(const struct zcl_command_request *rq, const char *key,
                 uint32_t fallback, uint32_t max, uint32_t *out);

/* Load the source named by `file` (NULL for lab.show), the state directories
 * and the toolchain. On failure the reply carries the typed refusal. */
bool lab_ctx_open(struct lab_ctx *ctx, const char *file,
                  struct zcl_command_reply *reply);
void lab_ctx_close(struct lab_ctx *ctx);
void lab_unconfined(struct zcl_command_reply *reply);

/* Serve the stored receipt for ctx->root when it matches this compiler. */
bool lab_cache_serve(struct lab_ctx *ctx, struct zcl_command_reply *reply);
/* Store the receipt built in reply->data and mark it as a fresh result. */
bool lab_publish(struct lab_ctx *ctx, struct zcl_command_reply *reply);

bool lab_attach(struct json_value *d, const char *key, struct json_value *sec,
                bool built);
bool lab_head(struct json_value *d, const struct lab_ctx *ctx, const char *kind,
              const struct lab_compile *comp);
bool lab_tail(struct json_value *d, const struct lab_compile *comp,
              bool requested, bool applied, size_t findings, const char *first);

#endif
