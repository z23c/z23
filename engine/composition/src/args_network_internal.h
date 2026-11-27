/* purpose: Internal helpers for node argument selection and diagnostics. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ARGS_NETWORK_INTERNAL_H
#define Z23_ARGS_NETWORK_INTERNAL_H
#include <stdbool.h>
struct app_context;
int args_network_begin(struct app_context *ctx);
/* Returns -2 for no match, -1 for handled, 1 for refusal. */
int args_network_arg(const char *arg, struct app_context *ctx, bool positional);
int args_network_finish(const struct app_context *ctx);
void args_warn_unrecognized(const char *arg);
#endif
