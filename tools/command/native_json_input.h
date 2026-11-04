/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: declare shared native JSON transport helpers. */
#ifndef ZCL_NATIVE_JSON_INPUT_H
#define ZCL_NATIVE_JSON_INPUT_H
#include <stdbool.h>
#include <stddef.h>
/* Read at most the budget plus an over-limit sentinel; caller frees.
 * length is the physical byte count, excluding the convenience trailing NUL. */
char *zcl_native_read_stdin(size_t max_bytes, bool *oversize, size_t *length);
struct json_value;
/* The native CLI error envelope, with an already validated next-action array. */
size_t zcl_native_error_json(const char *command, const char *code,
    const char *phase, const char *message, const char *evidence,
    const char *next_reason, const struct json_value *next, char *out, size_t cap);
#endif
