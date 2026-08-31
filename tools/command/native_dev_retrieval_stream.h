/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal CLI-only stream seam for the observational retrieval benchmark. */

#ifndef ZCL_TOOLS_NATIVE_DEV_RETRIEVAL_STREAM_H
#define ZCL_TOOLS_NATIVE_DEV_RETRIEVAL_STREAM_H

#include "json/json.h"

#include <stddef.h>
#include <stdio.h>

/* Compute one source-bound ranking and emit every adaptive page as JSONL.
 * Nothing is written until computation, source post-check, and all page
 * rendering have succeeded. Returns a zcl_command_exit value. */
int zcl_native_dev_retrieval_stream_jsonl(
    const struct json_value *input, size_t contract_bytes, FILE *out,
    char *error_code, size_t error_code_cap,
    char *error_message, size_t error_message_cap);

#endif
