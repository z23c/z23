/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private seam between the `dev` command shell
 * (native_dev_command.c) and its pure input/interrupt policy core
 * (native_dev_input_policy.c). Only those two files and the HOT_FORK story
 * adapter native_dev_input_and_interrupt_policy_v1 include it. */
#ifndef ZCL_TOOLS_COMMAND_NATIVE_DEV_INPUT_POLICY_H
#define ZCL_TOOLS_COMMAND_NATIVE_DEV_INPUT_POLICY_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Reads input["files"] as a bounded array of confined relative paths into
 * `files` (borrowed from `input`). An absent or null member is accepted
 * only when `allow_empty`. On refusal writes the reason to `why`. */
bool zcl_dev_request_files(const struct json_value *input,
                           bool allow_empty, const char **files,
                           size_t *count, char *why, size_t why_size);

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* input[key] as an integer; `fallback` when absent or null, false when the
 * member has any other type. */
bool zcl_dev_drive_input_int(const struct json_value *input,
                             const char *key, int64_t fallback,
                             int64_t *out);

/* True for exactly a 64-character lowercase-hex failure id. */
bool zcl_dev_failure_id_valid(const char *failure_id);
#endif

#ifdef ZCL_DEV_BUILD
/* True when a cycle event must interrupt `dev drive`: a *_RED phase, or a
 * red/rejected status. */
bool zcl_dev_event_interrupting(const struct json_value *cycle);

/* True for a non-empty test-group name of [A-Za-z0-9_], under 128 bytes. */
bool zcl_dev_group_valid(const char *group);

/* True for "gen-<64 lowercase hex>" or "legacy-<64 lowercase hex>". */
bool zcl_dev_generation_name_valid(const char *name);
#endif

#endif /* ZCL_TOOLS_COMMAND_NATIVE_DEV_INPUT_POLICY_H */
