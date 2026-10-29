/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_FLEET_PROBE_H
#define Z23_ANDROID_FLEET_PROBE_H
#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zapp_fleet_host { char label[16], destination[128]; };
/* Parses "label=destination,..." with at most cap hosts; labels are [a-z0-9-]. */
bool zapp_fleet_hosts_parse(const char *spec, struct zapp_fleet_host *hosts, size_t cap, size_t *count);
/* Converts one host's probe output to a row; output may be NULL when unreachable. */
bool zapp_fleet_row(const char *label, const char *output, int64_t elapsed_ms, struct json_value *row);
/* Runs one fixed read-only command per host over SSH, concurrently, within timeout_ms.
 * Writes {"hosts":[rows],"observed_at":unix_seconds} as JSON text. */
bool zapp_fleet_probe(const struct zapp_fleet_host *hosts, size_t count, int timeout_ms,
                      char *out, size_t cap);
/* Summarizes `z23 core sync blockers` output for the chat model as {"host","active","blockers":[{"id",
 * "class","reason"}]} with at most six blockers, or {"host","error"}; output is NULL when the host
 * did not answer. */
bool zapp_fleet_blockers_summary(const char *label, const char *output, char *out, size_t cap);
/* Runs `z23 core sync blockers`, a fixed read-only command, on one host over SSH within timeout_ms. */
bool zapp_fleet_blockers(const struct zapp_fleet_host *host, int timeout_ms, char *out, size_t cap);
/* The model's one tool, host_blockers, as an OpenAI tools array naming the configured labels,
 * and the system prompt sentence that tells the model when to call it. */
extern const char zapp_fleet_tool_guide[];
bool zapp_fleet_tool_schema(const struct zapp_fleet_host *hosts, size_t count, struct json_value *schema);
/* The configured host a host_blockers call names, matching labels without case; NULL refuses. */
const struct zapp_fleet_host *zapp_fleet_tool_host(const struct zapp_fleet_host *hosts, size_t count,
                                                   const char *name, const char *arguments);
/* When the question part of a prompt, after its last "Question: ", asks about blockers or
 * problems of a configured host named as written or spoken, fills the host_blockers call for
 * the first configured host it names. */
bool zapp_fleet_tool_wanted(const struct zapp_fleet_host *hosts, size_t count, const char *prompt,
                            char *name, size_t name_cap, char *arguments, size_t arguments_cap);
#endif
