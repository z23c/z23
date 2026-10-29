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
#endif
