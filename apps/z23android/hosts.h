/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_HOSTS_H
#define ZAPP_HOSTS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Formats the laptop host's fleet snapshot as a headline and one block per host.
 * Unknown or missing values are shown as unknown, never as zero. */
bool zapp_hosts_format(const char *json, char *out, size_t cap);
/* Writes value with comma thousands separators, which models copy more reliably than long digit
 * runs; negative values are written plainly. Returns out. */
const char *zapp_grouped(int64_t value, char out[32]);
#endif
