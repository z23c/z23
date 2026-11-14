/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: render local timing artifacts without treating them as proof. */
#ifndef ZCL_DEV_TIMINGS_H
#define ZCL_DEV_TIMINGS_H
#include <stdio.h>
#include <stdint.h>
#include <json/json.h>

struct timings_context { FILE *out; int64_t head_epoch; long lint_total; };
void timings_lint(struct timings_context *, const struct json_value *, const char *);
void timings_tests(struct timings_context *, const struct json_value *, const char *);
void timings_devloop(struct timings_context *, const struct json_value *, const char *);
void timings_first_build(struct timings_context *, const struct json_value *, const char *);
int timings_selftest(void);
int timings_file_selftest(void);
#endif
