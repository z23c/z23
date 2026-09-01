/* Copyright 2026 Rhett Creighton - MIT License
 * Purpose: expose the allocation-free tiny-lines fixture API. */
#ifndef ZCL_FIXTURE_TINY_LINES_H
#define ZCL_FIXTURE_TINY_LINES_H

#include <stdbool.h>
#include <stddef.h>

bool tiny_count_lines(const char *text, size_t length, size_t *out_lines);

#endif
