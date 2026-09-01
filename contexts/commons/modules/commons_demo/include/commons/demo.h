/* Copyright 2026 Rhett Creighton - MIT License
 * purpose: Public API for the standalone C23 Commons demonstration app. */

#ifndef ZCL_COMMONS_DEMO_H
#define ZCL_COMMONS_DEMO_H

#include <stdbool.h>
#include <stddef.h>

/* Parse {"name":string,"count":nonnegative-u32}, encode the two values with
 * the Commons codec, and render one stable human-readable summary. */
bool commons_demo_render(const char *input, char *out, size_t out_capacity);

#endif /* ZCL_COMMONS_DEMO_H */
