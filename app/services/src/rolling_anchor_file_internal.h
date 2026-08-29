/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private durable-publication helper for the rolling-anchor service. */

#ifndef ZCL_ROLLING_ANCHOR_FILE_INTERNAL_H
#define ZCL_ROLLING_ANCHOR_FILE_INTERNAL_H

#include <stdbool.h>

bool rolling_anchor_parent_flush(const char *path);

#endif
