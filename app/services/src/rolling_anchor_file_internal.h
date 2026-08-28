/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private file-identity helpers for the rolling-anchor service. */

#ifndef ZCL_ROLLING_ANCHOR_FILE_INTERNAL_H
#define ZCL_ROLLING_ANCHOR_FILE_INTERNAL_H

#include "platform/positioned_file.h"

bool rolling_anchor_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b);
bool rolling_anchor_parent_flush(const char *path);

#endif
