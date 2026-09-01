/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer stats view: comprehensive blockchain statistics rendered from the
 * read-only explorer projection. Controllers provide request context and
 * delegate page assembly here. */

#ifndef ZCL_VIEWS_EXPLORER_STATS_VIEW_H
#define ZCL_VIEWS_EXPLORER_STATS_VIEW_H

#include <stdint.h>
#include <stddef.h>

/* Compute comprehensive stats into the provided buffer.
 * Called from a background thread. Returns bytes written, 0 on error.
 * datadir: path to data directory (for node.db). */
size_t explorer_stats_build(uint8_t *buf, size_t buf_max, const char *datadir);

#endif
