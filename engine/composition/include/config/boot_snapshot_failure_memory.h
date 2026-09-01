/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_BOOT_SNAPSHOT_FAILURE_MEMORY_H
#define ZCL_BOOT_SNAPSHOT_FAILURE_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BOOT_SNAPSHOT_FAILURE_MARKER_MAX 1200

struct app_context;

/* Prepare the crash-loop guard for a snapshot seed selected during boot.
 *
 * The helper may auto-select a starter-pack snapshot when the datadir is still
 * unproven, writes a sibling "<snapshot>.failed" marker before the seed, and
 * clears ctx->load_snapshot_at_own_height when the marker cannot be written or
 * a prior marker says this exact seed already crashed. Reaching the loader with
 * no failure memory would make a bad bundle restart forever under systemd.
 */
bool boot_snapshot_failure_memory_prepare(struct app_context *ctx,
                                          bool coins_kv_proven_authority,
                                          int32_t coins_kv_applied_height,
                                          bool *from_autodetect,
                                          char *fail_marker,
                                          size_t fail_marker_cap);

/* Drop the marker after the loader returns cleanly. */
void boot_snapshot_failure_memory_clear(const char *fail_marker);

#endif /* ZCL_BOOT_SNAPSHOT_FAILURE_MEMORY_H */
