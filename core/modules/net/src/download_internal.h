/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal declarations shared by download.c and the per-peer assignment
 * window helpers in download_assign_windows.c. Not part of the public API.
 * All helpers require the caller to hold dm->cs. */

#ifndef DOWNLOAD_INTERNAL_H
#define DOWNLOAD_INTERNAL_H

#include "net/download.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct dl_assign_load {
    size_t peer_count;
    size_t history_peer_count;
    size_t history_global_count;
    size_t forward_queued;
    size_t history_queued;
};

struct dl_assign_windows {
    size_t available;
    size_t global_limit;
    size_t history_available;
};

struct dl_pick_scan {
    size_t npick;
    size_t history_picked;
    bool avoid_blocked;
    int64_t retry_after;
};

struct dl_assign_applied {
    size_t assigned;
    size_t history_assigned;
    bool attempted_slot;
};

struct dl_assign_outcome {
    size_t assigned;
    bool attempted_slot;
    bool avoid_blocked;
    int64_t retry_after;
};

struct dl_assign_load dl_assign_measure(const struct download_manager *dm,
                                        uint32_t peer_id);
size_t dl_assign_peer_limit(const struct dl_peer_stats *ps);
struct dl_assign_windows dl_assign_windows(
    const struct download_manager *dm,
    size_t peer_count, size_t peer_limit, size_t max_assign,
    size_t history_global_count, size_t history_peer_count,
    size_t forward_queued, size_t history_queued);
int dl_assign_prelim_result(size_t queue_before, size_t max_assign,
                            size_t peer_count, size_t peer_limit,
                            size_t active_before, size_t global_limit,
                            size_t forward_queued, size_t history_queued,
                            size_t history_available);
size_t dl_assign_tip_bias(const struct download_manager *dm,
                          const struct dl_peer_stats *ps,
                          size_t history_queued);
bool dl_assign_can_batch(size_t available, size_t tip_bias_skip,
                         size_t queue_len);

#endif /* DOWNLOAD_INTERNAL_H */
