/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fair bounded scheduler for cached STORAGE_ACK possession proofs. */

#ifndef ZCL_VCS_PACKAGE_POSSESSION_SCHEDULER_H
#define ZCL_VCS_PACKAGE_POSSESSION_SCHEDULER_H

#include "vcs/package_store.h"

#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS 64u

struct vcs_package_possession_scheduler;

struct vcs_package_possession_scheduler_config {
    uint32_t packages_per_cycle;
    uint32_t chunks_per_package_cycle;
    uint64_t bytes_per_cycle;
    uint64_t scrub_interval_s;
    uint64_t failure_retry_s;
};

struct vcs_package_possession_scheduler_status {
    uint32_t tracked_roots;
    uint32_t queued_roots;
    uint64_t bytes_verified_total;
    uint64_t successful_proofs;
    uint64_t failed_proofs;
    uint64_t cycles;
    uint64_t last_cycle_bytes;
    uint32_t last_cycle_packages;
    uint64_t next_due_mono;
};

struct vcs_package_possession_scheduler_row {
    uint8_t root[32];
    uint64_t mutation_generation;
    uint64_t last_success_mono;
    uint64_t next_due_mono;
    uint64_t bytes_verified;
    uint64_t proof_age_s;
    uint64_t failures;
    bool current;
    bool queued;
    enum vcs_package_possession_failure failure;
};

struct vcs_package_possession_scheduler *
vcs_package_possession_scheduler_new(
    const struct vcs_package_possession_scheduler_config *config);
void vcs_package_possession_scheduler_free(
    struct vcs_package_possession_scheduler *scheduler);

/* Reconcile the exact set of roots that need pinned-byte proofs. New and
 * generation-changed roots become due immediately; removed roots release any
 * in-progress proof. Duplicate input roots are ignored. */
bool vcs_package_possession_scheduler_reconcile(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, const uint8_t (*roots)[32],
    size_t root_count, uint64_t now_mono);

/* Force a watched root due now (restart/renewal/mutation event). */
bool vcs_package_possession_scheduler_require(
    struct vcs_package_possession_scheduler *scheduler,
    const uint8_t root[32], uint64_t now_mono);

/* Spend no more than the configured package/chunk/byte budgets. */
void vcs_package_possession_scheduler_run(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, uint64_t now_mono);

/* A cached success is current only while generation, completeness and pin
 * state still match. The returned receipt is the last successful proof. */
bool vcs_package_possession_scheduler_current(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, const uint8_t root[32],
    struct vcs_package_possession_receipt *receipt);

void vcs_package_possession_scheduler_status(
    const struct vcs_package_possession_scheduler *scheduler,
    uint64_t now_mono,
    struct vcs_package_possession_scheduler_status *out);
size_t vcs_package_possession_scheduler_rows(
    const struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, uint64_t now_mono,
    struct vcs_package_possession_scheduler_row *out, size_t max);

#endif /* ZCL_VCS_PACKAGE_POSSESSION_SCHEDULER_H */
