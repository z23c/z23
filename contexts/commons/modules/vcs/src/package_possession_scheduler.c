/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fair bounded scheduler for package possession validation. */

#include "vcs/package_possession_scheduler.h"

#include "base/safe_alloc.h"
#include "vcs/package_manifest.h"

#include <stdlib.h>
#include <string.h>

struct scheduler_entry {
    bool used;
    uint8_t root[32];
    uint64_t observed_generation;
    bool observed_complete;
    bool observed_pinned;
    uint64_t last_success_generation;
    uint64_t last_success_mono;
    uint64_t next_due_mono;
    uint64_t bytes_verified;
    uint64_t failures;
    enum vcs_package_possession_failure failure;
    struct vcs_package_possession_receipt receipt;
    struct vcs_package_possession_proof *proof;
};

struct vcs_package_possession_scheduler {
    struct vcs_package_possession_scheduler_config config;
    struct scheduler_entry
        entries[VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS];
    uint32_t cursor;
    uint64_t bytes_verified_total;
    uint64_t successful_proofs;
    uint64_t failed_proofs;
    uint64_t cycles;
    uint64_t last_cycle_bytes;
    uint32_t last_cycle_packages;
};

static struct scheduler_entry *entry_find(
    struct vcs_package_possession_scheduler *scheduler,
    const uint8_t root[32])
{
    for (size_t i = 0; i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS; i++)
        if (scheduler->entries[i].used &&
            memcmp(scheduler->entries[i].root, root, 32) == 0)
            return &scheduler->entries[i];
    return NULL;
}

static void entry_reset_proof(struct scheduler_entry *entry)
{
    vcs_package_store_possession_free(entry->proof);
    entry->proof = NULL;
}

static void entry_observe(struct scheduler_entry *entry,
                          struct vcs_package_store *store,
                          uint64_t now_mono)
{
    struct vcs_package_possession_receipt snapshot;
    bool present = vcs_package_store_possession_snapshot(
        store, entry->root, &snapshot);
    uint64_t generation = present ? snapshot.mutation_generation : 0;
    bool complete = present && snapshot.complete;
    bool pinned = present && snapshot.pinned;
    if (generation == entry->observed_generation &&
        complete == entry->observed_complete &&
        pinned == entry->observed_pinned)
        return;
    entry->observed_generation = generation;
    entry->observed_complete = complete;
    entry->observed_pinned = pinned;
    entry->last_success_generation = 0;
    entry->failure = !present ? VCS_PACKAGE_POSSESSION_UNTRACKED
                              : (!complete ? VCS_PACKAGE_POSSESSION_INCOMPLETE
                                           : (!pinned
                                                  ? VCS_PACKAGE_POSSESSION_UNPINNED
                                                  : VCS_PACKAGE_POSSESSION_NONE));
    entry_reset_proof(entry);
    entry->next_due_mono = now_mono;
}

struct vcs_package_possession_scheduler *
vcs_package_possession_scheduler_new(
    const struct vcs_package_possession_scheduler_config *config)
{
    if (!config || !config->packages_per_cycle ||
        config->packages_per_cycle >
            VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS ||
        !config->chunks_per_package_cycle ||
        config->bytes_per_cycle < VCS_PACKAGE_CHUNK_BYTES ||
        !config->scrub_interval_s || !config->failure_retry_s)
        return NULL;
    struct vcs_package_possession_scheduler *scheduler =
        zcl_calloc(1, sizeof(*scheduler), "possession_scheduler");
    if (!scheduler)
        return NULL;
    scheduler->config = *config;
    return scheduler;
}

void vcs_package_possession_scheduler_free(
    struct vcs_package_possession_scheduler *scheduler)
{
    if (!scheduler)
        return;
    for (size_t i = 0; i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS; i++)
        entry_reset_proof(&scheduler->entries[i]);
    free(scheduler);
}

bool vcs_package_possession_scheduler_reconcile(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, const uint8_t (*roots)[32],
    size_t root_count, uint64_t now_mono)
{
    if (!scheduler || !store || (root_count && !roots) ||
        root_count > VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS)
        return false;
    bool keep[VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS] = {false};
    for (size_t root_index = 0; root_index < root_count; root_index++) {
        struct scheduler_entry *entry = entry_find(scheduler,
                                                   roots[root_index]);
        size_t slot = VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS;
        if (entry)
            slot = (size_t)(entry - scheduler->entries);
        else {
            for (size_t i = 0;
                 i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS; i++)
                if (!scheduler->entries[i].used) {
                    slot = i;
                    break;
                }
            if (slot == VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS)
                return false;
            entry = &scheduler->entries[slot];
            memset(entry, 0, sizeof(*entry));
            entry->used = true;
            entry->observed_generation = UINT64_MAX;
            memcpy(entry->root, roots[root_index], 32);
            entry->next_due_mono = now_mono;
        }
        keep[slot] = true;
    }
    for (size_t i = 0; i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS; i++)
        if (scheduler->entries[i].used && !keep[i]) {
            entry_reset_proof(&scheduler->entries[i]);
            memset(&scheduler->entries[i], 0,
                   sizeof(scheduler->entries[i]));
        }
    return true;
}

bool vcs_package_possession_scheduler_require(
    struct vcs_package_possession_scheduler *scheduler,
    const uint8_t root[32], uint64_t now_mono)
{
    if (!scheduler || !root)
        return false;
    struct scheduler_entry *entry = entry_find(scheduler, root);
    if (!entry)
        return false;
    entry->last_success_generation = 0;
    if (entry->proof || entry->next_due_mono <= now_mono ||
        entry->failure != VCS_PACKAGE_POSSESSION_NONE)
        return true;
    entry_reset_proof(entry);
    entry->next_due_mono = now_mono;
    return true;
}

static void entry_fail(struct vcs_package_possession_scheduler *scheduler,
                       struct scheduler_entry *entry, uint64_t now_mono,
                       enum vcs_package_possession_failure failure)
{
    entry->failure = failure;
    entry->failures++;
    scheduler->failed_proofs++;
    entry->last_success_generation = 0;
    entry->next_due_mono = now_mono + scheduler->config.failure_retry_s;
    entry_reset_proof(entry);
}

void vcs_package_possession_scheduler_run(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, uint64_t now_mono)
{
    if (!scheduler || !store)
        return;
    scheduler->cycles++;
    scheduler->last_cycle_bytes = 0;
    scheduler->last_cycle_packages = 0;
    uint32_t scanned = 0;
    while (scanned < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS &&
           scheduler->last_cycle_packages <
               scheduler->config.packages_per_cycle &&
           scheduler->last_cycle_bytes < scheduler->config.bytes_per_cycle) {
        uint32_t index = scheduler->cursor++ %
                         VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS;
        scanned++;
        struct scheduler_entry *entry = &scheduler->entries[index];
        if (!entry->used || entry->next_due_mono > now_mono)
            continue;
        scheduler->last_cycle_packages++;
        entry_observe(entry, store, now_mono);
        if (!entry->observed_complete || !entry->observed_pinned) {
            entry_fail(scheduler, entry, now_mono, entry->failure);
            continue;
        }
        if (!entry->proof) {
            entry->proof = vcs_package_store_possession_begin(
                store, entry->root, true, &entry->receipt);
            if (!entry->proof) {
                entry_fail(scheduler, entry, now_mono,
                           entry->receipt.failure);
                continue;
            }
        }
        uint64_t remaining = scheduler->config.bytes_per_cycle -
                             scheduler->last_cycle_bytes;
        uint64_t used = 0;
        enum vcs_package_possession_step step =
            vcs_package_store_possession_step(
                entry->proof, remaining,
                scheduler->config.chunks_per_package_cycle,
                &entry->receipt, &used);
        scheduler->last_cycle_bytes += used;
        scheduler->bytes_verified_total += used;
        entry->bytes_verified += used;
        if (step == VCS_PACKAGE_POSSESSION_SUCCESS) {
            entry->last_success_generation =
                entry->receipt.mutation_generation;
            entry->last_success_mono = now_mono;
            entry->next_due_mono = now_mono +
                                   scheduler->config.scrub_interval_s;
            entry->failure = VCS_PACKAGE_POSSESSION_NONE;
            scheduler->successful_proofs++;
            entry_reset_proof(entry);
        } else if (step == VCS_PACKAGE_POSSESSION_FAILED) {
            entry_fail(scheduler, entry, now_mono, entry->receipt.failure);
        }
    }
}

bool vcs_package_possession_scheduler_current(
    struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, const uint8_t root[32],
    struct vcs_package_possession_receipt *receipt)
{
    if (!scheduler || !store || !root)
        return false;
    struct scheduler_entry *entry = entry_find(scheduler, root);
    if (!entry)
        return false;
    struct vcs_package_possession_receipt snapshot;
    bool current = vcs_package_store_possession_snapshot(
                       store, root, &snapshot) &&
                   snapshot.complete && snapshot.pinned &&
                   entry->last_success_generation != 0 &&
                   snapshot.mutation_generation ==
                       entry->last_success_generation;
    if (receipt)
        *receipt = entry->receipt;
    return current;
}

void vcs_package_possession_scheduler_status(
    const struct vcs_package_possession_scheduler *scheduler,
    uint64_t now_mono,
    struct vcs_package_possession_scheduler_status *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!scheduler)
        return;
    out->bytes_verified_total = scheduler->bytes_verified_total;
    out->successful_proofs = scheduler->successful_proofs;
    out->failed_proofs = scheduler->failed_proofs;
    out->cycles = scheduler->cycles;
    out->last_cycle_bytes = scheduler->last_cycle_bytes;
    out->last_cycle_packages = scheduler->last_cycle_packages;
    out->next_due_mono = UINT64_MAX;
    for (size_t i = 0; i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS; i++) {
        const struct scheduler_entry *entry = &scheduler->entries[i];
        if (!entry->used)
            continue;
        out->tracked_roots++;
        if (entry->next_due_mono <= now_mono || entry->proof)
            out->queued_roots++;
        if (entry->next_due_mono < out->next_due_mono)
            out->next_due_mono = entry->next_due_mono;
    }
    if (!out->tracked_roots)
        out->next_due_mono = 0;
}

size_t vcs_package_possession_scheduler_rows(
    const struct vcs_package_possession_scheduler *scheduler,
    struct vcs_package_store *store, uint64_t now_mono,
    struct vcs_package_possession_scheduler_row *out, size_t max)
{
    if (!scheduler || !store || !out || !max)
        return 0;
    size_t count = 0;
    for (size_t i = 0;
         i < VCS_PACKAGE_POSSESSION_SCHEDULER_MAX_ROOTS && count < max; i++) {
        const struct scheduler_entry *entry = &scheduler->entries[i];
        if (!entry->used)
            continue;
        struct vcs_package_possession_scheduler_row *row = &out[count++];
        memset(row, 0, sizeof(*row));
        memcpy(row->root, entry->root, 32);
        row->mutation_generation = entry->observed_generation;
        row->last_success_mono = entry->last_success_mono;
        row->next_due_mono = entry->next_due_mono;
        row->bytes_verified = entry->bytes_verified;
        row->proof_age_s = entry->last_success_mono &&
                                   now_mono >= entry->last_success_mono
                               ? now_mono - entry->last_success_mono
                               : 0;
        row->failures = entry->failures;
        row->failure = entry->failure;
        row->queued = entry->next_due_mono <= now_mono || entry->proof;
        row->current = vcs_package_possession_scheduler_current(
            (struct vcs_package_possession_scheduler *)scheduler,
            store, entry->root, NULL);
    }
    return count;
}
