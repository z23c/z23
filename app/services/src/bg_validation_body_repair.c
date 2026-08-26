/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stop-responsive canonical-body repair for background full validation.
 * Disk damage is handed to the existing condition engine, while this reader
 * stays on the same height until an independently hash-checked body arrives. */

#include "bg_validation_internal.h"

#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "services/bg_validation_service.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>

#ifdef ZCL_TESTING
static bg_validation_test_body_read_fn g_body_read_fn =
    read_block_from_disk_index_pread;
static bg_validation_test_sleep_fn g_sleep_fn = platform_sleep_ms;
static bg_validation_test_validate_fn g_validate_fn =
    bg_validation_validate_block_proofs;
#endif

bool bg_validation_index_is_active(
    struct main_state *ms, int height, const struct block_index *expected)
{
    if (!ms || !expected || !expected->phashBlock)
        return false;
    struct uint256 expected_hash = *expected->phashBlock;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *current = active_chain_at(&ms->chain_active, height);
    bool active = current == expected && current->phashBlock &&
        uint256_eq(current->phashBlock, &expected_hash);
    zcl_mutex_unlock(&ms->cs_main);
    return active;
}

enum bg_validation_block_outcome bg_validation_validate_canonical_block(
    struct main_state *ms, int height, const struct block *block,
    struct block_index *index, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, int64_t *sigs_out, int64_t *proofs_out,
    int64_t *skips_out)
{
#ifdef ZCL_TESTING
    bool valid = g_validate_fn(
#else
    bool valid = bg_validation_validate_block_proofs(
#endif
        block, index, datadir, params, num_workers, max_script_batch,
        sigs_out, proofs_out, skips_out);
    if (!bg_validation_index_is_active(ms, height, index))
        return BG_VALIDATION_BLOCK_ORPHAN;
    return valid ? BG_VALIDATION_BLOCK_VALID : BG_VALIDATION_BLOCK_INVALID;
}

bool bg_validation_read_body_resilient(
    struct bg_validation_service *svc, int height, const char *datadir,
    enum bg_validation_state ready_state, struct block *block,
    struct block_index **index_out)
{
    if (!svc || !svc->ms || !datadir || !block || !index_out || height < 0)
        LOG_RETURN(false, "bg_validation",
                   "resilient body read received invalid arguments");
    *index_out = NULL;
    unsigned failures = 0;

    while (!atomic_load(&svc->stop_requested)) {
        struct block_index *index = NULL;
        struct uint256 expected_hash;
        zcl_mutex_lock(&svc->ms->cs_main);
        index = active_chain_at(&svc->ms->chain_active, height);
        if (index && index->phashBlock)
            expected_hash = *index->phashBlock;
        else
            index = NULL;
        zcl_mutex_unlock(&svc->ms->cs_main);
        if (!index) {
            LOG_WARN("bg_validation",
                     "[bg-valid] coverage gap: no active block h=%d", height);
            return false;
        }
        struct reducer_frontier_body_read_note note_before_read;
        bool had_note = reducer_frontier_body_read_note_snapshot(
            &note_before_read);
#ifdef ZCL_TESTING
        bool read_ok = g_body_read_fn(block, index, datadir);
#else
        bool read_ok = read_block_from_disk_index_pread(block, index, datadir);
#endif
        if (read_ok) {
            zcl_mutex_lock(&svc->ms->cs_main);
            struct block_index *current =
                active_chain_at(&svc->ms->chain_active, height);
            bool still_active = current == index && current->phashBlock &&
                uint256_eq(current->phashBlock, &expected_hash);
            zcl_mutex_unlock(&svc->ms->cs_main);
            if (!still_active) {
                block_free(block);
                block_init(block);
                continue;
            }
            if (had_note && note_before_read.height == height)
                (void)reducer_frontier_body_read_note_clear_if(
                    &note_before_read);
            atomic_store(&svc->progress.state, ready_state);
            *index_out = index;
            return true;
        }

        reducer_frontier_body_read_note_record(
            height, block_index_file_load(index),
            (int64_t)block_index_data_pos_load(index),
            REDUCER_FRONTIER_BODY_READ_DISK, &expected_hash);
        failures++;
        block_free(block);
        block_init(block);
        atomic_store(&svc->progress.state, BG_VALIDATION_PAUSED);
        if (failures == 1 || failures % 12 == 0)
            LOG_WARN("bg_validation",
                     "[bg-valid] unreadable body h=%d failures=%u; repair "
                     "queued, retrying",
                     height, failures);
        for (int i = 0; i < 5 && !atomic_load(&svc->stop_requested); i++) {
            bg_validation_supervisor_heartbeat(svc);
#ifdef ZCL_TESTING
            g_sleep_fn(1000);
#else
            platform_sleep_ms(1000);
#endif
        }
    }
    return false;
}

#ifdef ZCL_TESTING
void bg_validation_test_set_validate_stub(
    bg_validation_test_validate_fn validate_fn)
{
    g_validate_fn = validate_fn
        ? validate_fn : bg_validation_validate_block_proofs;
}

void bg_validation_test_set_body_repair_stubs(
    bg_validation_test_body_read_fn read_fn,
    bg_validation_test_sleep_fn sleep_fn)
{
    g_body_read_fn = read_fn ? read_fn : read_block_from_disk_index_pread;
    g_sleep_fn = sleep_fn ? sleep_fn : platform_sleep_ms;
}
#endif
