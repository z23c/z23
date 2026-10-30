/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stop-responsive canonical-body repair for background full validation.
 * Disk damage is handed to the existing condition engine, while this reader
 * stays on the same height until an independently hash-checked body arrives. */

// repair-rung-ok:test_bg_validation_reverify — physical media can corrupt an
// already-written block body, so there is no producing writer to fix. The
// cited test corrupts the indexed position and proves that progress resumes
// only after a real replacement body deserializes and matches the active hash.
//
// one-result-type-ok:validation-state-and-durable-repair-note — this file adds
// no independent service result. A read either yields the exact active block,
// or publishes BG_VALIDATION_PAUSED plus a generation/hash-bound durable note;
// invalid arguments and unprovable active identity are logged fail-closed.

#include "bg_validation_internal.h"

#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "services/bg_validation_service.h"
#include "storage/disk_block_io.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>

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

/* Outcome of one body read attempt measured against the index snapshot that
 * was taken before the read: the disk read failed, the active chain moved
 * past the snapshot (retry the height immediately), or the body matched the
 * snapshot hash and was published. */
enum bg_validation_body_read_outcome {
    BG_VALIDATION_BODY_READ_FAILED,
    BG_VALIDATION_BODY_READ_STALE,
    BG_VALIDATION_BODY_READ_ACCEPTED,
};

/* Snapshot the active index at height; NULL means there is no provably active
 * block there, which the caller logs as a coverage gap. */
static struct block_index *bg_validation_snapshot_active_index(
    struct main_state *ms, int height, struct uint256 *expected_hash)
{
    struct block_index *index = NULL;
    zcl_mutex_lock(&ms->cs_main);
    index = active_chain_at(&ms->chain_active, height);
    if (index && index->phashBlock)
        *expected_hash = *index->phashBlock;
    else
        index = NULL;
    zcl_mutex_unlock(&ms->cs_main);
    return index;
}

/* One body read attempt measured against the snapshot taken before the read.
 * The block is left holding whatever the read produced on every outcome: the
 * caller frees and reinitialises it before the next attempt and publishes the
 * accepted index only after BG_VALIDATION_BODY_READ_ACCEPTED. */
static enum bg_validation_body_read_outcome bg_validation_attempt_body_read(
    struct bg_validation_service *svc, int height, const char *datadir,
    enum bg_validation_state ready_state, struct block *block,
    struct block_index *index, const struct uint256 *expected_hash,
    bool had_note, struct reducer_frontier_body_read_note *note)
{
#ifdef ZCL_TESTING
    bool read_ok = g_body_read_fn(block, index, datadir);
#else
    bool read_ok = read_block_from_disk_index_pread(block, index, datadir);
#endif
    if (!read_ok)
        return BG_VALIDATION_BODY_READ_FAILED;
    zcl_mutex_lock(&svc->ms->cs_main);
    struct block_index *current =
        active_chain_at(&svc->ms->chain_active, height);
    bool still_active = current == index && current->phashBlock &&
        uint256_eq(current->phashBlock, expected_hash);
    zcl_mutex_unlock(&svc->ms->cs_main);
    if (!still_active)
        return BG_VALIDATION_BODY_READ_STALE;
    if (had_note && note->height == height)
        (void)reducer_frontier_body_read_note_clear_if(note);
    atomic_store(&svc->progress.state, ready_state);
    return BG_VALIDATION_BODY_READ_ACCEPTED;
}

#define BG_VALIDATION_BODY_BLOCKER_ID "bg_validation.body_unreadable"
#define BG_VALIDATION_BODY_REPORT_AFTER 12u
#define BG_VALIDATION_BODY_RETRY_SECS 5u
#define BG_VALIDATION_BODY_REPORT_FIRST_SECS 10u
#define BG_VALIDATION_BODY_REPORT_MAX_SECS 600u

#ifdef ZCL_TESTING
static _Atomic unsigned g_body_report_count;
#endif

/* Pacing of the warning and blocker refresh for one stuck height. The body
 * read itself stays on the fixed retry cadence: a local pread is cheap and a
 * peer-fetched body must be noticed within one tick. */
struct bg_validation_body_report_pacing {
    unsigned since_report_secs;
    unsigned interval_secs;
};

/* Report on the first failure, then once the failures reach the report
 * threshold and the interval since the previous report has elapsed; each
 * report doubles the interval up to the cap. */
static bool bg_validation_body_report_due(
    struct bg_validation_body_report_pacing *pace, unsigned failures)
{
    pace->since_report_secs += BG_VALIDATION_BODY_RETRY_SECS;
    if (pace->interval_secs == 0)
        pace->interval_secs = BG_VALIDATION_BODY_REPORT_FIRST_SECS;
    bool due = failures == 1 ||
        (failures >= BG_VALIDATION_BODY_REPORT_AFTER &&
         pace->since_report_secs >= pace->interval_secs);
    if (!due)
        return false;
    pace->since_report_secs = 0;
    if (failures >= BG_VALIDATION_BODY_REPORT_AFTER) {
        pace->interval_secs *= 2;
        if (pace->interval_secs > BG_VALIDATION_BODY_REPORT_MAX_SECS)
            pace->interval_secs = BG_VALIDATION_BODY_REPORT_MAX_SECS;
    }
    return true;
}

static void bg_validation_name_body_blocker(
    int height, const struct block_index *index, unsigned failures)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "unreadable canonical body h=%d nFile=%d nDataPos=%u "
             "failures=%u; background validation is held at this height "
             "and re-reads it every %us until a peer-fetched body reads back",
             height, block_index_file_load(index),
             block_index_data_pos_load(index), failures,
             BG_VALIDATION_BODY_RETRY_SECS);
    struct blocker_record rec;
    if (blocker_init(&rec, BG_VALIDATION_BODY_BLOCKER_ID, "bg_validation",
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);
}

static void bg_validation_pause_before_body_retry(
    struct bg_validation_service *svc)
{
    for (unsigned i = 0; i < BG_VALIDATION_BODY_RETRY_SECS &&
                         !atomic_load(&svc->stop_requested); i++) {
        bg_validation_supervisor_heartbeat(svc);
#ifdef ZCL_TESTING
        g_sleep_fn(1000);
#else
        platform_sleep_ms(1000);
#endif
    }
}

/* Record the disk-failure note and publish the paused state; log and refresh
 * the typed blocker on the report cadence; then wait one retry tick. */
static void bg_validation_note_body_read_failure(
    struct bg_validation_service *svc, int height,
    const struct block_index *index, const struct uint256 *expected_hash,
    unsigned failures, struct bg_validation_body_report_pacing *pace)
{
    reducer_frontier_body_read_note_record(
        height, block_index_file_load(index),
        (int64_t)block_index_data_pos_load(index),
        REDUCER_FRONTIER_BODY_READ_DISK, expected_hash);
    atomic_store(&svc->progress.state, BG_VALIDATION_PAUSED);
    if (bg_validation_body_report_due(pace, failures)) {
#ifdef ZCL_TESTING
        atomic_fetch_add(&g_body_report_count, 1);
#endif
        if (failures >= BG_VALIDATION_BODY_REPORT_AFTER)
            bg_validation_name_body_blocker(height, index, failures);
        LOG_WARN("bg_validation",
                 "[bg-valid] unreadable body h=%d failures=%u; repair "
                 "queued, re-reading every %us (next report in %us)",
                 height, failures, BG_VALIDATION_BODY_RETRY_SECS,
                 pace->interval_secs);
    }
    bg_validation_pause_before_body_retry(svc);
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
    struct bg_validation_body_report_pacing pace = {0};

    while (!atomic_load(&svc->stop_requested)) {
        struct uint256 expected_hash;
        struct block_index *index = bg_validation_snapshot_active_index(
            svc->ms, height, &expected_hash);
        if (!index) {
            blocker_clear(BG_VALIDATION_BODY_BLOCKER_ID);
            LOG_WARN("bg_validation",
                     "[bg-valid] coverage gap: no active block h=%d", height);
            return false;
        }
        struct reducer_frontier_body_read_note note_before_read;
        bool had_note = reducer_frontier_body_read_note_snapshot(
            &note_before_read);
        enum bg_validation_body_read_outcome outcome =
            bg_validation_attempt_body_read(
                svc, height, datadir, ready_state, block, index,
                &expected_hash, had_note, &note_before_read);
        if (outcome == BG_VALIDATION_BODY_READ_ACCEPTED) {
            blocker_clear(BG_VALIDATION_BODY_BLOCKER_ID);
            *index_out = index;
            return true;
        }
        if (outcome == BG_VALIDATION_BODY_READ_STALE) {
            block_free(block);
            block_init(block);
            continue;
        }
        failures++;
        block_free(block);
        block_init(block);
        bg_validation_note_body_read_failure(svc, height, index,
                                             &expected_hash, failures, &pace);
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

unsigned bg_validation_test_body_report_count(void)
{
    return atomic_load(&g_body_report_count);
}

void bg_validation_test_set_body_repair_stubs(
    bg_validation_test_body_read_fn read_fn,
    bg_validation_test_sleep_fn sleep_fn)
{
    g_body_read_fn = read_fn ? read_fn : read_block_from_disk_index_pread;
    g_sleep_fn = sleep_fn ? sleep_fn : platform_sleep_ms;
}
#endif
