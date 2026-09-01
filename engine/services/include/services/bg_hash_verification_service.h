/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background Block Hash Verification Service
 * -------------------------------------------
 * Walks every block in the active chain and verifies that the stored
 * block hash (from LevelDB or block_index.bin) matches the SHA256d
 * recomputed from the actual block header on disk. This catches:
 *   - Corrupted LevelDB block index entries
 *   - Tampered block files
 *   - Hash collisions from software bugs
 *
 * Runs in a dedicated background thread at low priority. Saves progress
 * to SQLite every 1000 blocks for crash-resume. Non-blocking — the node
 * operates normally while verification runs.
 */

#ifndef ZCL_BG_HASH_VERIFICATION_SERVICE_H
#define ZCL_BG_HASH_VERIFICATION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#include "util/result.h"

#include "ports/bg_hash_verify_store_port.h"

struct main_state;
struct node_db;
struct chain_params;

enum bg_hash_verify_state {
    BG_HASH_VERIFY_IDLE = 0,
    BG_HASH_VERIFY_RUNNING,
    BG_HASH_VERIFY_COMPLETE,
    BG_HASH_VERIFY_FAILED,
};

struct bg_hash_verify_progress {
    _Atomic int verified_height;
    _Atomic int chain_height;
    _Atomic int mismatches;
    _Atomic int state;
};

struct bg_hash_verification_service {
    /* References (not owned). `datadir` points only into the owned storage
     * below: boot resolves the network directory in a stack buffer before
     * this long-lived worker starts, and the worker outlives that frame. */
    struct main_state *ms;
    struct node_db *ndb;
    const char *datadir;
    char datadir_storage[4096];
    const struct chain_params *params;

    /* Crash-resume cursor storage behind a port; bound from `ndb` in
     * bg_hash_verify_init. The service never names sqlite — all cursor
     * persistence flows through this seam. */
    struct bg_hash_verify_store_port progress_store;

    pthread_t thread;
    bool thread_started;
    _Atomic bool stop_requested;

    struct bg_hash_verify_progress progress;
};

void bg_hash_verify_init(struct bg_hash_verification_service *svc,
                         struct main_state *ms,
                         struct node_db *ndb,
                         const char *datadir,
                         const struct chain_params *params);

struct zcl_result bg_hash_verify_start(struct bg_hash_verification_service *svc);
void bg_hash_verify_stop(struct bg_hash_verification_service *svc);

struct bg_hash_verify_progress bg_hash_verify_get_progress(
    const struct bg_hash_verification_service *svc);

const char *bg_hash_verify_state_name(enum bg_hash_verify_state state);

extern struct bg_hash_verification_service *g_bg_hash_verify;

#endif
