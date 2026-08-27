/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Owns background validation's long-lived inputs and measured worker limits.
 * The boot adapter may resolve the network datadir in caller-local storage;
 * this service must retain bytes, never that caller's pointer. */

#include "services/bg_validation_service.h"

#include "adapters/outbound/persistence/bg_validation_store_sqlite.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

void bg_validation_init(struct bg_validation_service *svc,
                        struct main_state *ms,
                        struct node_db *ndb,
                        const char *datadir,
                        const struct chain_params *params)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->ndb = ndb;
    int datadir_len = datadir
        ? snprintf(svc->datadir_storage, sizeof(svc->datadir_storage),
                   "%s", datadir)
        : -1;
    if (datadir_len > 0 &&
        (size_t)datadir_len < sizeof(svc->datadir_storage)) {
        svc->datadir = svc->datadir_storage;
    } else {
        svc->datadir_storage[0] = '\0';
        svc->datadir = NULL;
        LOG_ERROR("bg_validation",
                  "bg_validation_init: datadir is empty or exceeds %zu bytes",
                  sizeof(svc->datadir_storage) - 1u);
    }
    svc->params = params;
    atomic_store(&svc->stop_requested, false);

    /* The SQLite adapter remains the only owner of cursor persistence. */
    bg_validation_store_sqlite_bind(ndb, &svc->progress_store);

    hw_profile_init(svc->datadir);
    hw_bench_init(svc->datadir);
    svc->num_workers = hw_bench_verify_workers(
        hw_profile_verify_workers(hw_profile_physical_cores()));
    svc->max_script_batch = hw_profile_script_batch_cap(hw_profile_ram_bytes());

    atomic_store(&svc->progress.state, BG_VALIDATION_IDLE);
    atomic_store(&svc->progress.verified_height, -1);
    atomic_store(&svc->progress.chain_height, 0);
    atomic_store(&svc->progress.sigs_verified, 0);
    atomic_store(&svc->progress.proofs_verified, 0);
    atomic_store(&svc->progress.blocks_per_sec, 0);
    atomic_store(&svc->progress.reverify_active, false);
    atomic_store(&svc->progress.reverify_passes, 0);
    atomic_store(&svc->progress.reverify_fails, 0);
    atomic_store(&svc->progress.reverify_height, 0);
}
