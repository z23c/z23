/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refuse snapshot activation without qualified Windows cutover. */
#if defined(_WIN32)

#include "config/consensus_state_snapshot_install.h"

#include <stdio.h>
#include <string.h>

#ifdef ZCL_TESTING
void consensus_state_snapshot_install_activate_test_set_after_stream_hook(
    void (*hook)(void *), void *ctx)
{
    (void)hook;
    (void)ctx;
}
void consensus_state_snapshot_install_activate_test_set_after_backup_hook(
    void (*hook)(void *), void *ctx)
{
    (void)hook;
    (void)ctx;
}
void consensus_state_snapshot_install_activate_test_fail_seed_once(void) { }
void consensus_state_snapshot_install_activate_test_fail_after_seed_once(void)
{
}
#endif

bool consensus_state_snapshot_install_activate(
    struct sqlite3 *progress_db,
    const struct consensus_state_activate_request *request,
    struct consensus_state_activate_result *result)
{
    (void)progress_db;
    (void)request;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->status = CONSENSUS_INSTALL_REFUSED;
        result->activated = false;
        snprintf(result->reason, sizeof(result->reason),
                 "snapshot activation is unavailable on Windows until the "
                 "backup and cutover transaction uses a retained native "
                 "directory capability");
    }
    fprintf(stderr,
            "REFUSED: consensus-state snapshot activation is unavailable on "
            "Windows until the native backup/cutover capability is qualified\n");
    return false;
}

#else
typedef int consensus_state_snapshot_install_activate_windows_not_built;
#endif
